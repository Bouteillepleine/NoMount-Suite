//! Real bind mounts for targets hookless injection cannot serve.
//!
//! OnePlus/Oppo `my_*` partitions are in zygote's FD allowlist: it preloads FDs
//! from there and validates their inode identity in `FileDescriptorInfo::
//! CreateFromFd`. Hookless spoofs `dev/ino` on injected inodes, so that check
//! fails and the first `forkSystemServer` aborts (bootloop). A real bind keeps
//! the file's true `dev/ino`, so it passes. Every other OnePlus module that
//! touches `my_*` does the same; the device already carries ~100 such binds, so
//! this adds no detection surface. Everything hookless can reach stays mountless.

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

const BINDS_LIST: &str = "/data/adb/nomount/binds.list";
const LOCK_FILE: &str = "/data/adb/nomount/binds.lock";
const SELINUX_XATTR: &[u8] = b"security.selinux\0";

/// flock(LOCK_EX) guard so binds.list read-modify-write is atomic across a
/// concurrent `nomount mount` (boot) and `nomount reload` (manager). Held only
/// for the duration of a single mutation; internal helpers never re-lock (flock
/// on a fresh fd from the same process would deadlock).
struct Lock(fs::File);
impl Lock {
    /// Fails loudly. This used to return `Option` and every call site bound it to
    /// `_lock` and carried on, so a failed open or flock silently degraded to no
    /// locking at all -- the exact concurrent mount/reload corruption of
    /// binds.list the lock exists to prevent.
    fn acquire() -> Result<Lock> {
        // 0600: created under the boot umask this landed 0666. It is inside a 0700
        // directory so nothing could reach it, but a world-writable lock is not a
        // property to depend on the parent for.
        let f = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .create(true)
                // Nothing is ever written to it -- the file exists only to carry the
                // flock -- so truncation is explicitly not wanted.
                .truncate(false)
                .write(true)
                .mode(0o600)
                .open(LOCK_FILE)
                .with_context(|| format!("open {LOCK_FILE}"))?
        };
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } != 0 {
            bail!("flock {LOCK_FILE}: {}", std::io::Error::last_os_error());
        }
        Ok(Lock(f))
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn cstr(p: &Path) -> Result<CString> {
    CString::new(p.to_str().context("non-utf8 path")?.as_bytes()).context("nul byte in path")
}

/// True if `target` is already a mount point (some other module bound it).
fn is_mounted(target: &Path) -> bool {
    let Some(t) = target.to_str() else {
        return false;
    };
    fs::read_to_string("/proc/self/mountinfo")
        .map(|s| {
            s.lines()
                .any(|l| l.split(' ').nth(4).map(|m| m == t).unwrap_or(false))
        })
        .unwrap_or(false)
}

/// Copy `target`'s SELinux label onto `source`, so the bound file reports the
/// partition's context (e.g. `system_file`) instead of `adb_data_file` -- without
/// this an app reading the my_* file hits an avc denial. Fails hard: a mislabeled
/// override is worse than none (broken read + a detection tell).
/// Read a path's SELinux label, if it has one.
fn read_selinux(p: &Path) -> Option<Vec<u8>> {
    let c = cstr(p).ok()?;
    let mut buf = [0u8; 256];
    let n = unsafe {
        libc::getxattr(c.as_ptr(), SELINUX_XATTR.as_ptr() as *const libc::c_char,
                       buf.as_mut_ptr() as *mut libc::c_void, buf.len())
    };
    if n <= 0 { None } else { Some(buf[..n as usize].to_vec()) }
}

/// Put a previously captured label back on `p`.
fn restore_selinux(p: &Path, label: &[u8]) {
    if let Ok(c) = cstr(p) {
        unsafe {
            libc::setxattr(c.as_ptr(), SELINUX_XATTR.as_ptr() as *const libc::c_char,
                           label.as_ptr() as *const libc::c_void, label.len(), 0);
        }
    }
}

fn mirror_selinux(source: &Path, target: &Path) -> Result<()> {
    let (sc, tc) = (cstr(source)?, cstr(target)?);
    let name = SELINUX_XATTR.as_ptr() as *const libc::c_char;
    let mut buf = [0u8; 256];
    let n = unsafe {
        libc::getxattr(tc.as_ptr(), name, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
    };
    if n <= 0 {
        bail!("read selinux label of {}", target.display());
    }
    let r = unsafe {
        libc::setxattr(sc.as_ptr(), name, buf.as_ptr() as *const libc::c_void, n as usize, 0)
    };
    if r != 0 {
        bail!("set selinux label on {}: {}", source.display(), std::io::Error::last_os_error());
    }
    Ok(())
}

/// File-over-file bind of `source` onto an existing `target`.
pub fn apply(source: &Path, target: &Path) -> Result<()> {
    // Reject non-UTF8 up front so the recorded/umounted path round-trips exactly.
    let s = source.to_str().context("non-utf8 bind source")?.to_string();
    let t = target.to_str().context("non-utf8 bind target")?.to_string();
    // New-file binds would need a tmpfs/overlay; my_* content is overrides of
    // existing OnePlus files, so require the target to exist.
    if !target.exists() {
        bail!("bind target missing (new-file unsupported): {t}");
    }

    let _lock = Lock::acquire()?;
    // Serialized: check-then-bind can't race another process into a double mount.
    if is_mounted(target) {
        // Another module already bound this target; leave it to them.
        return Ok(());
    }
    // Capture the source's own label BEFORE overwriting it, so teardown (and the
    // failure path below) can put it back. Without this every attempted bind left
    // a module file permanently carrying a partition label, even when the mount
    // then failed and no bind existed at all.
    let orig_label = read_selinux(source);
    // Relabel first; abort the whole bind on failure (never expose a mislabeled file).
    mirror_selinux(source, target)
        .with_context(|| format!("relabel for bind of {t}"))?;

    let (sc, tc) = (cstr(source)?, cstr(target)?);
    let r = unsafe {
        libc::mount(sc.as_ptr(), tc.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null())
    };
    if r != 0 {
        if let Some(l) = &orig_label { restore_selinux(source, l); }
        bail!("bind {} -> {t}: {}", source.display(), std::io::Error::last_os_error());
    }
    // Track it; if we can't, unbind rather than leak an untracked mount.
    let lbl = orig_label.as_deref().map(|l| String::from_utf8_lossy(l).trim_end_matches('\0').to_string())
        .unwrap_or_default();
    if let Err(e) = append_locked(&t, &s, &lbl) {
        unsafe { libc::umount2(tc.as_ptr(), libc::MNT_DETACH) };
        if let Some(l) = &orig_label { restore_selinux(source, l); }
        bail!("bind of {t} recorded failed ({e}); unbound");
    }
    Ok(())
}

/// Append a "target\tsource" record to binds.list. Caller must hold the Lock.
/// Storing the source lets a reload detect a changed backing (re-bind), not just
/// an added/removed target.
fn append_locked(target: &str, source: &str, orig_label: &str) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(BINDS_LIST)?;
    writeln!(f, "{target}\t{source}\t{orig_label}")
}

/// Parse one binds.list line into (target, source). Tolerates the legacy
/// target-only format (source comes back empty), so an upgrade-in-place reload
/// simply re-binds every legacy row once to backfill its source.
/// `target \t source \t original-label`. Tolerates both legacy shapes
/// (target-only, and target+source without a label).
fn parse_line(l: &str) -> Option<(PathBuf, PathBuf, String)> {
    let l = l.trim();
    if l.is_empty() {
        return None;
    }
    let mut it = l.split('\t');
    let t = it.next()?;
    let s = it.next().unwrap_or("");
    let lbl = it.next().unwrap_or("");
    Some((PathBuf::from(t), PathBuf::from(s), lbl.to_string()))
}

/// (target, source) pairs we currently have bound (from binds.list). Read-only.
pub fn tracked() -> Vec<(PathBuf, PathBuf)> {
    tracked_full().into_iter().map(|(t, s, _)| (t, s)).collect()
}

/// As [`tracked`], plus each row's recorded original source label.
fn tracked_full() -> Vec<(PathBuf, PathBuf, String)> {
    fs::read_to_string(BINDS_LIST)
        .map(|s| s.lines().filter_map(parse_line).collect())
        .unwrap_or_default()
}

/// Umount a single tracked bind and drop it from the list (gap-free reload).
pub fn umount_one(target: &Path) {
    let Ok(_lock) = Lock::acquire() else { return };
    if let Ok(c) = CString::new(target.to_string_lossy().as_bytes()) {
        unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
    }
    let rows = tracked_full();
    // Put the source file's own label back now that nothing is bound over it.
    for (t, s, lbl) in rows.iter().filter(|(t, _, _)| t == target) {
        let _ = t;
        if !lbl.is_empty() {
            restore_selinux(s, format!("{lbl}\0").as_bytes());
        }
    }
    let remaining: String = rows
        .into_iter()
        .filter(|(t, _, _)| t != target)
        .map(|(t, s, l)| format!("{}\t{}\t{}\n", t.display(), s.display(), l))
        .collect();
    // This list is the ONLY record of binds we made; if it cannot be rewritten
    // the dropped entry is leaked -- a real mount nothing will umount later.
    if let Err(e) = fs::write(BINDS_LIST, &remaining) {
        eprintln!(
            "nomount: could not update {BINDS_LIST}: {e} — a bind may be left \
             recorded (or unrecorded) and will not be cleaned up on the next pass"
        );
    }
}

/// Umount every bind we recorded, then clear the list. Run at the start of each
/// mount pass so stale binds (removed/updated modules) never accumulate.
pub fn teardown_all() {
    let Ok(_lock) = Lock::acquire() else { return };
    let Ok(list) = fs::read_to_string(BINDS_LIST) else {
        return;
    };
    for line in list.lines() {
        let Some((t, s, lbl)) = parse_line(line) else {
            continue;
        };
        if let Ok(c) = CString::new(t.to_string_lossy().as_bytes()) {
            unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
        }
        if !lbl.is_empty() {
            restore_selinux(&s, format!("{lbl}\0").as_bytes());
        }
    }
    // A stale list makes the next pass try to umount paths already gone. Not
    // fatal, but it is the difference between a clean pass and confusing noise.
    if let Err(e) = fs::remove_file(BINDS_LIST) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!("nomount: could not clear {BINDS_LIST}: {e} — the next pass will \
                       retry umounts that are already done");
        }
    }
}
