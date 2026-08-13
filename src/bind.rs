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
    fn acquire() -> Option<Lock> {
        let f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(LOCK_FILE)
            .ok()?;
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) } == 0 {
            Some(Lock(f))
        } else {
            None
        }
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
    source.to_str().context("non-utf8 bind source")?;
    let t = target.to_str().context("non-utf8 bind target")?.to_string();
    // New-file binds would need a tmpfs/overlay; my_* content is overrides of
    // existing OnePlus files, so require the target to exist.
    if !target.exists() {
        bail!("bind target missing (new-file unsupported): {t}");
    }

    let _lock = Lock::acquire();
    // Serialized: check-then-bind can't race another process into a double mount.
    if is_mounted(target) {
        // Another module already bound this target; leave it to them.
        return Ok(());
    }
    // Relabel first; abort the whole bind on failure (never expose a mislabeled file).
    mirror_selinux(source, target)
        .with_context(|| format!("relabel for bind of {t}"))?;

    let (sc, tc) = (cstr(source)?, cstr(target)?);
    let r = unsafe {
        libc::mount(sc.as_ptr(), tc.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null())
    };
    if r != 0 {
        bail!("bind {} -> {t}: {}", source.display(), std::io::Error::last_os_error());
    }
    // Track it; if we can't, unbind rather than leak an untracked mount.
    if let Err(e) = append_locked(&t) {
        unsafe { libc::umount2(tc.as_ptr(), libc::MNT_DETACH) };
        bail!("bind of {t} recorded failed ({e}); unbound");
    }
    Ok(())
}

/// Append a target to binds.list. Caller must hold the Lock.
fn append_locked(target: &str) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(BINDS_LIST)?;
    writeln!(f, "{target}")
}

/// Targets we currently have bound (from binds.list). Read-only.
pub fn tracked() -> Vec<PathBuf> {
    fs::read_to_string(BINDS_LIST)
        .map(|s| {
            s.lines()
                .map(|l| PathBuf::from(l.trim()))
                .filter(|p| !p.as_os_str().is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Umount a single tracked bind and drop it from the list (gap-free reload).
pub fn umount_one(target: &Path) {
    let _lock = Lock::acquire();
    if let Ok(c) = CString::new(target.to_string_lossy().as_bytes()) {
        unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
    }
    let remaining: String = tracked()
        .into_iter()
        .filter(|p| p != target)
        .map(|p| format!("{}\n", p.display()))
        .collect();
    let _ = fs::write(BINDS_LIST, remaining);
}

/// Umount every bind we recorded, then clear the list. Run at the start of each
/// mount pass so stale binds (removed/updated modules) never accumulate.
pub fn teardown_all() {
    let _lock = Lock::acquire();
    let Ok(list) = fs::read_to_string(BINDS_LIST) else {
        return;
    };
    for line in list.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Ok(c) = CString::new(t) {
            unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) };
        }
    }
    let _ = fs::remove_file(BINDS_LIST);
}
