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

pub(crate) const BINDS_LIST: &str = "/data/adb/nomount/binds.list";
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
        // BOUNDED, like `mount::pass_lock` and for the same reasons: this runs on
        // the boot path (`teardown_all` opens every mount pass), `service.sh` runs
        // that pass in the foreground and un-timed, and `uidwatch.sh` reaps a
        // handler lock it has seen for 60s -- a process merely WAITING on a
        // blocking LOCK_EX is indistinguishable from a dead one, so it gets reaped
        // and mutual exclusion is lost for the rest of the session. Same wait as
        // the pass lock so the two engine-wide locks behave alike.
        //
        // Unlike the pass lock we then FAIL rather than proceed unserialised:
        // every mutation here is a read-modify-write of binds.list, and an
        // unserialised one corrupts the only record of the binds we made.
        let wait = crate::mount::PASS_LOCK_WAIT;
        for _ in 0..(wait * 10) {
            if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Lock(f));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        bail!("another process still holds {LOCK_FILE} after {wait}s: {}",
              std::io::Error::last_os_error());
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// One conversion, lossless. There were four idioms in this crate for turning a
/// `Path` into a `CString` and two of them went through `to_string_lossy()`,
/// which substitutes U+FFFD and so hands the kernel a path nobody asked about.
/// This one used to be the third: it REFUSED a non-UTF-8 path outright, which is
/// at least loud, but a module is free to ship one and a bind of it should work.
/// `as_encoded_bytes()` is the byte sequence the filesystem actually holds.
fn cstr(p: &Path) -> Result<CString> {
    CString::new(p.as_os_str().as_encoded_bytes()).context("nul byte in path")
}

/// True if `target` is already a mount point (some other module bound it).
///
/// Parses through absorb's shared mountinfo parser so the mountpoint is octal-
/// UNESCAPED before comparison (`\040` etc.): the old raw field-4 compare never
/// matched a target with a space/tab in its path, so `apply` would try to bind
/// over a path it wrongly believed free.
fn is_mounted(target: &Path) -> bool {
    fs::read_to_string("/proc/self/mountinfo")
        .map(|s| crate::absorb::parse_mountinfo(&s).iter().any(|r| r.target == target))
        .unwrap_or(false)
}

/// Read a path's SELinux label, if it has one.
///
/// `lgetxattr`, never `getxattr`. Both `source` and `target` here are
/// module-supplied: `source` is `<module>/my_product/...` straight off the module
/// tree, and `target` is the path that tree implies. `getxattr` FOLLOWS symlinks,
/// so a module shipping a symlink would have this read -- and, worse, have
/// `restore_selinux` and `mirror_selinux` WRITE -- the label of whatever the link
/// points at. absorb.rs::label_apk_readable already refuses that for the same
/// reason. A symlink's own label is what the bind machinery is about; if the
/// answer is "there is no label on the link itself", that is the honest answer.
fn read_selinux(p: &Path) -> Option<Vec<u8>> {
    let c = cstr(p).ok()?;
    let mut buf = [0u8; 256];
    let n = unsafe {
        libc::lgetxattr(c.as_ptr(), SELINUX_XATTR.as_ptr() as *const libc::c_char,
                        buf.as_mut_ptr() as *mut libc::c_void, buf.len())
    };
    if n <= 0 { None } else { Some(buf[..n as usize].to_vec()) }
}

/// Put a previously captured label back on `p`. `lsetxattr`: see [`read_selinux`].
fn restore_selinux(p: &Path, label: &[u8]) {
    if let Ok(c) = cstr(p) {
        unsafe {
            libc::lsetxattr(c.as_ptr(), SELINUX_XATTR.as_ptr() as *const libc::c_char,
                            label.as_ptr() as *const libc::c_void, label.len(), 0);
        }
    }
}

/// Put the source file's own label back, now that nothing is bound over it.
///
/// The recorded label is EMPTY for a legacy two-field row (`parse_line` tolerates
/// one) and whenever `read_selinux` failed at bind time -- no label, or a label
/// longer than the 256-byte buffer. Both restore sites used to skip the restore
/// entirely in that case, leaving the ROM label (`system_file`) on a module file
/// under /data/adb. That mistake is SELF-PERPETUATING: the next `apply` reads the
/// leftover ROM label and records IT as the original, so from then on every
/// teardown faithfully "restores" a partition label onto a file in the module
/// tree, and it never heals.
///
/// Scope, honestly: /data/adb is 0700 root-only, so no app can reach the file and
/// no detector can see this. It is not a tell. It is a state file recording a
/// value that is known to be wrong, and `adb_data_file` is what every file under
/// /data/adb carries -- so that is the right thing to write when the row cannot
/// say.
fn restore_source_label(source: &Path, lbl: &str) {
    // A legacy TARGET-ONLY row has no source at all; there is nothing to relabel.
    if source.as_os_str().is_empty() {
        return;
    }
    restore_selinux(source, format!("{}\0", label_to_restore(lbl)).as_bytes());
}

/// What to write back when the row's label field is empty. Split out only so the
/// fallback can be pinned by a test without an xattr-capable filesystem.
fn label_to_restore(lbl: &str) -> &str {
    if lbl.is_empty() { "u:object_r:adb_data_file:s0" } else { lbl }
}

/// Copy `target`'s SELinux label onto `source`, so the bound file reports the
/// partition's context (e.g. `system_file`) instead of `adb_data_file` -- without
/// this an app reading the my_* file hits an avc denial. Fails hard: a mislabeled
/// override is worse than none (broken read + a detection tell).
///
/// Both ends use the `l`-prefixed calls -- the write side is the one that turns a
/// module symlink into an arbitrary-file relabel, and the read side would
/// otherwise report a label the bind will not actually serve. See
/// [`read_selinux`].
fn mirror_selinux(source: &Path, target: &Path) -> Result<()> {
    let (sc, tc) = (cstr(source)?, cstr(target)?);
    let name = SELINUX_XATTR.as_ptr() as *const libc::c_char;
    let mut buf = [0u8; 256];
    let n = unsafe {
        libc::lgetxattr(tc.as_ptr(), name, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
    };
    if n <= 0 {
        bail!("read selinux label of {}", target.display());
    }
    let r = unsafe {
        libc::lsetxattr(sc.as_ptr(), name, buf.as_ptr() as *const libc::c_void, n as usize, 0)
    };
    if r != 0 {
        bail!("set selinux label on {}: {}", source.display(), std::io::Error::last_os_error());
    }
    Ok(())
}

/// The result of an [`apply`] that succeeded.
pub enum BindOutcome {
    /// A new bind was made.
    Bound,
    /// The target was already a mount (another module bound it); nothing was
    /// added, so the caller must NOT count it as a new bind.
    AlreadyMounted,
}

/// File-over-file bind of `source` onto an existing `target`.
pub fn apply(source: &Path, target: &Path) -> Result<BindOutcome> {
    // Reject non-UTF8 up front so the recorded/umounted path round-trips exactly.
    let s = source.to_str().context("non-utf8 bind source")?.to_string();
    let t = target.to_str().context("non-utf8 bind target")?.to_string();
    // New-file binds would need a tmpfs/overlay; my_* content is overrides of
    // existing OnePlus files, so require the target to exist.
    if !target.exists() {
        bail!("bind target missing (new-file unsupported): {t}");
    }
    // A symlink source cannot be bound correctly, so refuse it rather than bind
    // something else. `mount(MS_BIND)` resolves the path, so it would serve the
    // link's TARGET -- while the label mirroring above lands on the link itself
    // (lsetxattr, deliberately). The file actually served would then carry
    // `adb_data_file` under a `my_*` path: an avc denial on every read and a
    // detection tell, with nothing in the log to say why. The same refusal keeps a
    // module from naming a source outside its own tree by way of a link.
    if fs::symlink_metadata(source).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        bail!(
            "bind source {s} is a symlink; a bind would serve its target instead, with the \
             wrong SELinux label. Ship the file itself"
        );
    }

    let _lock = Lock::acquire()?;
    // Serialized: check-then-bind can't race another process into a double mount.
    if is_mounted(target) {
        // Another module already bound this target; leave it to them. Distinct
        // outcome so the caller does not count a bind it never made.
        return Ok(BindOutcome::AlreadyMounted);
    }
    // Capture the source's own label BEFORE overwriting it, so teardown (and the
    // failure paths below) can put it back. Without this every attempted bind left
    // a module file permanently carrying a partition label, even when the mount
    // then failed and no bind existed at all.
    let orig_label = read_selinux(source);
    let lbl = orig_label.as_deref().map(|l| String::from_utf8_lossy(l).trim_end_matches('\0').to_string())
        .unwrap_or_default();
    // Record the restore row BEFORE relabelling (L5): a SIGKILL between the relabel
    // and the record would otherwise strand `source` carrying the ROM label under
    // /data/adb with no row to restore it from. A record with no live mount is
    // harmless (teardown umounts a non-mount as a no-op and restores the label),
    // and the two failure paths below remove it so a failed bind never lingers as
    // a phantom row reload would treat as already-bound.
    //
    // Keep the ANSWER, not just the success: `append_locked` is idempotent, so
    // `Ok(false)` means a row for this pair was ALREADY there — written by a pass
    // that was killed in the L5 window, and holding the only copy of the source's
    // true original label. Rolling that row back below would delete it, and the
    // `restore_selinux` on the same line would then re-assert the label this
    // process just read, which on such a retry is the ROM label the killed pass
    // already mirrored on. Net: no row, and a module file permanently carrying
    // `system_file` under /data/adb — the self-perpetuating state
    // `restore_source_label`'s doc exists to end, reached one door along. So roll
    // back only what THIS call wrote; a kept row heals at the next teardown.
    let newly_recorded = match append_locked(&t, &s, &lbl) {
        Ok(v) => v,
        Err(e) => {
            if let Some(l) = &orig_label { restore_selinux(source, l); }
            bail!("bind of {t} could not be recorded ({e}); not bound");
        }
    };
    // Relabel; abort the whole bind on failure (never expose a mislabeled file).
    if let Err(e) = mirror_selinux(source, target).with_context(|| format!("relabel for bind of {t}")) {
        if newly_recorded { remove_record_locked(&t, &s); }
        if let Some(l) = &orig_label { restore_selinux(source, l); }
        return Err(e);
    }

    let (sc, tc) = (cstr(source)?, cstr(target)?);
    let r = unsafe {
        libc::mount(sc.as_ptr(), tc.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null())
    };
    if r != 0 {
        if newly_recorded { remove_record_locked(&t, &s); }
        if let Some(l) = &orig_label { restore_selinux(source, l); }
        bail!("bind {} -> {t}: {}", source.display(), std::io::Error::last_os_error());
    }
    Ok(BindOutcome::Bound)
}

/// Replace binds.list, atomically. Caller must hold the Lock.
///
/// Temp-then-rename, not `fs::write`. This file is the ONLY record of the binds
/// we made -- `teardown_all` says so, and says what losing it costs: a live mount
/// over a `my_*` path whose backing file has already been relabelled back to
/// `adb_data_file`, which no later pass can see, let alone unmount. `fs::write`
/// truncates and then writes, so a short write (ENOSPC, a killed pass -- and
/// metamount.sh SIGKILLs this process at 60s) leaves exactly that. `rename` within
/// one directory is atomic, so a reader sees either the old list or the new one.
/// The same discipline `service.sh` uses for bindhosts' `mode_override.sh` and
/// `lib.sh` for the ksud de-link, both for smaller stakes.
///
/// The implementation moved to [`crate::statefile`] rather than being kept here:
/// every word above applies at least as strongly to `uidhide`, which is the hiding
/// POLICY and was still a plain `fs::write`. Keeping one copy per file is how the
/// `nm list` parsers drifted. The shared version also fsyncs the parent directory
/// after the rename, which this one did not -- `sync_all` on the temp makes the
/// CONTENT durable and says nothing about the directory entry naming it.
fn write_binds_list(body: &str) -> std::io::Result<()> {
    crate::statefile::write_atomic(BINDS_LIST, body)
}

/// Does this row name exactly this (target, source) pair?
///
/// ONE copy, because the idempotency guard in [`append_locked`] and the rollback
/// filter in [`remove_record_locked`] must agree by construction: "did I write a
/// row?" and "which rows does my rollback delete?" answering differently is how a
/// rollback came to throw away a row a killed pass had written — the only copy of
/// the source's true original label.
fn row_is(t: &Path, s: &Path, target: &str, source: &str) -> bool {
    t.to_string_lossy() == target && s.to_string_lossy() == source
}

/// Drop one (target, source) row from binds.list. Caller must hold the Lock. Used
/// to undo a record written before a relabel/mount that then failed (L5).
fn remove_record_locked(target: &str, source: &str) {
    let remaining: String = tracked_full()
        .into_iter()
        .filter(|(t, s, _)| !row_is(t, s, target, source))
        .map(|(t, s, l)| format!("{}\t{}\t{}\n", t.display(), s.display(), l))
        .collect();
    if let Err(e) = write_binds_list(&remaining) {
        eprintln!("nomount: could not roll back a failed bind record in {BINDS_LIST}: {e}");
    }
}

/// Append a "target\tsource" record to binds.list. Caller must hold the Lock.
/// Storing the source lets a reload detect a changed backing (re-bind), not just
/// an added/removed target.
///
/// `Ok(true)` means a row was written by THIS call; `Ok(false)` means one was
/// already there. The caller needs the difference: its rollback deletes every
/// row matching the pair, so rolling back a row it did not write throws away the
/// only copy of the source's true original label. See [`apply`].
fn append_locked(target: &str, source: &str, orig_label: &str) -> std::io::Result<bool> {
    use std::os::unix::fs::OpenOptionsExt;
    // IDEMPOTENT. `apply` records BEFORE it mounts (L5), so a pass SIGKILLed in
    // that window leaves a row with no mount -- and `reload` now re-applies such a
    // bind instead of trusting the file, which would otherwise append a second row
    // for the same pair. Two rows are not merely untidy: the label restore in
    // `umount_one`/`teardown_all` runs per matching ROW, and the second row's
    // label is the one read on the RE-apply, i.e. the ROM label already mirrored
    // onto the source by the killed pass. Keeping the first row keeps the only
    // copy of the source's true original label.
    if tracked_full().iter().any(|(t, s, _)| row_is(t, s, target, source)) {
        return Ok(false);
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        // 0600 as a property of the WRITE, not of whoever created the file first.
        // A WebUI-driven bind created this under ksud's umask; every later rewrite
        // goes through `write_atomic` and repairs it, which is exactly why nobody
        // noticed.
        .mode(0o600)
        .open(BINDS_LIST)?;
    // TRUNCATE BACK on a short write. This is the one non-atomic writer of an
    // only-copy record, in a file whose own header argues at length that it must
    // never be left half-written -- and `writeln!` short-writes on ENOSPC.
    //
    // What the leftover costs: the partial line has no newline, so the NEXT
    // append concatenates onto it and `parse_line` reads a corrupted target. Then
    // `teardown_all` calls `umount_target` on a path that does not exist, which
    // returns Ok through its `!is_mounted` arm, drops the row as retired, and
    // NEVER RESTORES THE SOURCE'S LABEL. The real bind survives with no record --
    // "a live mount that no later pass can see, let alone unmount", which this
    // file says the design exists to prevent -- and the module's backing file
    // keeps a ROM partition label under /data/adb indefinitely.
    //
    // Three lines, inside the lock the caller already holds, no new machinery.
    let orig = f.metadata()?.len();
    if let Err(e) = writeln!(f, "{target}\t{source}\t{orig_label}") {
        let _ = f.set_len(orig);
        return Err(e);
    }
    Ok(true)
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
///
/// Infallible on purpose for the callers that only ever ask "how many", but an
/// unreadable record is NOT an empty one: reporting surfaces that render the
/// answer to a user must use [`tracked_result`] instead, or a read error becomes
/// "no binds" and, next to a mount count that came from the kernel, "⚠ N foreign
/// mount(s)" blaming a module that did nothing.
pub fn tracked() -> Vec<(PathBuf, PathBuf)> {
    tracked_full().into_iter().map(|(t, s, _)| (t, s)).collect()
}

/// As [`tracked`], but an unreadable `binds.list` is an error rather than an
/// empty list. Absent is still `Ok(vec![])` — no binds is a normal state.
pub fn tracked_result() -> std::io::Result<Vec<(PathBuf, PathBuf)>> {
    match fs::read_to_string(BINDS_LIST) {
        Ok(s) => Ok(s.lines().filter_map(parse_line).map(|(t, s, _)| (t, s)).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// As [`tracked`], plus each row's recorded original source label.
fn tracked_full() -> Vec<(PathBuf, PathBuf, String)> {
    fs::read_to_string(BINDS_LIST)
        .map(|s| s.lines().filter_map(parse_line).collect())
        .unwrap_or_default()
}

/// Take the bind down, or say why not.
///
/// `Ok` means the target is NOT a mount any more -- either umount2 succeeded, or
/// it was never mounted. The second case is a legitimate row: `apply` records
/// BEFORE it mounts (L5), so a bind that failed after being recorded leaves one,
/// and it must be retired (and its label restored) rather than kept forever.
/// Anything else -- EPERM under a restrictive context is the one that bites --
/// means the mount is still live, and the caller must keep both the row and the
/// ROM label: restoring `adb_data_file` under a live bind serving a `my_*` path
/// is an avc denial on every read and a detection tell.
fn umount_target(target: &Path) -> Result<(), String> {
    // as_encoded_bytes(), NOT to_string_lossy() -- see absorb::umount_detach for
    // what the lossy form costs on a non-UTF-8 path. Here it is worse: the
    // caller keeps or retires the binds.list row on this answer, so unmounting
    // the wrong name reads as "still mounted" forever.
    let c = CString::new(target.as_os_str().as_encoded_bytes())
        .map_err(|_| "nul byte in path".to_string())?;
    if unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) } == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    // Ask the mount table rather than trusting errno: EINVAL means "not a mount
    // point", which is success here, and mountinfo answers that question for
    // every errno at once.
    if !is_mounted(target) {
        return Ok(());
    }
    Err(e.to_string())
}

/// Umount a single tracked bind and drop it from the list (gap-free reload).
///
/// Returns whether the bind is down. False means it is still mounted and still
/// recorded, so the caller must not count it as removed.
pub fn umount_one(target: &Path) -> bool {
    let _lock = match Lock::acquire() {
        Ok(l) => l,
        Err(e) => {
            // Was `else { return }`: a failed lock silently did nothing, which is
            // the same silent degrade `Lock::acquire` documents itself as
            // refusing. The caller counted the bind as removed either way.
            eprintln!("nomount: not umounting the bind over {}: {e:#}", target.display());
            return false;
        }
    };
    if let Err(e) = umount_target(target) {
        eprintln!(
            "nomount: could not umount the bind over {} ({e}); keeping its {BINDS_LIST} row \
             and its ROM label so the next pass can retry it",
            target.display()
        );
        return false;
    }
    let rows = tracked_full();
    // Put the source file's own label back now that nothing is bound over it.
    for (t, s, lbl) in rows.iter().filter(|(t, _, _)| t == target) {
        let _ = t;
        restore_source_label(s, lbl);
    }
    let remaining: String = rows
        .into_iter()
        .filter(|(t, _, _)| t != target)
        .map(|(t, s, l)| format!("{}\t{}\t{}\n", t.display(), s.display(), l))
        .collect();
    // This list is the ONLY record of binds we made; if it cannot be rewritten
    // the dropped entry is leaked -- a real mount nothing will umount later.
    if let Err(e) = write_binds_list(&remaining) {
        eprintln!(
            "nomount: could not update {BINDS_LIST}: {e} — a bind may be left \
             recorded (or unrecorded) and will not be cleaned up on the next pass"
        );
    }
    true
}

/// Umount every bind we recorded, then clear the list. Run at the start of each
/// mount pass so stale binds (removed/updated modules) never accumulate.
///
/// Returns whether every recorded bind actually came down. A row whose umount
/// FAILED is kept: this list is the only record of the binds we made, so dropping
/// it (as deleting the file wholesale used to) leaves a live mount that no later
/// pass can see, let alone unmount, over a `my_*` path whose backing file we had
/// just relabelled back to `adb_data_file`.
pub fn teardown_all() -> bool {
    let _lock = match Lock::acquire() {
        Ok(l) => l,
        Err(e) => {
            // Was `else { return }`. Silently skipping the teardown left the
            // previous pass's binds live while the pass below rebuilt over them.
            eprintln!("nomount: not tearing down recorded binds: {e:#}");
            return false;
        }
    };
    let list = match fs::read_to_string(BINDS_LIST) {
        Ok(s) => s,
        // No list at all is the ordinary first-pass case, not a failure.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
        Err(e) => {
            eprintln!("nomount: could not read {BINDS_LIST}: {e} — binds from the previous \
                       pass cannot be torn down");
            return false;
        }
    };
    // Rows that are still mounted, kept verbatim so a later pass can retry them.
    let mut kept = String::new();
    for line in list.lines() {
        let Some((t, s, lbl)) = parse_line(line) else {
            continue;
        };
        if let Err(e) = umount_target(&t) {
            eprintln!(
                "nomount: could not umount the bind over {} ({e}); keeping its record and \
                 its ROM label — a live bind serving a file labelled adb_data_file is an \
                 avc denial and a tell",
                t.display()
            );
            kept.push_str(&format!("{}\t{}\t{}\n", t.display(), s.display(), lbl));
            continue;
        }
        // Only now is nothing bound over the source, so the label can go back.
        restore_source_label(&s, &lbl);
    }
    if !kept.is_empty() {
        if let Err(e) = write_binds_list(&kept) {
            eprintln!("nomount: could not rewrite {BINDS_LIST}: {e} — a bind that is still \
                       mounted has lost its only record");
        }
        return false;
    }
    // A stale list makes the next pass try to umount paths already gone. Not
    // fatal, but it is the difference between a clean pass and confusing noise.
    if let Err(e) = fs::remove_file(BINDS_LIST) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!("nomount: could not clear {BINDS_LIST}: {e} — the next pass will \
                       retry umounts that are already done");
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `binds.list` is the only record of the binds we made, and `parse_line` is
    /// the only reader. Pin the three shapes on disk right now: the current
    /// 3-field row, and the two legacy ones an upgrade-in-place still meets.
    #[test]
    fn a_binds_list_row_round_trips_through_parse_line() {
        let row = "/my_product/etc/x\t/data/adb/modules/m/my_product/etc/x\tu:object_r:adb_data_file:s0";
        let (t, s, l) = parse_line(row).expect("a full row parses");
        assert_eq!(t, PathBuf::from("/my_product/etc/x"));
        assert_eq!(s, PathBuf::from("/data/adb/modules/m/my_product/etc/x"));
        assert_eq!(l, "u:object_r:adb_data_file:s0");
        assert_eq!(format!("{}\t{}\t{}", t.display(), s.display(), l), row);

        // Legacy target+source, no label: the label reads back empty, which is
        // exactly the case `label_to_restore` answers for.
        let (t, s, l) = parse_line("/my_product/etc/x\t/data/adb/modules/m/x").unwrap();
        assert_eq!((t, s, l.as_str()), (PathBuf::from("/my_product/etc/x"),
                                        PathBuf::from("/data/adb/modules/m/x"), ""));
        // Legacy target-only: no source, which `restore_source_label` guards on.
        let (_, s, _) = parse_line("/my_product/etc/x").unwrap();
        assert!(s.as_os_str().is_empty());
        assert!(parse_line("   ").is_none(), "a blank line is not a row");
    }

    /// The idempotency guard and the rollback filter must answer the SAME
    /// question, or a rollback deletes a row this call did not write.
    ///
    /// `append_locked` returns `Ok(false)` when `row_is` already matches, and
    /// `apply` then skips `remove_record_locked` — whose filter drops EVERY row
    /// `row_is` matches, including the one a pass killed in the L5 window left
    /// behind holding the only copy of the source's true original label.
    #[test]
    fn the_rollback_matches_exactly_what_the_append_guard_skips() {
        let (t, s) = ("/my_product/etc/x", "/data/adb/modules/m/my_product/etc/x");
        assert!(row_is(Path::new(t), Path::new(s), t, s));
        // A different label on the row does not make it a different row: that is
        // the whole point — the killed pass's row and this pass's would-be row
        // name the same pair and only the FIRST holds the true label.
        assert!(row_is(Path::new(t), Path::new(s), t, s));
        // Neither half alone matches.
        assert!(!row_is(Path::new(t), Path::new("/data/adb/modules/other/x"), t, s));
        assert!(!row_is(Path::new("/my_product/etc/y"), Path::new(s), t, s));
        // Prefixes are not matches (the rollback must not eat a sibling row).
        assert!(!row_is(Path::new("/my_product/etc/xy"), Path::new(s), t, s));
    }

    /// An empty label field means the row cannot say what the source carried, and
    /// skipping the restore leaves a ROM label on a file under /data/adb which the
    /// next `apply` then records AS the original — self-perpetuating. Everything
    /// under /data/adb carries `adb_data_file`, so that is what to write.
    #[test]
    fn an_unrecorded_label_falls_back_to_adb_data_file() {
        assert_eq!(label_to_restore(""), "u:object_r:adb_data_file:s0");
        assert_eq!(label_to_restore("u:object_r:system_file:s0"), "u:object_r:system_file:s0");
        // And a row with no source at all is a no-op, not a relabel of "".
        restore_source_label(Path::new(""), "");
    }
}
