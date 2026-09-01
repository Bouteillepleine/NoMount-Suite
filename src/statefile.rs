//! Crash-safe replacement of the state files under `/data/adb/nomount`.
//!
//! WHY THIS EXISTS. `fs::write` opens with `O_TRUNC` and then writes, so the file
//! is EMPTY for the window between those two steps. Anything that stops the
//! process in that window -- ENOSPC, a SIGKILL, a power loss -- leaves a truncated
//! or empty file, and for these files that is not a lost diagnostic:
//!
//!   * `uidhide` / `uidhide.cache` are the per-app hiding POLICY. A truncated one
//!     is read as "nothing to hide", and the next boot's apply pass then blocks
//!     nobody -- every hidden app silently visible to every injection, with no
//!     error anywhere, because an empty hide list is a legal hide list.
//!   * `absorbed.list` is the only record of which module file was re-pointed at
//!     which app APK; losing it strands the rule at the next boot.
//!   * `whiteouts.txt` is the durable half of the whiteouts -- the engine's copy
//!     is runtime-only, so the file IS the state.
//!
//! `bind.rs` already made this argument for `binds.list` and shipped the
//! temp-then-rename for it alone ("the same discipline `service.sh` uses for
//! bindhosts' `mode_override.sh` and `lib.sh` for the ksud de-link, both for
//! smaller stakes"). Every reason it gave applies at least as strongly to the hide
//! list, so the pattern moves here and `bind.rs` calls it too rather than keeping
//! a second copy.
//!
//! WHAT THIS ADDS over that copy: an fsync of the PARENT DIRECTORY after the
//! rename. Without it the rename itself is only in the page cache, so a power loss
//! can still leave the old file -- `sync_all` on the temp durably stores the
//! CONTENT and says nothing about the directory entry that names it.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Replace `path` with `body`, atomically, mode 0600.
///
/// A reader sees either the whole old file or the whole new one, never a partial
/// write: `rename(2)` within one directory is atomic, and the temp lives beside
/// the target so it is always the same filesystem.
///
/// 0600 EXPLICITLY, not by umask: `fs::write` on an existing file keeps whatever
/// mode it already had, so a file a pre-umask build created 0666 stayed 0666
/// forever -- observed on `absorbed.list`, `uidhide` and `uidhide.cache`. Writing
/// through a fresh temp makes the mode a property of the write instead of a
/// property of the file's history, which is why the per-file `set_permissions`
/// calls that used to follow these writes are gone.
///
/// The temp carries the pid: two writers of one file (the boot pass applying the
/// hide list while the WebUI adds an entry, say) would otherwise share a `.new`
/// and interleave into it. A process killed between create and rename leaves one
/// small 0600 file behind; nothing reads `*.new.<pid>`, and the next write of that
/// state file does not collide with it.
pub(crate) fn write_atomic(path: impl AsRef<Path>, body: impl AsRef<[u8]>) -> std::io::Result<()> {
    let path = path.as_ref();
    let dir = path.parent().unwrap_or_else(|| Path::new("/"));
    // The callers used to do this themselves, each with its own `.ok()`; the state
    // directory has to exist for the temp just as much as for the target.
    fs::create_dir_all(dir)?;

    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.new", std::process::id()));
    let tmp = dir.join(name);

    let write = || -> std::io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(body.as_ref())?;
        // Content durable BEFORE the rename publishes it. Renaming first would let
        // a crash expose a name that points at unwritten blocks -- i.e. exactly the
        // empty file this whole module exists to prevent, reached the other way.
        f.sync_all()
    };
    if let Err(e) = write() {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    // Best-effort: the rename is already visible to every reader on this boot, so a
    // failure here costs crash-durability and nothing else. Not worth failing a
    // write that has, from userspace's point of view, succeeded.
    if let Ok(d) = fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn replaces_content_and_forces_0600() {
        let d = tempdir();
        let p = d.join("uidhide");
        // Start from a file with the wide mode a pre-umask build left behind:
        // `fs::write` would have preserved it, which is half the reason for this.
        fs::write(&p, b"old").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o666)).unwrap();

        write_atomic(&p, b"com.example.detector\n").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "com.example.detector\n");
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn creates_the_state_directory_and_the_file() {
        let d = tempdir();
        let p = d.join("nested").join("whiteouts.txt");
        write_atomic(&p, b"/system/etc/x\n").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "/system/etc/x\n");
    }

    /// The temp must not survive a successful write: a leftover beside the hide
    /// list is confusing at best, and a directory of them is a leak.
    #[test]
    fn leaves_no_temp_behind() {
        let d = tempdir();
        let p = d.join("absorbed.list");
        write_atomic(&p, b"a\n").unwrap();
        write_atomic(&p, b"b\n").unwrap();
        let left: Vec<_> = fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".new"))
            .collect();
        assert!(left.is_empty(), "temp files left behind: {left:?}");
        assert_eq!(fs::read_to_string(&p).unwrap(), "b\n");
    }

    /// An empty body is a legitimate state ("nothing is hidden"), and must land as
    /// an empty file rather than as an error or as the previous contents.
    #[test]
    fn an_empty_body_is_a_write_not_a_no_op() {
        let d = tempdir();
        let p = d.join("uidhide");
        write_atomic(&p, b"com.a\n").unwrap();
        write_atomic(&p, b"").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "");
    }

    fn tempdir() -> std::path::PathBuf {
        let p = std::env::temp_dir()
            .join(format!("nm-statefile-{}-{:?}", std::process::id(), std::thread::current().id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }
}
