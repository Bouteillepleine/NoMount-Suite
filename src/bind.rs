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
use std::path::Path;

/// Targets we bound this boot, so the next mount pass can tear them down before
/// re-applying (binds do not survive reboot; a removed module must not leak one).
const BINDS_LIST: &str = "/data/adb/nomount/binds.list";
const SELINUX_XATTR: &[u8] = b"security.selinux\0";

fn cstr(p: &Path) -> Result<CString> {
    CString::new(p.to_str().context("non-utf8 path")?.as_bytes()).context("nul byte in path")
}

/// Copy `target`'s SELinux label onto `source`, so the bound file reports the
/// partition's context (e.g. `system_file`) instead of `adb_data_file` — without
/// this an app reading the my_* file hits an avc denial. Best-effort.
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
    // New-file binds would need a tmpfs/overlay; my_* module content is overrides
    // of existing OnePlus files, so require the target to exist.
    if !target.exists() {
        bail!("bind target missing (new-file unsupported): {}", target.display());
    }
    if let Err(e) = mirror_selinux(source, target) {
        eprintln!("nomount: warning - selinux relabel failed, binding anyway: {e:#}");
    }
    let (sc, tc) = (cstr(source)?, cstr(target)?);
    let r = unsafe {
        libc::mount(sc.as_ptr(), tc.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null())
    };
    if r != 0 {
        bail!("bind {} -> {}: {}", source.display(), target.display(), std::io::Error::last_os_error());
    }
    record(target);
    Ok(())
}

fn record(target: &Path) {
    if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(BINDS_LIST) {
        let _ = writeln!(f, "{}", target.display());
    }
}

/// Umount every bind we recorded, then clear the list. Run at the start of each
/// mount pass so stale binds (removed/updated modules) never accumulate.
pub fn teardown_all() {
    let Ok(list) = fs::read_to_string(BINDS_LIST) else {
        return;
    };
    for line in list.lines() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if let Ok(c) = CString::new(t) {
            unsafe {
                libc::umount2(c.as_ptr(), libc::MNT_DETACH);
            }
        }
    }
    let _ = fs::remove_file(BINDS_LIST);
}
