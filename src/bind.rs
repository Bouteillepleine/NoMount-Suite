//! Real bind mounts for targets hookless injection cannot serve

use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

pub(crate) const BINDS_LIST: &str = "/data/adb/nomount/binds.list";
const LOCK_FILE: &str = "/data/adb/nomount/binds.lock";
const SELINUX_XATTR: &[u8] = b"security.selinux\0";

struct Lock(fs::File);
impl Lock {
    fn acquire() -> Result<Lock> {
        let f = {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .mode(0o600)
                .open(LOCK_FILE)
                .with_context(|| format!("open {LOCK_FILE}"))?
        };
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

fn cstr(p: &Path) -> Result<CString> {
    CString::new(p.as_os_str().as_encoded_bytes()).context("nul byte in path")
}

fn is_mounted(target: &Path) -> bool {
    fs::read_to_string("/proc/self/mountinfo")
        .map(|s| crate::absorb::parse_mountinfo(&s).iter().any(|r| r.target == target))
        .unwrap_or(false)
}

fn read_selinux(p: &Path) -> Option<Vec<u8>> {
    let c = cstr(p).ok()?;
    let mut buf = [0u8; 256];
    let n = unsafe {
        libc::lgetxattr(c.as_ptr(), SELINUX_XATTR.as_ptr() as *const libc::c_char,
                        buf.as_mut_ptr() as *mut libc::c_void, buf.len())
    };
    if n <= 0 { None } else { Some(buf[..n as usize].to_vec()) }
}

fn restore_selinux(p: &Path, label: &[u8]) {
    if let Ok(c) = cstr(p) {
        unsafe {
            libc::lsetxattr(c.as_ptr(), SELINUX_XATTR.as_ptr() as *const libc::c_char,
                            label.as_ptr() as *const libc::c_void, label.len(), 0);
        }
    }
}

fn restore_source_label(source: &Path, lbl: &str) {
    if source.as_os_str().is_empty() {
        return;
    }
    restore_selinux(source, format!("{}\0", label_to_restore(lbl)).as_bytes());
}

fn label_to_restore(lbl: &str) -> &str {
    if lbl.is_empty() { "u:object_r:adb_data_file:s0" } else { lbl }
}

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

/// The result of an [`apply`] that succeeded
pub enum BindOutcome {
    Bound,
    AlreadyMounted,
}

/// File-over-file bind of `source` onto an existing `target`
pub fn apply(source: &Path, target: &Path) -> Result<BindOutcome> {
    let s = source.to_str().context("non-utf8 bind source")?.to_string();
    let t = target.to_str().context("non-utf8 bind target")?.to_string();
    if !target.exists() {
        bail!("bind target missing (new-file unsupported): {t}");
    }
    if fs::symlink_metadata(source).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
        bail!(
            "bind source {s} is a symlink; a bind would serve its target instead, with the \
             wrong SELinux label. Ship the file itself"
        );
    }

    let _lock = Lock::acquire()?;
    if is_mounted(target) {
        return Ok(BindOutcome::AlreadyMounted);
    }
    let orig_label = read_selinux(source);
    let lbl = orig_label.as_deref().map(|l| String::from_utf8_lossy(l).trim_end_matches('\0').to_string())
        .unwrap_or_default();
    let newly_recorded = match append_locked(&t, &s, &lbl) {
        Ok(v) => v,
        Err(e) => {
            if let Some(l) = &orig_label { restore_selinux(source, l); }
            bail!("bind of {t} could not be recorded ({e}); not bound");
        }
    };
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

fn write_binds_list(body: &str) -> std::io::Result<()> {
    crate::statefile::write_atomic(BINDS_LIST, body)
}

fn row_is(t: &Path, s: &Path, target: &str, source: &str) -> bool {
    t.to_string_lossy() == target && s.to_string_lossy() == source
}

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

fn append_locked(target: &str, source: &str, orig_label: &str) -> std::io::Result<bool> {
    use std::os::unix::fs::OpenOptionsExt;
    if tracked_full().iter().any(|(t, s, _)| row_is(t, s, target, source)) {
        return Ok(false);
    }
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(BINDS_LIST)?;
    let orig = f.metadata()?.len();
    if let Err(e) = writeln!(f, "{target}\t{source}\t{orig_label}") {
        let _ = f.set_len(orig);
        return Err(e);
    }
    Ok(true)
}

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

/// (target, source) pairs we currently have bound (from binds.list)
pub fn tracked() -> Vec<(PathBuf, PathBuf)> {
    tracked_full().into_iter().map(|(t, s, _)| (t, s)).collect()
}

/// As [`tracked`], but an unreadable `binds.list` is an error rather than an empty list
pub fn tracked_result() -> std::io::Result<Vec<(PathBuf, PathBuf)>> {
    match fs::read_to_string(BINDS_LIST) {
        Ok(s) => Ok(s.lines().filter_map(parse_line).map(|(t, s, _)| (t, s)).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

fn tracked_full() -> Vec<(PathBuf, PathBuf, String)> {
    fs::read_to_string(BINDS_LIST)
        .map(|s| s.lines().filter_map(parse_line).collect())
        .unwrap_or_default()
}

fn umount_target(target: &Path) -> Result<(), String> {
    let c = CString::new(target.as_os_str().as_encoded_bytes())
        .map_err(|_| "nul byte in path".to_string())?;
    if unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) } == 0 {
        return Ok(());
    }
    let e = std::io::Error::last_os_error();
    if !is_mounted(target) {
        return Ok(());
    }
    Err(e.to_string())
}

/// Umount a single tracked bind and drop it from the list (gap-free reload)
pub fn umount_one(target: &Path) -> bool {
    let _lock = match Lock::acquire() {
        Ok(l) => l,
        Err(e) => {
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
    for (t, s, lbl) in rows.iter().filter(|(t, _, _)| t == target) {
        let _ = t;
        restore_source_label(s, lbl);
    }
    let remaining: String = rows
        .into_iter()
        .filter(|(t, _, _)| t != target)
        .map(|(t, s, l)| format!("{}\t{}\t{}\n", t.display(), s.display(), l))
        .collect();
    if let Err(e) = write_binds_list(&remaining) {
        eprintln!(
            "nomount: could not update {BINDS_LIST}: {e} - a bind may be left \
             recorded (or unrecorded) and will not be cleaned up on the next pass"
        );
    }
    true
}

/// Umount every bind we recorded, then clear the list
pub fn teardown_all() -> bool {
    let _lock = match Lock::acquire() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("nomount: not tearing down recorded binds: {e:#}");
            return false;
        }
    };
    let list = match fs::read_to_string(BINDS_LIST) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return true,
        Err(e) => {
            eprintln!("nomount: could not read {BINDS_LIST}: {e} - binds from the previous \
                       pass cannot be torn down");
            return false;
        }
    };
    let mut kept = String::new();
    for line in list.lines() {
        let Some((t, s, lbl)) = parse_line(line) else {
            continue;
        };
        if let Err(e) = umount_target(&t) {
            eprintln!(
                "nomount: could not umount the bind over {} ({e}); keeping its record and \
                 its ROM label - a live bind serving a file labelled adb_data_file is an \
                 avc denial and a tell",
                t.display()
            );
            kept.push_str(&format!("{}\t{}\t{}\n", t.display(), s.display(), lbl));
            continue;
        }
        restore_source_label(&s, &lbl);
    }
    if !kept.is_empty() {
        if let Err(e) = write_binds_list(&kept) {
            eprintln!("nomount: could not rewrite {BINDS_LIST}: {e} - a bind that is still \
                       mounted has lost its only record");
        }
        return false;
    }
    if let Err(e) = fs::remove_file(BINDS_LIST) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!("nomount: could not clear {BINDS_LIST}: {e} - the next pass will \
                       retry umounts that are already done");
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_binds_list_row_round_trips_through_parse_line() {
        let row = "/my_product/etc/x\t/data/adb/modules/m/my_product/etc/x\tu:object_r:adb_data_file:s0";
        let (t, s, l) = parse_line(row).expect("a full row parses");
        assert_eq!(t, PathBuf::from("/my_product/etc/x"));
        assert_eq!(s, PathBuf::from("/data/adb/modules/m/my_product/etc/x"));
        assert_eq!(l, "u:object_r:adb_data_file:s0");
        assert_eq!(format!("{}\t{}\t{}", t.display(), s.display(), l), row);

        let (t, s, l) = parse_line("/my_product/etc/x\t/data/adb/modules/m/x").unwrap();
        assert_eq!((t, s, l.as_str()), (PathBuf::from("/my_product/etc/x"),
                                        PathBuf::from("/data/adb/modules/m/x"), ""));
        let (_, s, _) = parse_line("/my_product/etc/x").unwrap();
        assert!(s.as_os_str().is_empty());
        assert!(parse_line("   ").is_none(), "a blank line is not a row");
    }

    #[test]
    fn the_rollback_matches_exactly_what_the_append_guard_skips() {
        let (t, s) = ("/my_product/etc/x", "/data/adb/modules/m/my_product/etc/x");
        assert!(row_is(Path::new(t), Path::new(s), t, s));
        assert!(row_is(Path::new(t), Path::new(s), t, s));
        assert!(!row_is(Path::new(t), Path::new("/data/adb/modules/other/x"), t, s));
        assert!(!row_is(Path::new("/my_product/etc/y"), Path::new(s), t, s));
        assert!(!row_is(Path::new("/my_product/etc/xy"), Path::new(s), t, s));
    }

    #[test]
    fn an_unrecorded_label_falls_back_to_adb_data_file() {
        assert_eq!(label_to_restore(""), "u:object_r:adb_data_file:s0");
        assert_eq!(label_to_restore("u:object_r:system_file:s0"), "u:object_r:system_file:s0");
        restore_source_label(Path::new(""), "");
    }
}
