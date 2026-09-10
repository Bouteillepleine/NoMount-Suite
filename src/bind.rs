
use anyhow::{bail, Context, Result};
use std::ffi::CString;
use std::fs;
use std::io::Write;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

const BINDS_LIST: &str = "/data/adb/nomount/binds.list";
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
    CString::new(p.to_str().context("non-utf8 path")?.as_bytes()).context("nul byte in path")
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

pub enum BindOutcome {
    Bound,
    AlreadyMounted,
}

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
    if let Err(e) = append_locked(&t, &s, &lbl) {
        if let Some(l) = &orig_label { restore_selinux(source, l); }
        bail!("bind of {t} could not be recorded ({e}); not bound");
    }
    if let Err(e) = mirror_selinux(source, target).with_context(|| format!("relabel for bind of {t}")) {
        remove_record_locked(&t, &s);
        if let Some(l) = &orig_label { restore_selinux(source, l); }
        return Err(e);
    }

    let (sc, tc) = (cstr(source)?, cstr(target)?);
    let r = unsafe {
        libc::mount(sc.as_ptr(), tc.as_ptr(), std::ptr::null(), libc::MS_BIND, std::ptr::null())
    };
    if r != 0 {
        remove_record_locked(&t, &s);
        if let Some(l) = &orig_label { restore_selinux(source, l); }
        bail!("bind {} -> {t}: {}", source.display(), std::io::Error::last_os_error());
    }
    Ok(BindOutcome::Bound)
}

fn remove_record_locked(target: &str, source: &str) {
    let remaining: String = tracked_full()
        .into_iter()
        .filter(|(t, s, _)| !(t.to_string_lossy() == target && s.to_string_lossy() == source))
        .map(|(t, s, l)| format!("{}\t{}\t{}\n", t.display(), s.display(), l))
        .collect();
    if let Err(e) = fs::write(BINDS_LIST, &remaining) {
        eprintln!("nomount: could not roll back a failed bind record in {BINDS_LIST}: {e}");
    }
}

fn append_locked(target: &str, source: &str, orig_label: &str) -> std::io::Result<()> {
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(BINDS_LIST)?;
    writeln!(f, "{target}\t{source}\t{orig_label}")
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

pub fn tracked() -> Vec<(PathBuf, PathBuf)> {
    tracked_full().into_iter().map(|(t, s, _)| (t, s)).collect()
}

fn tracked_full() -> Vec<(PathBuf, PathBuf, String)> {
    fs::read_to_string(BINDS_LIST)
        .map(|s| s.lines().filter_map(parse_line).collect())
        .unwrap_or_default()
}

fn umount_target(target: &Path) -> Result<(), String> {
    let c = CString::new(target.to_string_lossy().as_bytes())
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
        if !lbl.is_empty() {
            restore_selinux(s, format!("{lbl}\0").as_bytes());
        }
    }
    let remaining: String = rows
        .into_iter()
        .filter(|(t, _, _)| t != target)
        .map(|(t, s, l)| format!("{}\t{}\t{}\n", t.display(), s.display(), l))
        .collect();
    if let Err(e) = fs::write(BINDS_LIST, &remaining) {
        eprintln!(
            "nomount: could not update {BINDS_LIST}: {e} - a bind may be left \
             recorded (or unrecorded) and will not be cleaned up on the next pass"
        );
    }
    true
}

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
        if !lbl.is_empty() {
            restore_selinux(&s, format!("{lbl}\0").as_bytes());
        }
    }
    if !kept.is_empty() {
        if let Err(e) = fs::write(BINDS_LIST, &kept) {
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
