//! Persistent whiteouts — hide stock ROM files that are themselves the tell.
//!
//! The engine supports whiteouts (`nm w`), but nothing kept a list, so any hide
//! was lost on reboot and had to be re-applied by hand. Mountify solves the same
//! problem with a curated `whiteouts.txt` plus a generator; this is the mountless
//! equivalent — a durable list re-applied at boot, with no module to install and
//! no mount to hide.
//!
//! Deliberately NOT seeded from someone else's list: the paths worth hiding are
//! ROM- and device-specific, and blindly whiting out a path this device does not
//! have is at best a no-op and at worst a boot hazard. `suggest` inspects THIS
//! device instead and only ever proposes paths that actually exist.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::nm::Nm;

pub const WHITEOUT_PATH: &str = "/data/adb/nomount/whiteouts.txt";

const OVERLAYFS_SUPER_MAGIC: i64 = 0x794c_7630;

/// True when the path sits on an overlayfs mount.
///
/// This decides whether a whiteout is safe, because hiding an entry is only
/// unmeasurable where the directory's own metadata does not describe its
/// contents. On the ROM's erofs partitions it does, exactly:
///
///   st_size  == 12 * entries + total name bytes
///   st_nlink == 2 + subdirectories
///
/// Both held with zero deviation across every stock directory checked on OP15,
/// and hiding one entry breaks them by precisely that entry's cost — a hole a
/// caller can compute from one stat plus one getdents64, with no knowledge of
/// the stock ROM. Overlayfs merged directories report neither relationship
/// (nlink is 1 and the size comes from one layer), so there is nothing to
/// contradict and the whiteout is genuinely invisible.
fn is_overlay(p: &Path) -> Option<bool> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c = CString::new(p.as_os_str().as_bytes()).ok()?;
    let mut sf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut sf) } != 0 {
        return None;
    }
    Some(sf.f_type as i64 == OVERLAYFS_SUPER_MAGIC)
}

/// The parent is what actually carries the evidence: hiding an entry changes
/// what the DIRECTORY reports, not the target.
pub(crate) fn measurable_hole(target: &Path) -> bool {
    let dir = target.parent().unwrap_or(Path::new("/"));
    matches!(is_overlay(dir), Some(false))
}

/// Patterns that are commonly probed and are safe to hide when present. Kept
/// device-agnostic: `suggest` filters these against what really exists here.
const SUGGESTIONS: &[(&str, &str)] = &[
    ("/system/bin/install-recovery.sh", "recovery-restore script; a classic root-check target"),
    ("/system/vendor/bin/install-recovery.sh", "same, vendor copy"),
    ("/system/etc/init/adbd.rc", "adb init policy; probed by USB-debug checks"),
];

/// A path that stats but cannot be OPENED is not a real file — it is fabricated
/// at the syscall layer. KSU's sucompat does exactly this for `/system/bin/su`:
/// `ls` and `stat` answer, `open` returns ENOENT, and it is how root is invoked.
/// Proposing a whiteout for such a path is useless at best and, for su,
/// recommends hiding the root mechanism itself. Only ever suggest real files.
fn is_real_file(p: &Path) -> bool {
    p.is_file() && fs::File::open(p).is_ok()
}

/// Read the persisted list: trimmed, comment- and blank-stripped, deduplicated.
pub fn read() -> Result<Vec<String>> {
    let raw = match fs::read_to_string(WHITEOUT_PATH) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context("read whiteouts.txt"),
    };
    Ok(parse(&raw))
}

/// Pure: trimmed, comment/blank-stripped, order-preserving, deduplicated.
fn parse(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in raw.lines() {
        let e = line.trim();
        if e.is_empty() || e.starts_with('#') {
            continue;
        }
        if !out.iter().any(|x| x == e) {
            out.push(e.to_string());
        }
    }
    out
}

fn write(entries: &[String]) -> Result<()> {
    if let Some(dir) = Path::new(WHITEOUT_PATH).parent() {
        fs::create_dir_all(dir).ok();
    }
    let mut body = String::from("# NoMount whiteouts — one absolute path per line, re-applied at boot.\n");
    for e in entries {
        body.push_str(e);
        body.push('\n');
    }
    fs::write(WHITEOUT_PATH, body).context("write whiteouts.txt")
}

/// A path is only worth whiting out if it is absolute, currently exists, and is
/// not a partition root. Hiding a whole partition masks every stock entry under
/// it, which is the same forkSystemServer abort an injection on a root causes.
pub(crate) fn validate(p: &str) -> Result<()> {
    let path = Path::new(p);
    if !path.is_absolute() {
        anyhow::bail!("not an absolute path: {p}");
    }
    if path.components().count() <= 2 {
        anyhow::bail!("refusing a partition root: {p} would mask every stock entry under it");
    }
    if p.starts_with("/data") {
        anyhow::bail!("refusing {p}: /data is not a ROM path");
    }
    Ok(())
}

pub fn add(target: &str, force: bool) -> Result<()> {
    let t = target.trim().to_string();
    validate(&t)?;
    let p = Path::new(&t);
    if measurable_hole(p) && !force {
        anyhow::bail!(
            "refusing {t}: its directory is not on overlayfs, so hiding the entry leaves a \
             measurable hole. There st_size == 12*entries + name bytes and st_nlink == 2 + \
             subdirs, exactly; removing this entry from the listing without changing either \
             is something no real filesystem does, and any caller can check it with one stat \
             and one getdents64. Whiteouts under an overlayfs mount carry no such evidence. \
             Use --force if you want it anyway."
        );
    }
    if !p.exists() {
        eprintln!("nomount: note - {t} does not exist right now; recorded anyway");
    } else if !is_real_file(p) && p.is_file() {
        eprintln!(
            "nomount: warning - {t} stats but cannot be opened, so it is fabricated at the \
             syscall layer (e.g. KSU sucompat's su), not a real file. A whiteout will not \
             hide it and may interfere with whatever provides it."
        );
    }
    let mut list = read()?;
    if list.iter().any(|x| *x == t) {
        println!("already listed: {t}");
        return Ok(());
    }
    list.push(t.clone());
    write(&list)?;
    // Apply immediately so the effect does not wait for a reboot.
    match Nm::new().whiteout(Path::new(&t)) {
        Ok(()) => println!("ok: {t} hidden (persists across reboots)"),
        Err(e) => println!("saved {t}, but applying now failed: {e:#}"),
    }
    Ok(())
}

pub fn remove(target: &str) -> Result<()> {
    let t = target.trim();
    let mut list = read()?;
    let before = list.len();
    list.retain(|x| x != t);
    if list.len() == before {
        println!("not listed: {t}");
        return Ok(());
    }
    write(&list)?;
    let _ = Nm::new().del(Path::new(t));
    println!("ok: {t} no longer hidden");
    Ok(())
}

pub fn list() -> Result<()> {
    let entries = read()?;
    if entries.is_empty() {
        println!("no whiteouts configured");
        return Ok(());
    }
    for e in &entries {
        let state = if Path::new(e).exists() { "visible - not applied" } else { "hidden" };
        println!("{e}\t{state}");
    }
    Ok(())
}

/// Re-apply the whole list. Called at boot, after the mount pass.
pub fn apply() -> Result<()> {
    let nm = Nm::new();
    let (mut ok, mut failed) = (0u32, 0u32);
    for e in read()? {
        if validate(&e).is_err() {
            eprintln!("nomount: skipping invalid whiteout entry {e:?}");
            failed += 1;
            continue;
        }
        if measurable_hole(Path::new(&e)) {
            eprintln!(
                "nomount: warning - {e} is not on overlayfs; the whiteout is measurable \
                 from its directory's size and link count"
            );
        }
        match nm.whiteout(Path::new(&e)) {
            Ok(()) => ok += 1,
            Err(_) => failed += 1,
        }
    }
    println!("nomount whiteout: applied {ok}, failed {failed}");
    Ok(())
}

/// Propose only paths that exist on THIS device and are not already listed.
pub fn suggest() -> Result<()> {
    let have = read()?;
    let mut found = 0;
    for (p, why) in SUGGESTIONS {
        let path = Path::new(p);
        if is_real_file(path) && !have.iter().any(|x| x == p) {
            if measurable_hole(path) {
                continue; /* would be refused; proposing it would only mislead */
            }
            println!("{p}\t{why}");
            found += 1;
        }
    }
    if found == 0 {
        println!("nothing to suggest: none of the known candidates exist here, or all are listed");
    } else {
        println!("\n{found} candidate(s); add with: nomount whiteout add <path>");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_strips_comments_blanks_and_dedups() {
        let raw = "# hdr\n\n/system/bin/x\n  /system/bin/y  \n/system/bin/x\n";
        assert_eq!(parse(raw), vec!["/system/bin/x".to_string(), "/system/bin/y".to_string()]);
    }

    #[test]
    fn rejects_partition_roots_and_relative_and_data() {
        assert!(validate("/product").is_err(), "partition root must be refused");
        assert!(validate("/").is_err());
        assert!(validate("system/bin/x").is_err(), "relative must be refused");
        assert!(validate("/data/adb/x").is_err(), "/data is not a ROM path");
        assert!(validate("/system/bin/install-recovery.sh").is_ok());
    }
}
