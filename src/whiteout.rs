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


/// Statfs magic of the directory holding `target`.
fn parent_fs_magic(target: &Path) -> Option<i64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let dir = target.parent().unwrap_or(Path::new("/"));
    let c = CString::new(dir.as_os_str().as_bytes()).ok()?;
    let mut sf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut sf) } != 0 {
        return None;
    }
    Some(sf.f_type as i64)
}

/// Does hiding `target` leave evidence in its PARENT's metadata?
///
/// Only erofs describes a directory's contents in the directory itself, and only
/// while it fits in one block:
///   * **erofs, size < 4096** — `st_size == 12*(entries incl . and ..) + name
///     bytes` exactly, so a hidden entry is one stat plus one getdents64 away…
///     UNLESS the engine corrects it, which it does from v13 (it recomputes both
///     size and nlink from the served listing). Hence the version gate: a new
///     Suite on an OLD kernel still leaves the hole and must still say so.
///   * **erofs, size >= 4096** — erofs pads each block by an amount that depends
///     on where the names fall (measured +18…+208 on stock dirs), so there is no
///     closed form for the engine to correct, and the hole stays.
///   * **overlayfs** — reports `nlink=1` and a size unrelated to the entry set.
///   * **f2fs / ext4** — block-granular (`/data/adb` is 3452 for 22 entries).
///     These were previously reported as holes by a plain "not overlayfs" test,
///     which was wrong: there is no invariant to contradict.
pub(crate) fn measurable_hole(target: &Path) -> bool {
    const EROFS_MAGIC: i64 = 0xE0F5_E1E2;
    if parent_fs_magic(target) != Some(EROFS_MAGIC) {
        return false;
    }
    let dir = target.parent().unwrap_or(Path::new("/"));
    let size = fs::metadata(dir).map(|m| m.len()).unwrap_or(0);
    if size >= 4096 || size == 0 {
        return true; // multi-block: no closed form, engine cannot correct it
    }
    // Single block: only a hole on an engine that does not recompute.
    engine_predates_v13()
}

/// Cached: `measurable_hole` runs once per whiteout, and every call used to fork
/// `nm v`. A debloat module is ENTIRELY whiteouts, so `doctor` on one spawned a
/// process per hide for an answer that cannot change within a run.
fn engine_predates_v13() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| crate::nm::Nm::new().version().map(|v| v < 13).unwrap_or(true))
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
    // Warn, do not refuse. Module whiteouts are applied off overlayfs (see
    // mount::whiteout_leaves_hole), and a CLI that still refused the same
    // operation would be the odd one out. `--force` is kept as a no-op so
    // existing scripts and the message this used to print stay valid; passing it
    // just silences the note.
    if measurable_hole(p) && !force {
        eprintln!(
            "nomount: note - hiding {t} leaves a measurable hole: its parent is a multi-block \
             erofs directory (or the engine predates v13), so the size and link count still \
             count this entry and the engine cannot recompute them. Applying anyway; \
             `nomount doctor` lists every such path."
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

/// Targets the engine is currently whiting out, from `nm list`.
fn live_whiteouts() -> std::collections::HashSet<String> {
    Nm::new()
        .list()
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split(" [UID:").next().unwrap_or(l).trim().strip_suffix(" (whiteout)"))
        .map(|t| t.trim().to_string())
        .collect()
}

pub fn list() -> Result<()> {
    let entries = read()?;
    if entries.is_empty() {
        println!("no whiteouts configured");
        return Ok(());
    }
    // Path-absence alone cannot tell "hidden" from "was never there": an entry for a
    // path this ROM does not ship reported `hidden`, which reads as working. Ask the
    // engine which targets it is actually serving, and use absence only to confirm.
    let live = live_whiteouts();
    for e in &entries {
        let applied = live.contains(e);
        let present = Path::new(e).exists();
        let state = match (applied, present) {
            (true, false) => "hidden",
            (true, true) => "applied, but still visible - the engine is not serving it",
            (false, false) => "not applied (and no such path on this ROM)",
            (false, true) => "not applied - run `nomount whiteout apply`",
        };
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
                "nomount: warning - {e} leaves a measurable hole; the whiteout is detectable \
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
