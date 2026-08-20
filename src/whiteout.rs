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
use std::path::{Path, PathBuf};

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

/// How a filename is matched. Anchored on purpose: a plain substring test for
/// "ksu" matches `/system/bin/cksum`, and a scanner that proposes hiding a stock
/// coreutil is worse than no scanner. Measured on OP15, where `cksum` and
/// `debuggerd` were the ONLY hits a substring sweep produced.
enum Match {
    Exact(&'static str),
    Prefix(&'static str),
    Suffix(&'static str),
}

impl Match {
    fn hits(&self, name: &str) -> bool {
        match self {
            Match::Exact(x) => name == *x,
            Match::Prefix(x) => name.starts_with(x),
            Match::Suffix(x) => name.ends_with(x),
        }
    }
}

/// What the scan looks for, and why each one is a tell. Every entry is a file a
/// ROOT SETUP leaves on a read-only ROM partition — none of it ships on a stock
/// device, so a hit is meaningful rather than a heuristic.
const PATTERNS: &[(Match, &str)] = &[
    (Match::Prefix("install-recovery"), "recovery-restore script; a classic root-check target"),
    (Match::Exact("daemonsu"), "SuperSU daemon binary"),
    (Match::Exact("supolicy"), "SuperSU sepolicy tool"),
    (Match::Exact(".installed_su_daemon"), "SuperSU install marker"),
    (Match::Prefix("magisk"), "Magisk binary or applet left on the ROM"),
    (Match::Exact("Superuser.apk"), "SuperSU manager APK on the ROM"),
    (Match::Prefix("SuperSU"), "SuperSU payload on the ROM"),
    (Match::Exact("XposedBridge.jar"), "Xposed framework jar; probed directly by RASP"),
    (Match::Prefix("app_process_xposed"), "Xposed's replacement zygote entry point"),
    (Match::Prefix("libriru"), "Riru injection library"),
    (Match::Prefix("libzygisk"), "Zygisk injection library"),
    (Match::Prefix("libxposed"), "Xposed injection library"),
    (Match::Suffix("SuperSUDaemon"), "SuperSU init.d hook"),
];

/// Directories the scan reads. One level each -- bounded on purpose, and these
/// are where a root setup actually writes. `/system/xbin`, `/system/sbin` and
/// `/system/etc/init.d` do not exist on a modern device; that is the point, and
/// a hit there is worth more than one anywhere else.
const SCAN_DIRS: &[&str] = &[
    "/system/bin", "/system/xbin", "/system/sbin", "/system/etc", "/system/etc/init",
    "/system/etc/init.d", "/system/addon.d", "/system/framework", "/system/lib",
    "/system/lib64", "/system/app", "/vendor/bin", "/vendor/etc/init",
    "/product/etc/init", "/system_ext/bin", "/system_ext/etc/init",
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
    if list.contains(&t) {
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

/// Targets NoMount is currently serving.
///
/// A scanner that walks `/system/bin` will happily meet a file a MODULE put
/// there, and proposing a whiteout for it would hide that module's own content.
/// The old three-entry list never needed this check; a directory walk does.
fn injected_targets() -> std::collections::HashSet<String> {
    Nm::new()
        .list()
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let l = l.split(" [UID:").next().unwrap_or(l).trim();
            Some(l.rsplit_once(" -> ")?.0.trim().to_string())
        })
        .collect()
}

/// Can an ordinary, non-root-granted app see this path at all?
///
/// The decisive question, and the one a path list cannot answer. `/system/bin/su`
/// is the case that proves it: on a sucompat kernel it is present for a granted
/// uid and ENOENT for every app, so it is not a tell and hiding it would only
/// interfere with how root is invoked. uid 9999 (`nobody`) is never on the allow
/// list, and was verified on OP15 to see stock AND injected files while getting
/// ENOENT for `su`.
fn app_can_see(path: &str) -> bool {
    // Single-quoted: `path` is a FILENAME READ OFF THE FILESYSTEM, and this string
    // is handed to a shell. A ROM (or a module writing into one) carrying a name
    // like `x; id` would otherwise run it. uid 9999 is unprivileged, but a shell
    // built by concatenation is not something to leave standing.
    let quoted = format!("'{}'", path.replace('\'', "'\\''"));
    std::process::Command::new("su")
        .args(["9999", "-c", &format!("ls -d {quoted}")])
        .output()
        .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(true) // cannot ask -> do not silently drop the candidate
}

/// One thing the scan found worth hiding.
pub struct Candidate {
    pub path: String,
    pub why: &'static str,
    /// Hiding it still leaves the parent's size and link count counting it.
    /// Reported, NOT filtered -- see `scan`.
    pub hole: bool,
}

/// Walk the ROM for files that only a root setup leaves behind.
///
/// Returns (candidates, skipped_invisible, skipped_injected) so the caller can
/// say what was filtered rather than just showing a short list.
pub fn scan() -> (Vec<Candidate>, usize, usize) {
    let have = read().unwrap_or_default();
    let injected = injected_targets();
    let (mut out, mut invisible, mut ours) = (Vec::new(), 0usize, 0usize);

    // Depth 2, not 1. `/system/app` and `/system/priv-app` hold one DIRECTORY per
    // app, so a stale `Superuser.apk` lives at `/system/app/Superuser/Superuser.apk`
    // and a depth-1 walk could never match it -- the pattern was unreachable.
    let mut queue: Vec<(PathBuf, u8)> =
        SCAN_DIRS.iter().map(|d| (PathBuf::from(d), 0u8)).collect();
    let mut seen = 0usize;
    while let Some((dir, depth)) = queue.pop() {
        // Bounded: a symlinked ROM root could otherwise turn this into a full walk.
        seen += 1;
        if seen > 4096 {
            break;
        }
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            let path = e.path();
            if depth < 1 && e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                queue.push((path.clone(), depth + 1));
            }
            let Some((_, why)) = PATTERNS.iter().find(|(m, _)| m.hits(&name)) else { continue };
            let ps = path.to_string_lossy().into_owned();

            // Fabricated-at-the-syscall-layer paths stat but never open; a
            // whiteout cannot hide one and may break whatever provides it.
            if !is_real_file(&path) {
                continue;
            }
            if have.contains(&ps) || validate(&ps).is_err() {
                continue;
            }
            if injected.contains(&ps) {
                ours += 1;
                continue;
            }
            if !app_can_see(&ps) {
                invisible += 1;
                continue;
            }
            // NOT a filter. `/system/bin` is a multi-block erofs directory (8541
            // bytes on OP15), so every candidate in the one place these files
            // actually live leaves a measurable hole -- dropping them here made the
            // scan silently report "nothing found" on exactly the device that has
            // something to find. `whiteout add` applies such a hide anyway and says
            // so, so the scan proposes it and carries the same warning.
            out.push(Candidate { path: ps, why, hole: measurable_hole(&path) });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    (out, invisible, ours)
}

/// `nomount whiteout suggest` — scan THIS device and propose what it finds.
pub fn suggest() -> Result<()> {
    let (found, invisible, ours) = scan();
    for c in &found {
        let note = if c.hole { " (hiding it leaves a measurable hole in the parent)" } else { "" };
        println!("{}\t{}{note}", c.path, c.why);
    }
    if found.is_empty() {
        println!(
            "nothing to suggest: no root-setup leftovers on any ROM partition here. On a \
             mountless setup that is the expected result -- nothing is written to /system, so \
             there is nothing on it to hide."
        );
    } else {
        println!("\n{} candidate(s); add with: nomount whiteout add <path>", found.len());
    }
    if invisible > 0 {
        println!(
            "({invisible} match(es) skipped: no ordinary app can see them, so hiding them \
             would be a no-op)"
        );
    }
    if ours > 0 {
        println!("({ours} match(es) skipped: NoMount is serving them -- they are module content)");
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

    /// The false positive that made a substring sweep useless: "ksu" is inside
    /// `cksum`, and `debuggerd` contains "adbd". Both are stock binaries, and
    /// proposing a hide for either is worse than proposing nothing.
    #[test]
    fn patterns_are_anchored_and_miss_stock_binaries() {
        for stock in ["cksum", "debuggerd", "sh", "linker64", "app_process64", "toybox"] {
            assert!(
                !PATTERNS.iter().any(|(m, _)| m.hits(stock)),
                "{stock} is a stock binary and must never be proposed"
            );
        }
        for tell in [
            "install-recovery.sh", "install-recovery_oplus.sh", "daemonsu", "magiskinit",
            "XposedBridge.jar", "libriru.so", "99SuperSUDaemon",
        ] {
            assert!(PATTERNS.iter().any(|(m, _)| m.hits(tell)), "{tell} must be found");
        }
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
