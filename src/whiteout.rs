
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::nm::Nm;

pub const WHITEOUT_PATH: &str = "/data/adb/nomount/whiteouts.txt";

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

pub(crate) fn measurable_hole(target: &Path) -> bool {
    const EROFS_MAGIC: i64 = 0xE0F5_E1E2;
    if parent_fs_magic(target) != Some(EROFS_MAGIC) {
        return false;
    }
    let dir = target.parent().unwrap_or(Path::new("/"));
    let size = fs::metadata(dir).map(|m| m.len()).unwrap_or(0);
    if size >= 4096 || size == 0 {
        return true;
    }
    engine_predates_v13()
}

fn engine_predates_v13() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| crate::nm::Nm::new().version().map(|v| v < 13).unwrap_or(true))
}

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

const SCAN_DIRS: &[&str] = &[
    "/system/bin", "/system/xbin", "/system/sbin", "/system/etc", "/system/etc/init",
    "/system/etc/init.d", "/system/addon.d", "/system/framework", "/system/lib",
    "/system/lib64", "/system/app", "/vendor/bin", "/vendor/etc/init",
    "/product/etc/init", "/system_ext/bin", "/system_ext/etc/init",
];

fn is_real_file(p: &Path) -> bool {
    p.is_file() && fs::File::open(p).is_ok()
}

pub fn read() -> Result<Vec<String>> {
    let raw = match fs::read_to_string(WHITEOUT_PATH) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context("read whiteouts.txt"),
    };
    Ok(parse(&raw))
}

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
    let mut body = String::from("# NoMount whiteouts - one absolute path per line, re-applied at boot.\n");
    for e in entries {
        body.push_str(e);
        body.push('\n');
    }
    fs::write(WHITEOUT_PATH, body).context("write whiteouts.txt")
}

pub(crate) fn validate(p: &str) -> Result<()> {
    let path = Path::new(p);
    if !path.is_absolute() {
        anyhow::bail!("not an absolute path: {p}");
    }
    if path.components().any(|c| matches!(c, std::path::Component::ParentDir)) {
        anyhow::bail!("refusing {p}: '..' is not allowed in a whiteout path (pass the resolved path)");
    }
    crate::mount::can_whiteout(path).map_err(|why| anyhow::anyhow!("refusing {p}: {why}"))
}

pub fn add(target: &str, force: bool) -> Result<()> {
    let t = target.trim().to_string();
    validate(&t)?;
    let p = Path::new(&t);
    if measurable_hole(p) && !force {
        eprintln!(
            "nomount: note - hiding {t} leaves a measurable hole: its parent is a multi-block \
             erofs directory (or the engine predates v13), so the size and link count still \
             count this entry and the engine cannot recompute them. Applying anyway; \
             `nomount check --plan` lists every such path."
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
    match Nm::new().whiteout(Path::new(&t)) {
        Ok(()) => {
            println!("ok: {t} hidden (persists across reboots)");
            Ok(())
        }
        Err(e) => Err(e.context(format!(
            "saved {t} to the durable list, but applying it now FAILED - the path is still \
             visible until the next reboot"
        ))),
    }
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
    match Nm::new().del(Path::new(t)) {
        Ok(()) => {
            println!("ok: {t} no longer hidden");
            Ok(())
        }
        Err(e) => Err(e.context(format!(
            "removed {t} from the durable list, but un-hiding it now FAILED - it stays \
             hidden until the next reboot"
        ))),
    }
}

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
    if failed > 0 {
        anyhow::bail!("{failed} of {} whiteout(s) could not be applied (applied {ok})", ok + failed);
    }
    Ok(())
}

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

fn app_can_see(path: &str) -> bool {
    let quoted = format!("'{}'", path.replace('\'', "'\\''"));
    std::process::Command::new("su")
        .args(["9999", "-c", &format!("ls -d {quoted}")])
        .output()
        .map(|o| o.status.success() && !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(true)
}

pub struct Candidate {
    pub path: String,
    pub why: &'static str,
    pub hole: bool,
}

pub fn scan() -> (Vec<Candidate>, usize, usize) {
    let have = read().unwrap_or_default();
    let injected = injected_targets();
    let (mut out, mut invisible, mut ours) = (Vec::new(), 0usize, 0usize);

    let mut queue: Vec<(PathBuf, u8)> =
        SCAN_DIRS.iter().map(|d| (PathBuf::from(d), 0u8)).collect();
    let mut seen = 0usize;
    while let Some((dir, depth)) = queue.pop() {
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
            out.push(Candidate { path: ps, why, hole: measurable_hole(&path) });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    (out, invisible, ours)
}

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
        println!("({ours} match(es) skipped: NoMount is serving them - they are module content)");
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

    #[test]
    fn refuses_every_root_the_module_plan_refuses() {
        for p in [
            "/apex/com.android.art/bin/dex2oat",
            "/apex/com.android.runtime/bin/dex2oat",
            "/proc/self/maps",
            "/sys/kernel/notes",
            "/dev/binder",
            "/mnt/vendor/persist/x",
            "/storage/emulated/0/x",
            "/data/adb/modules/x/y",
            "/d/tracing/x",
        ] {
            assert!(validate(p).is_err(), "{p} must be refused");
            assert!(
                crate::mount::can_whiteout(Path::new(p)).is_err(),
                "{p}: the two predicates must agree"
            );
        }
        for p in [
            "/system/bin/install-recovery.sh",
            "/product/app/AIMemory",
            "/my_stock/app/OplusOperationManual",
            "/vendor/etc/foo.conf",
        ] {
            assert!(validate(p).is_ok(), "{p} must be allowed");
            assert!(crate::mount::can_whiteout(Path::new(p)).is_ok(), "{p}");
        }
    }

    #[test]
    fn rejects_dotdot_escapes_to_a_partition_root() {
        for p in [
            "/system/../product",
            "/product/app/../..",
            "/system/bin/../../vendor",
            "/product/./..",
        ] {
            assert!(validate(p).is_err(), "{p} resolves to a partition root and must be refused");
        }
        assert!(validate("/system/bin/../lib/x.so").is_err(), "any .. must be refused");
        assert!(validate("/product/overlay/Foo.apk").is_ok());
        assert!(validate("/system/bin/install-recovery.sh").is_ok());
    }
}
