
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::nm::Nm;

const MOUNTINFO: &str = "/proc/self/mountinfo";
const MODULE_ROOT: &str = "/data/adb";
const FOREIGN_ROOT: &str = "/data";
pub const SKIP_FILE: &str = "/data/adb/nomount/absorb-skip.txt";
const SKIP_FILE_LEGACY: &str = "/data/adb/nomount/absorb-skip";
pub const ABSORBED_LIST: &str = "/data/adb/nomount/absorbed.list";
pub const ABSORBED_TMPFS_LIST: &str = "/data/adb/nomount/absorbed-tmpfs.list";

const BUILTIN_SKIPS: &[&str] = &[
    "/apex/com.android.art/bin/dex2oat",
    "/apex/com.android.runtime/bin/dex2oat",
    "/system/bin/dex2oat", // pre-apex layout
    "/system/bin/app_process",
];

fn skip_list() -> (Vec<String>, &'static str) {
    let mut entries: Vec<String> = BUILTIN_SKIPS.iter().map(|s| (*s).to_string()).collect();
    let mut from = "the built-in list";
    for f in [SKIP_FILE, SKIP_FILE_LEGACY] {
        if let Ok(s) = std::fs::read_to_string(f) {
            if from == "the built-in list" {
                from = f;
            }
            entries.extend(
                s.lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(str::to_string),
            );
        }
    }
    entries.sort();
    entries.dedup();
    (entries, from)
}

pub(crate) fn is_hook_framework(module_dir: &Path) -> bool {
    if module_dir.join("zygisk").is_dir() {
        return true;
    }
    let Ok(bin) = fs::read_dir(module_dir.join("bin")) else {
        return false;
    };
    bin.filter_map(Result::ok)
        .any(|e| e.file_name().to_string_lossy().starts_with("zygisk"))
}

pub(crate) fn module_dir_of(src: &Path) -> Option<PathBuf> {
    let s = src.to_string_lossy();
    let rest = s.split("/modules/").nth(1)?;
    let id = rest.split('/').next()?;
    if id.is_empty() {
        return None;
    }
    Some(PathBuf::from("/data/adb/modules").join(id))
}

fn hooking_modules(rows: &[MountRow], roots: &HashMap<String, PathBuf>, skips: &[String]) -> HashSet<String> {
    let mut ids = HashSet::new();
    for r in rows {
        let Some(src) = source_of(r, roots) else { continue };
        let Some(dir) = module_dir_of(&src) else { continue };
        let hooks_a_path = skips.iter().any(|k| {
            k.starts_with('/') && r.target.to_string_lossy().starts_with(k.as_str())
        });
        if hooks_a_path || is_hook_framework(&dir) {
            if let Some(id) = dir.file_name() {
                ids.insert(id.to_string_lossy().into_owned());
            }
        }
    }
    ids
}

pub enum Declined {
    Framework(String),
    HooksElsewhere(String),
    Listed(&'static str),
    MustBind,
}

pub enum Disposition {
    Absorb,
    Redundant,
    Declined(Declined),
    Leaking(&'static str),
}

pub struct Surveyed {
    pub target: PathBuf,
    pub source: PathBuf,
    pub disposition: Disposition,
}

pub(crate) fn declined_reason_with(
    src: &Path,
    target: &Path,
    skips: &[String],
    from: &'static str,
    hookers: &HashSet<String>,
) -> Option<Declined> {
    if let Some(d) = module_dir_of(src) {
        let id = d.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if is_hook_framework(&d) {
            return Some(Declined::Framework(id));
        }
        if hookers.contains(&id) {
            return Some(Declined::HooksElsewhere(id));
        }
    }
    is_skipped(src, target, skips).then_some(Declined::Listed(from))
}

pub(crate) fn is_skipped(src: &Path, target: &Path, skips: &[String]) -> bool {
    if module_dir_of(src).is_some_and(|d| is_hook_framework(&d)) {
        return true;
    }
    let (s, t) = (src.to_string_lossy(), target.to_string_lossy());
    skips.iter().any(|k| {
        if k.starts_with('/') {
            t.starts_with(k.as_str())
        } else {
            s.contains(&format!("/modules/{k}/"))
        }
    })
}

#[derive(Debug, Clone)]
pub(crate) struct MountRow {
    pub dev: String,
    pub root: String,
    pub target: PathBuf,
}

pub(crate) fn parse_mountinfo(body: &str) -> Vec<MountRow> {
    let mut out = Vec::new();
    for line in body.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f.len() < 5 {
            continue;
        }
        out.push(MountRow {
            dev: f[2].to_string(),
            root: unescape(f[3]),
            target: PathBuf::from(unescape(f[4])),
        });
    }
    out
}

fn unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 4])
                .ok()
                .and_then(|o| u8::from_str_radix(o, 8).ok())
            {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

pub(crate) fn fs_roots(rows: &[MountRow]) -> HashMap<String, PathBuf> {
    let mut m: HashMap<String, PathBuf> = HashMap::new();
    for r in rows.iter().filter(|r| r.root == "/") {
        m.entry(r.dev.clone())
            .and_modify(|cur| {
                if r.target.as_os_str().len() < cur.as_os_str().len() {
                    *cur = r.target.clone();
                }
            })
            .or_insert_with(|| r.target.clone());
    }
    m
}

pub(crate) fn source_of(row: &MountRow, roots: &HashMap<String, PathBuf>) -> Option<PathBuf> {
    if row.root == "/" {
        return None;
    }
    let base = roots.get(&row.dev)?;
    let rel = row.root.trim_start_matches('/');
    Some(if base == Path::new("/") {
        PathBuf::from("/").join(rel)
    } else {
        base.join(rel)
    })
}

pub(crate) fn is_app_apk(target: &Path) -> bool {
    if !target.starts_with("/data/app/") {
        return false;
    }
    let n = target.components().count();
    if n != 5 && n != 6 {
        return false;
    }
    target
        .file_name()
        .and_then(|f| f.to_str())
        .is_some_and(|f| f == "base.apk" || (f.starts_with("split_") && f.ends_with(".apk")))
}

pub(crate) fn is_absorbable(src: &Path, target: &Path) -> bool {
    src.starts_with(MODULE_ROOT)
        && (!target.starts_with(FOREIGN_ROOT) || is_app_apk(target))
        && target.components().count() > 1
}

pub struct Elsewhere {
    pub seen_in: String,
    pub mount: Surveyed,
}

fn mnt_ns_of(pid: &str) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/ns/mnt")).ok().map(|p| p.to_string_lossy().into_owned())
}

fn namespace_probes() -> Vec<(String, String)> {
    let mut out = vec![("init".to_string(), "1".to_string())];
    let Ok(rd) = fs::read_dir("/proc") else { return out };
    for e in rd.filter_map(Result::ok) {
        let pid = e.file_name().to_string_lossy().into_owned();
        if !pid.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(raw) = fs::read_to_string(format!("/proc/{pid}/cmdline")) else { continue };
        let name = raw.split('\0').next().unwrap_or("").trim();
        if name == "zygote64" || name == "zygote" {
            out.push((name.to_string(), pid));
        }
    }
    out
}

pub fn survey_elsewhere() -> Vec<Elsewhere> {
    let Some(mine) = mnt_ns_of("self") else { return Vec::new() };
    let ours: HashSet<(PathBuf, PathBuf)> = survey()
        .unwrap_or_default()
        .into_iter()
        .map(|s| (s.target, s.source))
        .collect();

    let mut seen_ns: HashSet<String> = HashSet::from([mine]);
    let mut out = Vec::new();
    for (name, pid) in namespace_probes() {
        let Some(ns) = mnt_ns_of(&pid) else { continue };
        if !seen_ns.insert(ns) {
            continue;
        }
        for m in survey_of(&format!("/proc/{pid}/mountinfo")).unwrap_or_default() {
            if !ours.contains(&(m.target.clone(), m.source.clone())) {
                out.push(Elsewhere { seen_in: format!("{name} (pid {pid})"), mount: m });
            }
        }
    }
    out
}

#[derive(Default)]
pub(crate) struct Redundancy {
    live: HashMap<PathBuf, PathBuf>,
    aliases: Vec<(PathBuf, PathBuf)>,
}

const REDUNDANCY_FILE_BUDGET: usize = 5000;

pub(crate) fn live_injections(list: &str) -> HashMap<PathBuf, PathBuf> {
    crate::nm::parse_list(list)
        .into_iter()
        .filter(|r| r.uid == 0 && r.kind == crate::nm::LiveKind::Inject)
        .filter_map(|r| Some((r.target, r.source?)))
        .collect()
}

pub(crate) fn mount_aliases(rows: &[MountRow]) -> Vec<(PathBuf, PathBuf)> {
    let mut by_subtree: HashMap<(&str, &str), Vec<&PathBuf>> = HashMap::new();
    for r in rows {
        by_subtree.entry((r.dev.as_str(), r.root.as_str())).or_default().push(&r.target);
    }
    let mut out = Vec::new();
    for targets in by_subtree.values() {
        for a in targets {
            for b in targets {
                if a != b {
                    out.push(((*a).clone(), (*b).clone()));
                }
            }
        }
    }
    out
}

fn files_under(src: &Path) -> Option<Vec<PathBuf>> {
    fn walk(dir: &Path, prefix: &Path, out: &mut Vec<PathBuf>) -> Option<()> {
        for e in std::fs::read_dir(dir).ok()?.flatten() {
            if out.len() >= REDUNDANCY_FILE_BUDGET {
                return None;
            }
            let ft = e.file_type().ok()?;
            let rel = prefix.join(e.file_name());
            if ft.is_dir() {
                walk(&e.path(), &rel, out)?;
            } else {
                out.push(rel);
            }
        }
        Some(())
    }
    if !src.is_dir() {
        return src.exists().then(|| vec![PathBuf::new()]);
    }
    let mut out = Vec::new();
    walk(src, Path::new(""), &mut out)?;
    (!out.is_empty()).then_some(out)
}

impl Redundancy {
    pub(crate) fn new(list: &str, rows: &[MountRow]) -> Self {
        Self { live: live_injections(list), aliases: mount_aliases(rows) }
    }

    fn reachable(&self, target: &Path) -> Vec<PathBuf> {
        let mut out = vec![target.to_path_buf()];
        for (a, b) in &self.aliases {
            if let Ok(tail) = target.strip_prefix(a) {
                out.push(b.join(tail));
            }
        }
        out
    }

    pub(crate) fn covers(&self, src: &Path, target: &Path) -> bool {
        let Some(files) = files_under(src) else { return false };
        files.iter().all(|rel| {
            let want = if rel.as_os_str().is_empty() { src.to_path_buf() } else { src.join(rel) };
            self.reachable(target)
                .iter()
                .any(|t| self.live.get(&t.join(rel)).is_some_and(|s| *s == want))
        })
    }
}

pub(crate) fn classify(
    src: &Path,
    target: &Path,
    skips: &[String],
    skip_src: &'static str,
    hookers: &HashSet<String>,
    red: &Redundancy,
) -> Option<Disposition> {
    let mode = if is_app_apk(target) {
        crate::mount::Serve::Inject
    } else {
        crate::mount::serve_mode(target)
    };
    if !is_absorbable(src, target) {
        if !src.starts_with(MODULE_ROOT) {
            return matches!(mode, crate::mount::Serve::Inject | crate::mount::Serve::Bind)
                .then_some(Disposition::Leaking(
                    "source is outside /data/adb, so there is no module content to re-serve",
                ));
        }
        return Some(Disposition::Leaking(
            "target is on /data and is not an app APK, which absorb does not take over",
        ));
    }
    if let Some(d) = declined_reason_with(src, target, skips, skip_src, hookers) {
        return Some(Disposition::Declined(d));
    }
    if red.covers(src, target) {
        return Some(Disposition::Redundant);
    }
    Some(match mode {
        crate::mount::Serve::Inject => Disposition::Absorb,
        crate::mount::Serve::Bind => Disposition::Declined(Declined::MustBind),
        crate::mount::Serve::Refuse(why) => Disposition::Leaking(why),
    })
}

pub fn survey() -> Result<Vec<Surveyed>> {
    survey_of(MOUNTINFO)
}

pub fn survey_of(mountinfo: &str) -> Result<Vec<Surveyed>> {
    let body = std::fs::read_to_string(mountinfo).context("read mountinfo")?;
    let rows = parse_mountinfo(&body);
    let roots = fs_roots(&rows);
    let (skips, skip_src) = skip_list();
    let hookers = hooking_modules(&rows, &roots, &skips);
    let red = Redundancy::new(&Nm::new().list().unwrap_or_default(), &rows);

    let mut out: Vec<Surveyed> = rows
        .iter()
        .filter_map(|r| {
            let src = source_of(r, &roots)?;
            if !src.starts_with(FOREIGN_ROOT) {
                return None;
            }
            if r.target.starts_with(MODULE_ROOT) {
                return None;
            }
            if r.target.starts_with(FOREIGN_ROOT) && !src.starts_with(MODULE_ROOT) {
                return None;
            }
            if r.target.components().count() <= 1 {
                return None;
            }
            let disposition = classify(&src, &r.target, &skips, skip_src, &hookers, &red)?;
            Some(Surveyed { target: r.target.clone(), source: src, disposition })
        })
        .collect();
    out.sort_by_key(|s| std::cmp::Reverse(s.target.components().count()));
    Ok(out)
}

pub struct Candidate {
    pub target: PathBuf,
    pub source: PathBuf,
    pub redundant: bool,
}

pub(crate) fn mounted_targets() -> Option<std::collections::HashSet<PathBuf>> {
    let body = std::fs::read_to_string(MOUNTINFO).ok()?;
    Some(parse_mountinfo(&body).into_iter().map(|r| r.target).collect())
}

pub fn absorbed_pairs() -> Vec<(PathBuf, PathBuf)> {
    read_absorbed_pairs().unwrap_or_default()
}

pub fn read_absorbed_pairs() -> std::io::Result<Vec<(PathBuf, PathBuf)>> {
    match fs::read_to_string(ABSORBED_LIST) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
        Ok(s) => Ok(parse_absorbed_pairs(&s)),
    }
}

fn parse_absorbed_pairs(body: &str) -> Vec<(PathBuf, PathBuf)> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('\t'))
        .map(|(t, src)| (PathBuf::from(t), PathBuf::from(src)))
        .collect()
}

fn label_apk_readable(p: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()) else { return false };
    let ctx = c"u:object_r:apk_data_file:s0";
    let rc = unsafe {
        libc::lsetxattr(
            c.as_ptr(),
            c"security.selinux".as_ptr(),
            ctx.as_ptr().cast(),
            ctx.to_bytes_with_nul().len(),
            0,
        )
    };
    if rc != 0 {
        eprintln!(
            "nomount: could not label {} apk_data_file ({}) - not serving it: an app cannot read adb_data_file, and serving it anyway gives a null Resources and a crash in handleBindApplication",
            p.display(),
            std::io::Error::last_os_error()
        );
        return false;
    }
    true
}

pub fn reapply_absorbed(nm: &Nm) -> u32 {
    reapply_absorbed_pairs(nm, &absorbed_pairs())
}

pub fn reapply_absorbed_pairs(nm: &Nm, pairs: &[(PathBuf, PathBuf)]) -> u32 {
    let Ok(live) = nm.list() else {
        eprintln!(
            "nomount: cannot enumerate live rules - skipping the absorbed-rule re-serve this \
             pass (re-adding blind would d_drop rules that are already live)"
        );
        return 0;
    };
    let mut n = 0;
    for (target, source) in pairs {
        if !is_app_apk(target) || !source.exists() || !target.exists() {
            continue;
        }
        let tgt = target.to_string_lossy();
        if live.lines().any(|l| l.rsplit_once(" -> ").is_some_and(|(t, _)| t.trim() == tgt)) {
            continue;
        }
        if !label_apk_readable(source) {
            continue;
        }
        if nm.add(target, source).is_ok() {
            n += 1;
        }
    }
    n
}

pub fn read_absorbed_targets() -> std::io::Result<HashSet<PathBuf>> {
    Ok(read_absorbed_pairs()?.into_iter().map(|(t, _)| t).collect())
}

pub fn set_absorbed_pairs(pairs: &[(PathBuf, PathBuf)]) {
    if let Some(d) = Path::new(ABSORBED_LIST).parent() {
        let _ = fs::create_dir_all(d);
    }
    let mut body = String::from(
        "# Targets absorb re-serves as injections; reload keeps these.\n\
         # <target>\\t<source> -- the source lets the boot pass re-serve it without\n\
         # waiting for the owning module to mount again.\n",
    );
    for (t, src) in pairs {
        body.push_str(&t.to_string_lossy());
        body.push('\t');
        body.push_str(&src.to_string_lossy());
        body.push('\n');
    }
    if let Err(e) = fs::write(ABSORBED_LIST, &body) {
        eprintln!("nomount: could not record absorbed targets: {e:#}");
        return;
    }
    let _ = fs::set_permissions(ABSORBED_LIST, std::os::unix::fs::PermissionsExt::from_mode(0o600));
}

pub(crate) fn still_mounted(p: &Path) -> bool {
    std::fs::read_to_string(MOUNTINFO)
        .map(|b| parse_mountinfo(&b).iter().any(|r| r.target == p))
        .unwrap_or(true)
}

pub(crate) fn servable(target: &Path, aliases: &[(PathBuf, PathBuf)]) -> PathBuf {
    if matches!(crate::mount::serve_mode(target), crate::mount::Serve::Inject) {
        return target.to_path_buf();
    }
    for (a, b) in aliases {
        if let Ok(tail) = target.strip_prefix(a) {
            let alt = b.join(tail);
            if matches!(crate::mount::serve_mode(&alt), crate::mount::Serve::Inject) {
                return alt;
            }
        }
    }
    target.to_path_buf()
}

pub(crate) fn runtime_droppable(target: &Path, aliases: &[(PathBuf, PathBuf)]) -> bool {
    fn touches_my_partition(p: &Path) -> bool {
        p.components()
            .any(|c| c.as_os_str().to_str().is_some_and(|s| s.starts_with("my_")))
    }
    !touches_my_partition(target) && !touches_my_partition(&servable(target, aliases))
}

pub(crate) fn umount_detach(p: &Path) -> bool {
    let Ok(c) = CString::new(p.to_string_lossy().as_bytes()) else {
        return false;
    };
    unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) == 0 }
}

fn already_serving(target: &Path, source: &Path) -> bool {
    let (Ok(t), Ok(s)) = (fs::metadata(target), fs::metadata(source)) else { return false };
    t.len() == s.len()
}

fn add_repointing(nm: &Nm, target: &Path, source: &Path, live: &LiveMap) -> bool {
    match live.get(target) {
        Some(cur) if cur.as_path() == source && already_serving(target, source) => true,
        Some(prev) => {
            let prev = prev.clone();
            let _ = nm.del(target);
            if nm.add(target, source).is_ok() {
                return true;
            }
            #[allow(clippy::needless_return)]
            if nm.add(target, &prev).is_ok() {
                eprintln!(
                    "nomount: absorb: could not re-point {} at {} -- restored the previous rule",
                    target.display(),
                    source.display()
                );
            } else {
                eprintln!(
                    "nomount: absorb: {} now has NO rule - re-point and restore both failed",
                    target.display()
                );
            }
            false
        }
        None => nm.add(target, source).is_ok(),
    }
}

type LiveMap = std::collections::HashMap<PathBuf, PathBuf>;

fn live_injects(nm: &Nm) -> LiveMap {
    nm.list()
        .map(|l| {
            crate::nm::parse_list(&l)
                .into_iter()
                .filter(|r| r.uid == 0)
                .filter_map(|r| r.source.map(|src| (r.target, src)))
                .collect()
        })
        .unwrap_or_default()
}

fn inject(nm: &Nm, source: &Path, target: &Path, out: &mut Vec<(PathBuf, PathBuf)>,
          live: &LiveMap) -> u32 {
    let mut failed = 0u32;
    if source.is_dir() {
        let entries = match std::fs::read_dir(source) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("nomount: cannot read {} to absorb it: {e}", source.display());
                return 1;
            }
        };
        for e in entries.flatten() {
            let Ok(ft) = e.file_type() else {
                failed += 1;
                continue;
            };
            let child_src = e.path();
            let child_tgt = target.join(e.file_name());
            if ft.is_dir() {
                failed += inject(nm, &child_src, &child_tgt, out, live);
            } else if add_repointing(nm, &child_tgt, &child_src, live) {
                out.push((child_tgt, child_src));
            } else {
                failed += 1;
            }
        }
    } else if add_repointing(nm, target, source, live) {
        out.push((target.to_path_buf(), source.to_path_buf()));
    } else {
        failed += 1;
    }
    failed
}

pub(crate) fn pkg_of_apk_target(target: &Path) -> Option<String> {
    if !is_app_apk(target) {
        return None;
    }
    let dir = target.parent()?.file_name()?.to_str()?;
    let (pkg, _gen) = dir.rsplit_once('-')?;
    (!pkg.is_empty() && pkg.contains('.')).then(|| pkg.to_string())
}

fn current_apk_of(pkg: &str) -> Result<Option<PathBuf>> {
    let out = std::process::Command::new("/system/bin/pm")
        .args(["path", pkg])
        .output()
        .context("exec /system/bin/pm path")?;
    if !out.status.success() {
        anyhow::bail!("pm path {pkg} exited {:?}", out.status.code());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("package:"))
        .map(|p| PathBuf::from(p.trim())))
}

pub fn refresh_app_apks(nm: &Nm) -> (u32, u32) {
    let (mut repointed, mut stale) = (0u32, 0u32);
    let Ok(list) = nm.list() else { return (0, 0) };
    let mut pm_failed = false;
    for line in list.lines() {
        let Some((target, source)) = line.split_once(" -> ") else { continue };
        let target = Path::new(target.trim());
        let source = PathBuf::from(source.split(" [").next().unwrap_or(source).trim());
        if !is_app_apk(target) || target.exists() {
            continue;
        }
        let Some(pkg) = pkg_of_apk_target(target) else { continue };
        match current_apk_of(&pkg) {
            Err(_) => {
                if !pm_failed {
                    pm_failed = true;
                    eprintln!(
                        "nomount: pm is not answering; leaving absorbed APK rules untouched \
                         this pass rather than dropping them as uninstalled"
                    );
                }
            }
            Ok(Some(now)) if now != *target && source.exists() => {
                let _ = nm.del(target);
                if nm.add(&now, &source).is_ok() {
                    repointed += 1;
                }
            }
            Ok(_) => {
                let _ = nm.del(target);
                stale += 1;
            }
        }
    }
    (repointed, stale)
}

pub(crate) const ROM_ROOTS: &[&str] =
    &["/system/", "/product/", "/vendor/", "/system_ext/", "/odm/", "/oem/", "/my_"];

pub(crate) fn rom_tmpfs_target(line: &str) -> Option<PathBuf> {
    let (pre, post) = line.split_once(" - ")?;
    if post.split_whitespace().next()? != "tmpfs" {
        return None;
    }
    let target = pre.split_whitespace().nth(4)?;
    ROM_ROOTS.iter().any(|r| target.starts_with(r)).then(|| PathBuf::from(unescape(target)))
}

fn boot_id() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn dir_is_empty(p: &Path) -> Option<bool> {
    fs::read_dir(p).ok().map(|mut e| e.next().is_none())
}

pub(crate) fn absorbed_tmpfs() -> Vec<(PathBuf, String)> {
    fs::read_to_string(ABSORBED_TMPFS_LIST).map(|s| parse_tmpfs_record(&s)).unwrap_or_default()
}

fn parse_tmpfs_record(body: &str) -> Vec<(PathBuf, String)> {
    body.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| match l.split_once('\t') {
            Some((t, boot)) => (PathBuf::from(t.trim()), boot.trim().to_string()),
            None => (PathBuf::from(l), String::new()),
        })
        .collect()
}

pub fn absorbed_tmpfs_targets() -> HashSet<PathBuf> {
    absorbed_tmpfs().into_iter().map(|(t, _)| t).collect()
}

fn tmpfs_entry_lives(seen_now: bool, seen_boot: &str, boot: &str, mounted: bool) -> bool {
    seen_now || mounted || seen_boot.is_empty() || seen_boot == boot
}

fn set_absorbed_tmpfs(entries: &[(PathBuf, String)]) {
    if let Some(d) = Path::new(ABSORBED_TMPFS_LIST).parent() {
        let _ = fs::create_dir_all(d);
    }
    let mut body = String::from(
        "# ROM directories absorb empties in place of a module's tmpfs.\n\
         # <target>\\t<boot id when its tmpfs was last seen> -- absorb re-derives this\n\
         # from the live mount table every boot and drops an entry whose tmpfs is gone,\n\
         # so uninstalling the owning module restores the directory. Not hand-edited:\n\
         # a hide you want to keep belongs in whiteouts.txt.\n",
    );
    for (t, boot) in entries {
        body.push_str(&t.to_string_lossy());
        body.push('\t');
        body.push_str(boot);
        body.push('\n');
    }
    if let Err(e) = fs::write(ABSORBED_TMPFS_LIST, &body) {
        eprintln!("nomount: could not record the ROM tmpfs takeovers: {e:#}");
    }
}

pub fn reapply_tmpfs_whiteouts(nm: &Nm) -> u32 {
    let mut n = 0u32;
    for (t, _) in absorbed_tmpfs() {
        if crate::whiteout::validate(&t.to_string_lossy()).is_err() {
            eprintln!("nomount: skipping invalid ROM-tmpfs entry {}", t.display());
            continue;
        }
        if nm.whiteout(&t).is_ok() {
            n += 1;
        }
    }
    n
}

#[derive(Default)]
struct TmpfsPass {
    done: u32,
    failed: u32,
    leaked: u32,
    declined: u32,
}

fn absorb_rom_tmpfs(dry_run: bool) -> TmpfsPass {
    let mut st = TmpfsPass::default();
    let Ok(body) = fs::read_to_string(MOUNTINFO) else { return st };
    let (skips, _) = skip_list();
    let nm = Nm::new();
    let boot = boot_id().unwrap_or_default();
    let mut record = absorbed_tmpfs();
    let durable = crate::whiteout::read().unwrap_or_default();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    for target in body.lines().filter_map(rom_tmpfs_target) {
        if is_skipped(Path::new("/"), &target, &skips) {
            println!("skipping the tmpfs over {} (opt-out list)", target.display());
            st.declined += 1;
            continue;
        }
        let t_str = target.to_string_lossy().into_owned();
        let was_durable = durable.contains(&t_str);
        let ours = was_durable || record.iter().any(|(t, _)| *t == target);
        match dir_is_empty(&target) {
            Some(true) => {}
            None if ours => {}
            other => {
                eprintln!(
                    "nomount: LEAK the tmpfs over {} stays mounted: it {} so it is not the \
                     \"make this directory look empty\" trick a whiteout can replace -- \
                     converting it would hide content the owning module is serving",
                    target.display(),
                    if other.is_some() { "has files in it" } else { "cannot be read" }
                );
                st.leaked += 1;
                continue;
            }
        }
        if dry_run {
            println!("would empty {} mountlessly (tmpfs -> whiteout)", target.display());
            st.done += 1;
            continue;
        }
        seen.insert(target.clone());
        if ours {
            let _ = nm.del(&target);
        }
        if !umount_detach(&target) && still_mounted(&target) {
            eprintln!("nomount: cannot unmount the tmpfs over {}", target.display());
            st.failed += 1;
            continue;
        }
        if was_durable {
            println!(
                "moving {t_str} out of whiteouts.txt into absorb's own list: it came from a \
                 tmpfs, so it should stop hiding when that tmpfs does"
            );
            let _ = crate::whiteout::remove(&t_str);
        }
        if let Err(e) = crate::whiteout::validate(&t_str) {
            eprintln!("nomount: {t_str} unmounted but will not be hidden: {e:#}");
            st.failed += 1;
            continue;
        }
        match nm.whiteout(&target) {
            Ok(()) => {
                match record.iter_mut().find(|(t, _)| *t == target) {
                    Some(e) => e.1 = boot.clone(),
                    None => record.push((target.clone(), boot.clone())),
                }
                st.done += 1;
            }
            Err(e) => {
                eprintln!("nomount: {} unmounted but the whiteout failed: {e:#}", target.display());
                st.failed += 1;
            }
        }
    }
    if dry_run {
        return st;
    }
    let mut expired = 0u32;
    record.retain(|(t, seen_boot)| {
        if tmpfs_entry_lives(seen.contains(t), seen_boot, &boot, still_mounted(t)) {
            return true;
        }
        let _ = nm.del(t);
        println!(
            "restored {}: nothing mounts a tmpfs there any more, so it is no longer hidden",
            t.display()
        );
        expired += 1;
        false
    });
    if expired > 0 || !seen.is_empty() || !record.is_empty() {
        set_absorbed_tmpfs(&record);
    }
    st
}

pub fn run_absorb(dry_run: bool, include_dirs: bool, early: bool) -> Result<()> {
    let _pass = if dry_run { None } else { crate::mount::pass_lock() };
    let nm = Nm::new();
    nm.version()
        .context("hookless NoMount engine not responding")?;

    if !dry_run {
        let reserved = reapply_absorbed(&nm);
        if reserved > 0 {
            println!("re-served {reserved} recorded APK rule(s)");
        }
        let (repointed, stale) = refresh_app_apks(&nm);
        if repointed > 0 || stale > 0 {
            println!("refreshed {repointed} app APK rule(s), dropped {stale} for an uninstalled app");
        }
    }
    let tmpfs = absorb_rom_tmpfs(dry_run);
    let surveyed = survey()?;
    let aliases = std::fs::read_to_string(MOUNTINFO)
        .map(|b| mount_aliases(&parse_mountinfo(&b)))
        .unwrap_or_default();
    let (mut leaking, mut declined) = (tmpfs.leaked + tmpfs.failed, tmpfs.declined);
    for s in &surveyed {
        if matches!(s.disposition, Disposition::Declined(_)) {
            declined += 1;
        }
        match &s.disposition {
            Disposition::Absorb => {}
            Disposition::Redundant if early || runtime_droppable(&s.target, &aliases) => println!(
                "redundant {} <- {} (already served by an injection; unmounting only)",
                s.target.display(),
                s.source.display()
            ),
            Disposition::Redundant => {
                leaking += 1;
                eprintln!(
                    "nomount: LEAK {} <- {} is redundant (its content is already injected) but stays mounted: re-asserting a my_* rule at runtime has rebooted a device, and unmounting without that re-assert reverts the path to the stock file. Delete the bind from the owning module's post-fs-data.sh instead - the next boot then serves it by injection with nothing to absorb",
                    s.target.display(),
                    s.source.display()
                );
            }
            Disposition::Declined(Declined::Framework(id)) => println!(
                "skipping {} ({id} is a hook framework)",
                s.target.display()
            ),
            Disposition::Declined(Declined::Listed(from)) => {
                println!("skipping {} (listed in {from})", s.target.display())
            }
            Disposition::Declined(Declined::HooksElsewhere(id)) => println!(
                "skipping {} ({id} hooks a known path elsewhere, so all of its mounts are left alone)",
                s.target.display()
            ),
            Disposition::Declined(Declined::MustBind) => println!(
                "skipping {} (my_* is served by a real bind; injecting one bootloops zygote)",
                s.target.display()
            ),
            Disposition::Leaking(why) => {
                leaking += 1;
                eprintln!(
                    "nomount: LEAK {} <- {} stays mounted and is visible to any app: {why}",
                    s.target.display(),
                    s.source.display()
                );
            }
        }
    }

    for e in survey_elsewhere() {
        leaking += 1;
        eprintln!(
            "nomount: LEAK {} <- {} is mounted in {} but not in our namespace: absorb \
             cannot see or unmount it (replicated with nsenter)",
            e.mount.target.display(),
            e.mount.source.display(),
            e.seen_in
        );
    }

    let mut deferred = 0usize;
    let cands: Vec<Candidate> = surveyed
        .into_iter()
        .filter(|s| match s.disposition {
            Disposition::Absorb => {
                if early || runtime_droppable(&s.target, &aliases) {
                    true
                } else {
                    deferred += 1;
                    false
                }
            }
            Disposition::Redundant => {
                if early || runtime_droppable(&s.target, &aliases) {
                    true
                } else {
                    deferred += 1;
                    false
                }
            }
            _ => false,
        })
        .map(|s| Candidate {
            redundant: matches!(s.disposition, Disposition::Redundant),
            target: s.target,
            source: s.source,
        })
        .collect();
    if deferred > 0 {
        println!(
            "nomount absorb: {deferred} my_* mount(s) deferred to the pre-zygote pass \
             (absorbing them on a live system has rebooted a device); they are taken at the \
             next boot if the my_hookless trial is enabled"
        );
    }
    if cands.is_empty() {
        if tmpfs.done > 0 || tmpfs.failed > 0 {
            println!(
                "nomount absorb: {} ROM tmpfs emptied mountlessly ({} failed)",
                tmpfs.done, tmpfs.failed
            );
        }
        match (leaking, declined) {
            (0, 0) => println!("nomount absorb: nothing mounted over the ROM (posture clean)"),
            (0, d) => println!(
                "nomount absorb: nothing to absorb; {d} mount(s) left by design and still visible"
            ),
            (n, d) => println!(
                "nomount absorb: nothing to absorb, but {n} foreign mount(s) remain, \
                 plus {d} more left by design - the posture is NOT clean"
            ),
        }
        return Ok(());
    }

    let (mut done, mut failed, mut skipped_dirs) = (0u32, 0u32, 0u32);
    let mut dropped = 0u32;
    let live_map = live_injects(&nm);
    let mut reasserted: HashSet<PathBuf> = HashSet::new();
    let mut fresh: Vec<(PathBuf, PathBuf)> = Vec::new();
    for c in &cands {
        let is_dir_bind = c.source.is_dir();
        if c.redundant {
            if dry_run {
                println!(
                    "would drop redundant mount {} <- {}",
                    c.target.display(),
                    c.source.display()
                );
                dropped += 1;
                continue;
            }
            if !umount_detach(&c.target) && still_mounted(&c.target) {
                eprintln!(
                    "nomount: cannot unmount redundant {} - leaving it alone",
                    c.target.display()
                );
                failed += 1;
                continue;
            }
            dropped += 1;
            let at = servable(&c.target, &aliases);
            if !reasserted.insert(at.clone()) {
                continue;
            }
            let mut refreshed = Vec::new();
            let fails = inject(&nm, &c.source, &at, &mut refreshed, &live_map);
            if fails > 0 {
                eprintln!(
                    "nomount: {} unmounted but re-asserting {fails} of its rule(s) failed - that content may have reverted to the stock file",
                    c.target.display()
                );
                failed += 1;
            }
            continue;
        }
        if dry_run {
            if is_dir_bind && !include_dirs {
                println!(
                    "would skip directory bind {} <- {} (needs --include-dirs)",
                    c.target.display(), c.source.display()
                );
                skipped_dirs += 1;
            } else {
                println!("would absorb {} <- {}", c.target.display(), c.source.display());
            }
            continue;
        }
        if is_dir_bind && !include_dirs {
            println!(
                "skipping directory bind {} <- {} (use --include-dirs; injection would \
                 snapshot the listing and miss files added later)",
                c.target.display(), c.source.display()
            );
            skipped_dirs += 1;
            continue;
        }
        if !umount_detach(&c.target) && still_mounted(&c.target) {
            eprintln!(
                "nomount: cannot unmount {} - leaving it alone (injecting anyway would \
                 strand it in mountinfo)",
                c.target.display()
            );
            failed += 1;
            continue;
        }
        let before = fresh.len();
        let fails = inject(&nm, &c.source, &c.target, &mut fresh, &live_map);
        let served = fresh.len() - before;
        if fails == 0 {
            done += 1;
        } else {
            eprintln!(
                "nomount: absorb of {} served {served} rule(s), {fails} failed",
                c.target.display()
            );
            failed += 1;
        }
    }
    let rules = fresh.len() as u32;
    let fresh_pairs: Vec<(PathBuf, PathBuf)> = fresh;
    match read_absorbed_pairs() {
        Ok(mut all) => {
            for p in fresh_pairs {
                if !all.iter().any(|(t, _)| *t == p.0) {
                    all.push(p);
                }
            }
            all.sort();
            set_absorbed_pairs(&all);
        }
        Err(e) => eprintln!(
            "nomount: could not read {ABSORBED_LIST} ({e}) -- NOT rewriting it, because an \
             empty read here would delete every recorded rule. {rules} rule(s) from this pass \
             are unrecorded until the next successful absorb"
        ),
    }

    let leaks = if leaking > 0 {
        format!(", {leaking} not absorbed and still mounted")
    } else {
        String::new()
    };
    let drops = if dropped > 0 {
        format!(", {dropped} redundant mount(s) dropped")
    } else {
        String::new()
    };
    if dry_run {
        println!(
            "nomount absorb: {} mount(s) would be absorbed, {} ROM tmpfs, {skipped_dirs} directory bind(s) skipped{drops}{leaks} (dry run)",
            cands.len() as u32 - skipped_dirs - dropped,
            tmpfs.done
        );
    } else {
        let dirs = if skipped_dirs > 0 {
            format!(", {skipped_dirs} directory bind(s) skipped")
        } else {
            String::new()
        };
        println!(
            "nomount absorb: {done} mount(s) absorbed as {rules} rule(s), {} ROM tmpfs emptied mountlessly, {} failed{dirs}{drops}{leaks}",
            tmpfs.done,
            failed + tmpfs.failed
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
205 1 254:78 / /data rw,nosuid,nodev,noatime shared:2 - f2fs /dev/block/dm-78 rw
10222 205 254:78 /local/tmp/bt/src/f /data/local/tmp/bt/dst/f rw,noatime shared:60 - f2fs /dev/block/dm-78 rw
900 205 254:78 /adb/modules/foo/system/bin/x /system/bin/x rw,noatime shared:9 - f2fs /dev/block/dm-78 rw
35 1 0:35 / /product ro,noatime - erofs /dev/block/dm-25 ro";

    #[test]
    fn a_tmpfs_over_the_rom_is_recognised() {
        let line = "359 149 0:129 / /product/app/YouTube rw,relatime shared:77 - tmpfs none rw,seclabel";
        assert_eq!(rom_tmpfs_target(line).as_deref(), Some(Path::new("/product/app/YouTube")));
    }

    #[test]
    fn the_tmpfs_record_round_trips_stamped_and_unstamped_lines() {
        let v = parse_tmpfs_record(
            "# header\n\
             /product/app/YouTube\tb9f0-1\n\
             \n\
             /system/app/Old\n",
        );
        assert_eq!(
            v,
            vec![
                (PathBuf::from("/product/app/YouTube"), "b9f0-1".to_string()),
                (PathBuf::from("/system/app/Old"), String::new()),
            ]
        );
    }

    #[test]
    fn a_takeover_expires_only_after_a_boot_without_its_tmpfs() {
        assert!(tmpfs_entry_lives(true, "old-boot", "this-boot", false));
        assert!(tmpfs_entry_lives(false, "this-boot", "this-boot", false));
        assert!(tmpfs_entry_lives(false, "old-boot", "this-boot", true));
        assert!(tmpfs_entry_lives(false, "", "this-boot", false));
        assert!(!tmpfs_entry_lives(false, "old-boot", "this-boot", false));
    }

    #[test]
    fn a_tmpfs_over_a_partition_root_is_recognised_but_never_hidden() {
        let line = "360 149 0:130 / /my_product rw,relatime shared:78 - tmpfs none rw,seclabel";
        assert_eq!(rom_tmpfs_target(line).as_deref(), Some(Path::new("/my_product")));
        assert!(crate::whiteout::validate("/my_product").is_err());
        assert!(crate::whiteout::validate("/product/app/YouTube").is_ok());
    }

    #[test]
    fn stock_mounts_are_left_alone() {
        for line in [
            "20 1 0:20 / /dev rw - tmpfs tmpfs rw",
            "25 1 0:21 / /apex rw - tmpfs tmpfs rw",
            "30 1 0:22 / /mnt rw - tmpfs tmpfs rw",
            "40 1 8:6 / /vendor/firmware_mnt ro - vfat /dev/block/sde6 ro",
            "41 1 0:99 / /product/lib ro - overlay overlay-overlay ro",
        ] {
            assert!(rom_tmpfs_target(line).is_none(), "{line}");
        }
    }

    #[test]
    fn a_package_name_is_recoverable_from_its_apk_path() {
        assert_eq!(
            pkg_of_apk_target(Path::new(
                "/data/app/~~j9-uUJRSd2LZbuW==/com.google.android.youtube-ZvGL==/base.apk"
            ))
            .as_deref(),
            Some("com.google.android.youtube")
        );
        assert_eq!(
            pkg_of_apk_target(Path::new("/data/app/com.foo.bar-1/base.apk")).as_deref(),
            Some("com.foo.bar")
        );
    }

    #[test]
    fn a_package_name_is_not_guessed_from_anything_else() {
        for p in [
            "/data/app/~~a==/nodots-b==/base.apk",
            "/data/app/~~a==/com.foo/base.apk",
            "/product/overlay/x.apk",
            "/data/app/~~a==/com.foo-b==/lib/arm64/libx.so",
        ] {
            assert!(pkg_of_apk_target(Path::new(p)).is_none(), "{p}");
        }
    }

    #[test]
    fn an_app_apk_bind_is_absorbable() {
        let src = Path::new("/data/adb/rvhc/youtube-morphe-jhc-arm64.apk");
        let target = Path::new("/data/app/~~j9-uUJRSd2LZbuW==/com.google.android.youtube-ZvGL==/base.apk");
        assert!(is_app_apk(target));
        assert!(is_absorbable(src, target));
    }

    #[test]
    fn split_apks_and_the_legacy_layout_count_too() {
        assert!(is_app_apk(Path::new("/data/app/~~a==/com.foo-b==/split_config.arm64_v8a.apk")));
        assert!(is_app_apk(Path::new("/data/app/com.foo-1/base.apk")));
    }

    #[test]
    fn other_data_targets_stay_refused() {
        let src = Path::new("/data/adb/modules/x/foo");
        for t in [
            "/data/app/~~a==/com.foo-b==/lib/arm64/libx.so",
            "/data/app/~~a==/com.foo-b==/oat/arm64/base.odex",
            "/data/data/com.foo/files/x.apk",
            "/data/local/tmp/base.apk",
            "/data/app/base.apk",
        ] {
            assert!(!is_app_apk(Path::new(t)), "{t}");
            assert!(!is_absorbable(src, Path::new(t)), "{t}");
        }
    }

    #[test]
    fn resolves_a_bind_source_via_its_filesystem_root() {
        let rows = parse_mountinfo(SAMPLE);
        let roots = fs_roots(&rows);
        let m = rows.iter().find(|r| r.target == Path::new("/system/bin/x")).unwrap();
        assert_eq!(
            source_of(m, &roots).unwrap(),
            PathBuf::from("/data/adb/modules/foo/system/bin/x")
        );
    }

    #[test]
    fn only_module_backed_rom_targets_are_absorbable() {
        let rows = parse_mountinfo(SAMPLE);
        let roots = fs_roots(&rows);
        for r in &rows {
            let Some(src) = source_of(r, &roots) else { continue };
            let want = r.target == Path::new("/system/bin/x");
            assert_eq!(is_absorbable(&src, &r.target), want, "{:?}", r.target);
        }
    }

    #[test]
    fn whole_filesystem_mounts_are_never_absorbed() {
        let rows = parse_mountinfo(SAMPLE);
        let roots = fs_roots(&rows);
        let prod = rows.iter().find(|r| r.target == Path::new("/product")).unwrap();
        assert!(source_of(prod, &roots).is_none());
    }

    #[test]
    fn skip_list_matches_module_id_or_target_prefix() {
        let src = Path::new("/data/adb/modules/zygisk_lsposed/bin/dex2oat");
        let tgt = Path::new("/apex/com.android.art/bin/dex2oat64");
        assert!(is_skipped(src, tgt, &["zygisk_lsposed".into()]), "module id");
        assert!(is_skipped(src, tgt, &["/apex/".into()]), "target prefix");
        assert!(!is_skipped(src, tgt, &["other_module".into()]));
        assert!(!is_skipped(src, tgt, &["/system/".into()]));
        assert!(!is_skipped(src, tgt, &[]));
    }

    #[test]
    fn path_key_covers_any_fork_id() {
        let tgt = Path::new("/apex/com.android.art/bin/dex2oat64");
        let key: Vec<String> = vec!["/apex/com.android.art/bin/dex2oat".into()];
        for id in ["zygisk_lsposed", "zygisk_lsposed_next", "lsposed", "some_new_fork"] {
            let src = PathBuf::from(format!("/data/adb/modules/{id}/bin/dex2oat"));
            assert!(is_skipped(&src, tgt, &key), "path key must cover fork id {id}");
        }
        let idkey: Vec<String> = vec!["zygisk_lsposed".into()];
        let other = PathBuf::from("/data/adb/modules/zygisk_lsposed_next/bin/dex2oat");
        assert!(!is_skipped(&other, tgt, &idkey), "id key cannot cover a renamed fork");
    }

    #[test]
    fn builtin_covers_every_dex2oat_path_vector_hooks() {
        let builtins: Vec<String> = BUILTIN_SKIPS.iter().map(|s| s.to_string()).collect();
        let src = PathBuf::from("/data/adb/modules/zygisk_vector/bin/dex2oat64");
        for p in [
            "/apex/com.android.runtime/bin/dex2oat",
            "/apex/com.android.runtime/bin/dex2oatd",
            "/apex/com.android.runtime/bin/dex2oat64",
            "/apex/com.android.runtime/bin/dex2oatd64",
            "/apex/com.android.art/bin/dex2oat32",
            "/apex/com.android.art/bin/dex2oatd32",
            "/apex/com.android.art/bin/dex2oat64",
            "/apex/com.android.art/bin/dex2oatd64",
        ] {
            assert!(is_skipped(&src, Path::new(p), &builtins), "must cover {p}");
        }
    }

    #[test]
    fn builtin_fallback_still_protects_hook_paths() {
        let builtins: Vec<String> = BUILTIN_SKIPS.iter().map(|s| s.to_string()).collect();
        let src = PathBuf::from("/data/adb/modules/anything/bin/dex2oat");
        assert!(is_skipped(&src, Path::new("/apex/com.android.art/bin/dex2oat64"), &builtins));
        assert!(is_skipped(&src, Path::new("/system/bin/app_process64"), &builtins));
        assert!(!is_skipped(&src, Path::new("/product/etc/foo.xml"), &builtins));
    }

    #[test]
    fn a_target_mount_rs_would_not_inject_is_never_absorbed() {
        let none: Vec<String> = vec![];
        let modsrc = PathBuf::from("/data/adb/modules/SystemlessDebloater/dummy.apk");

        assert!(matches!(
            classify(&modsrc, Path::new("/my_product/app/Foo/Foo.apk"), &none, "test", &HashSet::new(), &Redundancy::default()).unwrap(),
            Disposition::Declined(Declined::MustBind)
        ));
        assert!(matches!(
            classify(&modsrc, Path::new("/apex/com.android.conscrypt/cacerts"), &none, "test", &HashSet::new(), &Redundancy::default()).unwrap(),
            Disposition::Leaking(_)
        ));
        assert!(matches!(
            classify(&modsrc, Path::new("/product"), &none, "test", &HashSet::new(), &Redundancy::default()).unwrap(),
            Disposition::Leaking(_)
        ));
        assert!(matches!(
            classify(&modsrc, Path::new("/system/app/Foo/Foo.apk"), &none, "test", &HashSet::new(), &Redundancy::default()).unwrap(),
            Disposition::Absorb
        ));
    }

    #[test]
    fn module_bind_over_an_installed_apk_is_absorbed() {
        let none: Vec<String> = Vec::new();
        let src = PathBuf::from("/data/adb/rvhc/youtube-morphe-jhc-arm64.apk");
        let tgt = PathBuf::from(
            "/data/app/~~j9-uUJRSd2LZbuWhGChmMg==/com.google.android.youtube-ZvGLpaBP8lRYo5dmzQ92LA==/base.apk",
        );
        let d = classify(&src, &tgt, &none, "test", &HashSet::new(), &Redundancy::default());
        assert!(
            matches!(d, Some(Disposition::Absorb)),
            "a module bind over an installed APK must be absorbed"
        );

        let scratch = PathBuf::from("/data/adb/modules/foo/tmp");
        assert!(
            classify(&src, &scratch, &none, "test", &HashSet::new(), &Redundancy::default())
                .is_none()
                || !matches!(
                    classify(&src, &scratch, &none, "test", &HashSet::new(), &Redundancy::default()),
                    Some(Disposition::Absorb)
                ),
            "module scratch space must never be absorbed"
        );
        let stock = PathBuf::from("/data/local/tmp/x");
        assert!(
            !matches!(
                classify(&stock, &tgt, &none, "test", &HashSet::new(), &Redundancy::default()),
                Some(Disposition::Absorb)
            ),
            "a non-module /data source must never be absorbed"
        );
    }

    #[test]
    fn a_bind_sourced_outside_data_adb_is_reported_not_ignored() {
        let d = classify(
            Path::new("/data/local/tmp/custom-ca-copy"),
            Path::new("/system/etc/security/cacerts"),
            &[],
            "test",
            &HashSet::new(),
            &Redundancy::default(),
        );
        assert!(matches!(d, Some(Disposition::Leaking(_))), "must be reported as a leak");

        for (s, t) in [
            ("/data/user", "/data_mirror/data_ce/null"),
            ("/data/media", "/mnt/pass_through/0/emulated"),
            ("/data/misc/profiles/cur", "/data_mirror/cur_profiles"),
        ] {
            assert!(
                classify(Path::new(s), Path::new(t), &[], "test", &HashSet::new(), &Redundancy::default()).is_none(),
                "stock plumbing {t} must not be reported"
            );
        }
    }

    #[test]
    fn a_declined_framework_still_beats_the_target_rule() {
        let src = PathBuf::from("/data/adb/modules/anything/bin/dex2oat");
        let builtins: Vec<String> = BUILTIN_SKIPS.iter().map(|s| s.to_string()).collect();
        assert!(matches!(
            classify(&src, Path::new("/system/bin/app_process64"), &builtins, "built-in", &HashSet::new(), &Redundancy::default()).unwrap(),
            Disposition::Declined(Declined::Listed(_))
        ));
    }

    #[test]
    fn a_module_that_hooks_anywhere_has_all_its_mounts_declined() {
        const ROWS: &str = "\
205 1 254:78 / /data rw - f2fs /dev/block/dm-78 rw
900 205 254:78 /adb/modules/obfuscated_fw/bin/x /apex/com.android.art/bin/dex2oat64 rw - f2fs /dev/block/dm-78 rw
901 205 254:78 /adb/modules/obfuscated_fw/system/etc/f /system/etc/f rw - f2fs /dev/block/dm-78 rw
902 205 254:78 /adb/modules/plain_mod/system/etc/g /system/etc/g rw - f2fs /dev/block/dm-78 rw";
        let rows = parse_mountinfo(ROWS);
        let roots = fs_roots(&rows);
        let builtins: Vec<String> = BUILTIN_SKIPS.iter().map(|s| s.to_string()).collect();
        let hookers = hooking_modules(&rows, &roots, &builtins);
        assert!(hookers.contains("obfuscated_fw"), "must be identified by the path it hooks");
        assert!(!hookers.contains("plain_mod"), "an ordinary module must not be swept in");

        let d = classify(
            Path::new("/data/adb/modules/obfuscated_fw/system/etc/f"),
            Path::new("/system/etc/f"),
            &builtins,
            "test",
            &hookers,
            &Redundancy::default(),
        );
        assert!(matches!(d, Some(Disposition::Declined(Declined::HooksElsewhere(_)))));

        let d = classify(
            Path::new("/data/adb/modules/plain_mod/system/etc/g"),
            Path::new("/system/etc/g"),
            &builtins,
            "test",
            &hookers,
            &Redundancy::default(),
        );
        assert!(matches!(d, Some(Disposition::Absorb)));
    }

    #[test]
    fn mount_aliases_pair_mountpoints_sharing_dev_and_root() {
        let rows = parse_mountinfo(&[
            "1 0 254:34 / /mnt/vendor/my_product ro,noatime - f2fs /dev/block/dm-34 ro",
            "2 0 254:34 / /my_product ro,noatime - f2fs /dev/block/dm-34 ro",
            "3 0 254:78 / /data rw,noatime - f2fs /dev/block/dm-78 rw",
        ]
        .join("
"));
        let a = mount_aliases(&rows);
        assert!(a.contains(&(
            PathBuf::from("/mnt/vendor/my_product"),
            PathBuf::from("/my_product")
        )));
        assert!(a.contains(&(
            PathBuf::from("/my_product"),
            PathBuf::from("/mnt/vendor/my_product")
        )));
        assert!(!a.iter().any(|(x, _)| x == Path::new("/data")));
    }

    #[test]
    fn live_injections_ignores_per_uid_and_non_inject_rules() {
        let live = live_injections(
            "/system/etc/a -> /data/adb/modules/m/system/etc/a
             /system/etc/b -> /data/adb/modules/m/system/etc/b [UID: 10123]
             /system/etc/c (whiteout)
             /system/etc (virtual dir)",
        );
        assert_eq!(live.len(), 1);
        assert!(live.contains_key(Path::new("/system/etc/a")));
    }

    #[test]
    fn a_bind_over_already_injected_content_is_redundant_through_either_path() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("bootanimation");
        std::fs::create_dir_all(&src).unwrap();
        for f in ["bootanimation.zip", "rbootanimation.zip"] {
            std::fs::write(src.join(f), b"x").unwrap();
        }
        let list = format!(
            "/my_product/media/bootanimation/bootanimation.zip -> {0}/bootanimation.zip
             /my_product/media/bootanimation/rbootanimation.zip -> {0}/rbootanimation.zip",
            src.display()
        );
        let rows = parse_mountinfo(&[
            "1 0 254:34 / /mnt/vendor/my_product ro,noatime - f2fs /dev/block/dm-34 ro",
            "2 0 254:34 / /my_product ro,noatime - f2fs /dev/block/dm-34 ro",
        ]
        .join("
"));
        let red = Redundancy::new(&list, &rows);

        assert!(red.covers(&src, Path::new("/my_product/media/bootanimation")));
        assert!(red.covers(&src, Path::new("/mnt/vendor/my_product/media/bootanimation")));

        std::fs::write(src.join("extra.zip"), b"x").unwrap();
        assert!(!red.covers(&src, Path::new("/my_product/media/bootanimation")));
    }

    #[test]
    fn a_rule_from_another_source_does_not_make_a_bind_redundant() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("f");
        std::fs::write(&src, b"x").unwrap();
        let red = Redundancy::new("/system/etc/f -> /data/adb/modules/other/system/etc/f", &[]);
        assert!(!red.covers(&src, Path::new("/system/etc/f")));
        let red = Redundancy::new(&format!("/system/etc/f -> {}", src.display()), &[]);
        assert!(red.covers(&src, Path::new("/system/etc/f")));
    }

    #[test]
    fn nothing_to_prove_is_not_redundant() {
        let d = tempfile::tempdir().unwrap();
        let empty = d.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let red = Redundancy::new("/system/etc/x -> /whatever", &[]);
        assert!(!red.covers(&empty, Path::new("/system/etc/x")));
        assert!(!red.covers(&d.path().join("missing"), Path::new("/system/etc/x")));
    }

    #[test]
    fn serving_is_judged_on_size_not_mtime() {
        let d = tempfile::tempdir().unwrap();
        let served = d.path().join("served");
        let source = d.path().join("source");
        std::fs::write(&served, b"1234").unwrap();
        std::fs::write(&source, b"1234").unwrap();
        let c = std::ffi::CString::new(source.to_str().unwrap()).unwrap();
        let times = libc::utimbuf { actime: 1_000_000, modtime: 1_000_000 };
        assert_eq!(unsafe { libc::utime(c.as_ptr(), &times) }, 0);
        assert!(already_serving(&served, &source));
        std::fs::write(&served, b"12345").unwrap();
        assert!(!already_serving(&served, &source));
        assert!(!already_serving(&d.path().join("gone"), &source));
    }

    #[test]
    fn my_partitions_are_never_dropped_at_runtime() {
        let aliases = vec![(
            PathBuf::from("/mnt/vendor/my_product"),
            PathBuf::from("/my_product"),
        )];
        assert!(!runtime_droppable(Path::new("/my_product/media/bootanimation"), &aliases));
        assert!(!runtime_droppable(
            Path::new("/mnt/vendor/my_product/media/bootanimation"),
            &aliases
        ));
        assert!(runtime_droppable(Path::new("/system/etc/f"), &aliases));
        assert!(runtime_droppable(Path::new("/product/media/x.zip"), &[]));
    }

    #[test]
    fn the_servable_twin_is_where_rules_land() {
        let aliases = vec![
            (PathBuf::from("/mnt/vendor/product"), PathBuf::from("/product")),
            (PathBuf::from("/product"), PathBuf::from("/mnt/vendor/product")),
        ];
        assert_eq!(
            servable(Path::new("/mnt/vendor/product/media/b"), &aliases),
            PathBuf::from("/product/media/b")
        );
        assert_eq!(
            servable(Path::new("/system/etc/f"), &aliases),
            PathBuf::from("/system/etc/f")
        );
        assert_eq!(
            servable(Path::new("/mnt/vendor/other/f"), &aliases),
            PathBuf::from("/mnt/vendor/other/f")
        );
    }

    #[test]
    fn user_skip_entries_add_to_the_builtins() {
        let (list, _) = skip_list();
        for b in BUILTIN_SKIPS {
            assert!(list.iter().any(|e| e == b), "built-in {b} must always be present");
        }
    }

    #[test]
    fn unescapes_octal_in_paths() {
        let rows = parse_mountinfo("1 1 0:1 /a\\040b /c\\040d rw - t s rw");
        assert_eq!(rows[0].root, "/a b");
        assert_eq!(rows[0].target, PathBuf::from("/c d"));
    }

    #[test]
    fn unescape_preserves_non_ascii() {
        let rows = parse_mountinfo("1 1 0:1 /caf\u{e9}\\040mod /data/caf\u{e9}\\040mod rw - t s rw");
        assert_eq!(rows[0].root, "/café mod");
        assert_eq!(rows[0].target, PathBuf::from("/data/café mod"));

        let rows = parse_mountinfo("1 1 0:1 /a\u{1F600}b\\040c /x\u{1F600}y\\040z rw - t s rw");
        assert_eq!(rows[0].root, "/a\u{1F600}b c");
        assert_eq!(rows[0].target, PathBuf::from("/x\u{1F600}y z"));

        let rows = parse_mountinfo("1 1 0:1 /a\\011b /c\\012d rw - t s rw");
        assert_eq!(rows[0].root, "/a\tb");
        assert_eq!(rows[0].target, PathBuf::from("/c\nd"));
    }
}
