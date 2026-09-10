//! Convert other people's bind mounts into hookless injections

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::nm::Nm;

const MOUNTINFO: &str = "/proc/self/mountinfo";
const MODULE_ROOT: &str = "/data/adb";
const FOREIGN_ROOT: &str = "/data";
/// Opt-out list: module ids or target path prefixes to leave mounted
pub const SKIP_FILE: &str = "/data/adb/nomount/absorb-skip.txt";
const SKIP_FILE_LEGACY: &str = "/data/adb/nomount/absorb-skip";
/// Rules absorb created, so `reload` knows they are wanted
pub const ABSORBED_LIST: &str = "/data/adb/nomount/absorbed.list";
/// ROM directories absorb empties in place of another module's tmpfs
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
        match std::fs::read_to_string(f) {
            Ok(s) => {
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
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => eprintln!(
                "nomount: could not read {f} ({e}) -- absorbing as if you had opted nothing \
                 out; check its permissions before trusting this pass"
            ),
        }
    }
    entries.sort();
    entries.dedup();
    (entries, from)
}

/// A module that provides Zygisk or an Xposed framework, detected by what it ships rather
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

/// `/data/adb/modules/<id>` for a path inside a module tree
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

/// Why a still-present module mount was left alone, when that was deliberate
pub enum Declined {
    Framework(String),
    HooksElsewhere(String),
    Listed(&'static str),
    MustBind,
}

/// What absorb will do about one foreign mount
pub enum Disposition {
    Absorb,
    Redundant,
    Declined(Declined),
    Leaking(&'static str),
}

/// One foreign mount and its verdict
pub struct Surveyed {
    pub target: PathBuf,
    pub source: PathBuf,
    pub disposition: Disposition,
}

/// `None` means nothing declined this mount - it is still mounted for some other reason
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

/// True if this mount is explicitly excluded
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

/// One parsed `/proc/self/mountinfo` row (the fields we need)
#[derive(Debug, Clone)]
pub(crate) struct MountRow {
    pub dev: String,
    /// Path of this mount's root *within its filesystem*, not an absolute path
    pub root: String,
    pub target: PathBuf,
}

/// Read and parse `/proc/self/mountinfo` - as bytes
pub(crate) fn read_mountinfo(path: &str) -> std::io::Result<Vec<MountRow>> {
    Ok(parse_mountinfo_bytes(&std::fs::read(path)?))
}

/// Parse mountinfo
pub(crate) fn parse_mountinfo_bytes(body: &[u8]) -> Vec<MountRow> {
    use std::os::unix::ffi::OsStringExt;
    let mut out = Vec::new();
    for line in body.split(|b| *b == b'\n') {
        let f: Vec<&[u8]> = line.split(|b| *b == b' ').collect();
        if f.len() < 5 {
            continue;
        }
        let Ok(dev) = std::str::from_utf8(f[2]) else { continue };
        out.push(MountRow {
            dev: dev.to_string(),
            root: String::from_utf8_lossy(&unescape_bytes(f[3])).into_owned(),
            target: PathBuf::from(std::ffi::OsString::from_vec(unescape_bytes(f[4]))),
        });
    }
    out
}

/// The `&str` door, kept for the tests that feed literals
pub(crate) fn parse_mountinfo(body: &str) -> Vec<MountRow> {
    parse_mountinfo_bytes(body.as_bytes())
}

fn unescape_bytes(b: &[u8]) -> Vec<u8> {
    if !b.contains(&b'\\') {
        return b.to_vec();
    }
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
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
    out
}

fn unescape(s: &str) -> String {
    let out = unescape_bytes(s.as_bytes());
    String::from_utf8(out).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

/// Map each filesystem (maj:min) to where its root is mounted, so a bind's fs-relative
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

/// Absolute source path backing a bind row, if it can be resolved
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

/// An installed app's APK: `/data/app/~~<hash>==/<pkg>-<hash>==/base.apk`, or the
/// `split_*.apk` beside it. The `~~<hash>==` wrapper is optional, hence 5 or 6 components.
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

/// Is this mount module content laid over the ROM?
pub(crate) fn is_absorbable(src: &Path, target: &Path) -> bool {
    src.starts_with(MODULE_ROOT)
        && (!target.starts_with(FOREIGN_ROOT) || is_app_apk(target))
        && target.components().count() > 1
}

/// A foreign mount that exists in another mount namespace but not in ours
pub struct Elsewhere {
    /// Which process's namespace it was seen in, for the report
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

/// Foreign mounts visible in another namespace but not in ours
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

/// Live injections plus the mountpoint aliases needed to match a bind against them, so
#[derive(Default)]
pub(crate) struct Redundancy {
    live: HashMap<PathBuf, PathBuf>,
    aliases: Vec<(PathBuf, PathBuf)>,
}

const REDUNDANCY_FILE_BUDGET: usize = 5000;

/// The uid-0 injections, target -> source
pub(crate) fn live_injections(list: &str) -> HashMap<PathBuf, PathBuf> {
    crate::nm::parse_list(list)
        .into_iter()
        .filter(|r| r.uid == 0 && r.kind == crate::nm::LiveKind::Inject)
        .filter_map(|r| Some((r.target, r.source?)))
        .collect()
}

/// Mountpoints that are the same subtree, derived from mountinfo alone: identical (device,
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

    /// True if a live injection already serves every file this bind carries, from the very
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

/// The verdict for one foreign mount
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

/// Every mount whose source is on /data and whose target is not - content some module laid
pub fn survey() -> Result<Vec<Surveyed>> {
    survey_of(MOUNTINFO)
}

/// The same survey against any process's mountinfo, so another mount namespace can be
pub fn survey_of(mountinfo: &str) -> Result<Vec<Surveyed>> {
    let rows = read_mountinfo(mountinfo).context("read mountinfo")?;
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

/// A mount we intend to act on: convert it, or - when its content is already injected -
pub struct Candidate {
    pub target: PathBuf,
    pub source: PathBuf,
    /// Unmount only
    pub redundant: bool,
}

/// Targets that currently have something mounted on them
pub(crate) fn mounted_targets() -> Option<std::collections::HashSet<PathBuf>> {
    Some(read_mountinfo(MOUNTINFO).ok()?.into_iter().map(|r| r.target).collect())
}

/// Targets absorb is currently serving
pub fn absorbed_pairs() -> Vec<(PathBuf, PathBuf)> {
    read_absorbed_pairs().unwrap_or_default()
}

/// `Err` only when the record exists but could not be read
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

fn owning_module(src: &Path) -> Option<String> {
    let s = src.to_string_lossy();
    for base in ["/data/adb/modules/", "/data/adb/modules_update/"] {
        if let Some(rest) = s.strip_prefix(base) {
            let id = rest.split('/').next().unwrap_or("");
            if !id.is_empty() {
                return Some(id.to_string());
            }
        }
    }
    None
}

fn prune_absorbed_pairs(
    pairs: Vec<(PathBuf, PathBuf)>,
    module_live: impl Fn(&str) -> bool,
    src_exists: impl Fn(&Path) -> bool,
) -> (Vec<(PathBuf, PathBuf)>, Vec<String>) {
    let mut gone: Vec<String> = Vec::new();
    let kept = pairs
        .into_iter()
        .filter(|(_, src)| match owning_module(src) {
            Some(id) if !module_live(&id) => {
                if !gone.contains(&id) {
                    gone.push(id);
                }
                false
            }
            None if !src_exists(src) => {
                gone.push(format!("{} (source gone)", src.display()));
                false
            }
            _ => true,
        })
        .collect();
    (kept, gone)
}

fn prune_absorbed_record(early: bool) {
    let Ok(all) = read_absorbed_pairs() else { return };
    if all.is_empty() {
        return;
    }
    let (kept, gone) = prune_absorbed_pairs(all, module_on_disk, |p| early || p.exists());
    let (skips, _) = skip_list();
    let mut released: Vec<String> = Vec::new();
    let kept: Vec<(PathBuf, PathBuf)> = kept
        .into_iter()
        .filter(|(t, src)| {
            if !is_skipped(src, t, &skips) {
                return true;
            }
            let _ = Nm::new().del(t);
            released.push(t.display().to_string());
            false
        })
        .collect();
    if !released.is_empty() {
        println!(
            "released {} absorbed rule(s) now on the opt-out list: {}",
            released.len(),
            released.join(", ")
        );
    }
    if !gone.is_empty() {
        println!(
            "dropped {} stale recorded row(s) (uninstalled module, or a source that no longer \
             exists): {}",
            gone.len(),
            gone.join(", ")
        );
    }
    if !released.is_empty() || !gone.is_empty() {
        set_absorbed_pairs(&kept);
    }
}

fn module_on_disk(id: &str) -> bool {
    Path::new("/data/adb/modules").join(id).is_dir()
        || Path::new("/data/adb/modules_update").join(id).is_dir()
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

/// Re-serve the absorbed APK rules recorded by a previous run
pub fn reapply_absorbed(nm: &Nm) -> u32 {
    match read_absorbed_pairs() {
        Ok(p) => reapply_absorbed_pairs(nm, &p),
        Err(e) => {
            eprintln!(
                "nomount: could not read {ABSORBED_LIST} ({e}) -- no recorded APK rule was \
                 re-served this pass"
            );
            0
        }
    }
}

/// Same, against a record read earlier - `run_mount` has to snapshot it before it clears
pub fn reapply_absorbed_pairs(nm: &Nm, pairs: &[(PathBuf, PathBuf)]) -> u32 {
    let Ok(live) = nm.list() else {
        eprintln!(
            "nomount: cannot enumerate live rules - skipping the absorbed-rule re-serve this \
             pass (re-adding blind would d_drop rules that are already live)"
        );
        return 0;
    };
    let live_targets: HashSet<PathBuf> = crate::nm::parse_list(&live)
        .into_iter()
        .filter(|r| r.kind == crate::nm::LiveKind::Inject)
        .map(|r| r.target)
        .collect();
    let mut n = 0;
    for (target, source) in pairs {
        if !source.exists() || !target.exists() {
            continue;
        }
        if let Err(why) = crate::mount::path_is_representable(target)
            .and(crate::mount::path_is_representable(source))
        {
            eprintln!(
                "nomount: not re-serving the recorded rule {} <- {}: {why}",
                target.display(),
                source.display()
            );
            continue;
        }
        if let Some(id) = owning_module(source) {
            if !crate::mount::module_enabled(&Path::new("/data/adb/modules").join(&id)) {
                continue;
            }
        }
        if live_targets.contains(target) {
            continue;
        }
        if still_mounted(target) {
            eprintln!(
                "nomount: not re-serving {} - something is mounted on it; injecting over a live \
                 mount strands it in mountinfo until reboot",
                target.display()
            );
            continue;
        }
        if is_app_apk(target) && !label_apk_readable(source) {
            continue;
        }
        if nm.add(target, source).is_ok() {
            n += 1;
        }
    }
    n
}

/// The absorbed target set, derived from the pairs record (the file is always the
pub fn read_absorbed_targets() -> std::io::Result<HashSet<PathBuf>> {
    Ok(read_absorbed_pairs()?.into_iter().map(|(t, _)| t).collect())
}

fn absorbed_pairs_body(pairs: &[(PathBuf, PathBuf)]) -> String {
    let mut body = String::from(
        "# Targets absorb re-serves as injections; reload keeps these.\n\
         # <target>\\t<source> -- the source lets the boot pass re-serve it without\n\
         # waiting for the owning module to mount again.\n",
    );
    for (t, src) in pairs {
        if let Err(why) = crate::mount::path_is_representable(t)
            .and(crate::mount::path_is_representable(src))
        {
            eprintln!(
                "nomount: not recording {} <- {}: {why}",
                t.display(),
                src.display()
            );
            continue;
        }
        body.push_str(&t.to_string_lossy());
        body.push('\t');
        body.push_str(&src.to_string_lossy());
        body.push('\n');
    }
    body
}

/// Replace the record, truncating
pub fn set_absorbed_pairs(pairs: &[(PathBuf, PathBuf)]) {
    if let Some(d) = Path::new(ABSORBED_LIST).parent() {
        let _ = fs::create_dir_all(d);
    }
    let body = absorbed_pairs_body(pairs);
    if let Err(e) = crate::statefile::write_atomic(ABSORBED_LIST, &body) {
        eprintln!("nomount: could not record absorbed targets: {e:#}");
    }
}

/// Is anything still mounted here?
pub(crate) fn still_mounted(p: &Path) -> bool {
    read_mountinfo(MOUNTINFO)
        .map(|rows| rows.iter().any(|r| r.target == p))
        .unwrap_or(true)
}

/// The path to re-assert rules at
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

/// May a redundant bind be dropped while Android is running?
pub(crate) fn runtime_droppable(target: &Path, aliases: &[(PathBuf, PathBuf)]) -> bool {
    fn touches_my_partition(p: &Path) -> bool {
        p.components()
            .any(|c| c.as_os_str().to_str().is_some_and(|s| s.starts_with("my_")))
    }
    !touches_my_partition(target) && !touches_my_partition(&servable(target, aliases))
}

pub(crate) fn umount_detach(p: &Path) -> bool {
    let Ok(c) = CString::new(p.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) == 0 }
}

fn already_serving(target: &Path, source: &Path) -> bool {
    let (Ok(t), Ok(s)) = (fs::metadata(target), fs::metadata(source)) else { return false };
    t.len() == s.len()
}

fn add_repointing(nm: &Nm, target: &Path, source: &Path, live: &LiveMap) -> bool {
    if let Err(why) = crate::mount::path_is_representable(target)
        .and(crate::mount::path_is_representable(source))
    {
        eprintln!(
            "nomount: absorb: refusing {} <- {} - {why}",
            target.display(),
            source.display()
        );
        return false;
    }
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

/// The package an installed-APK path belongs to: `/data/app/~~a==/com.foo-b==/base.apk`
/// yields `com.foo`. `None` for anything that is not an installed-APK path.
pub(crate) fn pkg_of_apk_target(target: &Path) -> Option<String> {
    if !is_app_apk(target) {
        return None;
    }
    let dir = target.parent()?.file_name()?.to_str()?;
    let (pkg, _gen) = dir.split_once('-')?;
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

/// Re-point absorbed APK rules at the app's current path
pub fn refresh_app_apks(nm: &Nm) -> (u32, u32) {
    let (mut repointed, mut stale) = (0u32, 0u32);
    let Ok(list) = nm.list() else { return (0, 0) };
    let mut pm_failed = false;
    let mut moved: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut dropped: Vec<PathBuf> = Vec::new();
    let rules = crate::nm::parse_list(&list);
    let live: LiveMap = rules
        .iter()
        .filter(|r| r.uid == 0)
        .filter_map(|r| r.source.clone().map(|s| (r.target.clone(), s)))
        .collect();
    for r in rules {
        let Some(source) = r.source else { continue };
        let target = r.target.as_path();
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
            Ok(Some(now)) if now != *target && !source.exists() => {
                eprintln!(
                    "nomount: {pkg} moved to {} but {} is not there right now -- leaving the \
                     rule and its record alone rather than dropping them as an uninstall",
                    now.display(),
                    source.display()
                );
            }
            Ok(Some(now)) if now != *target && !is_app_apk(&now) => {
                eprintln!(
                    "nomount: pm reports {pkg} at {} which is not an installed-APK path; \
                     leaving the absorbed rule alone",
                    now.display()
                );
            }
            Ok(Some(now))
                if now != *target
                    && now.file_name() != target.file_name() =>
            {
                eprintln!(
                    "nomount: {pkg} moved to {}, but the recorded rule targets {} - `pm path`                      only reports the base APK, so this split cannot be re-pointed                      automatically; leaving the rule and its record alone",
                    now.display(),
                    target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
                );
            }
            Ok(Some(now)) if now != *target => {
                if add_repointing(nm, &now, &source, &live) {
                    rewrite_absorbed_after_refresh(&[(target.to_path_buf(), now.clone())], &[]);
                    let _ = nm.del(target);
                    moved.push((target.to_path_buf(), now));
                    repointed += 1;
                } else {
                    eprintln!(
                        "nomount: could not re-point {pkg} at {} -- leaving the old rule and its \
                         record alone; {} is served the stock APK until this succeeds",
                        now.display(),
                        pkg
                    );
                }
            }
            Ok(_) => {
                let _ = nm.del(target);
                dropped.push(target.to_path_buf());
                stale += 1;
            }
        }
    }
    if !moved.is_empty() || !dropped.is_empty() {
        rewrite_absorbed_after_refresh(&moved, &dropped);
    }
    (repointed, stale)
}

fn rewrite_absorbed_after_refresh(moved: &[(PathBuf, PathBuf)], dropped: &[PathBuf]) {
    let all = match read_absorbed_pairs() {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "nomount: could not read {ABSORBED_LIST} ({e}) - not rewriting it, so the \
                 re-pointed APK rule(s) are unrecorded until the next successful absorb"
            );
            return;
        }
    };
    let (next, changed) = apply_apk_refresh(all, moved, dropped);
    if changed {
        set_absorbed_pairs(&next);
    }
}

fn apply_apk_refresh(
    mut pairs: Vec<(PathBuf, PathBuf)>,
    moved: &[(PathBuf, PathBuf)],
    dropped: &[PathBuf],
) -> (Vec<(PathBuf, PathBuf)>, bool) {
    let before = pairs.clone();
    for (t, _) in pairs.iter_mut() {
        if let Some((_, now)) = moved.iter().find(|(old, _)| old == t) {
            *t = now.clone();
        }
    }
    pairs.retain(|(t, _)| !dropped.iter().any(|d| d == t));
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    let mut keep: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(pairs.len());
    for p in pairs.into_iter().rev() {
        if seen.insert(p.0.clone()) {
            keep.push(p);
        }
    }
    let mut pairs = keep;
    pairs.sort();
    let changed = pairs != before;
    (pairs, changed)
}

/// ROM partitions a module might try to empty
/// Is `p` a ROM path - at a partition root, or under one?
///
/// `ROM_ROOTS` entries carry a trailing slash so that `/system/` cannot match `/systemx`.
/// A bare `starts_with` therefore also misses the root ITSELF: `"/product"` does not start
/// with `"/product/"`. A tmpfs mounted exactly at `/product` - a common debloat trick - was
/// invisible to `check_no_rom_tmpfs`, which then reported PASS with its own named oracle
/// wide open. Both spellings, in one place.
pub(crate) fn on_rom_path(p: &str) -> bool {
    ROM_ROOTS.iter().any(|r| {
        p.starts_with(r) || (r.ends_with('/') && p == r.trim_end_matches('/'))
    })
}

pub(crate) const ROM_ROOTS: &[&str] =
    &["/system/", "/product/", "/vendor/", "/system_ext/", "/odm/", "/oem/", "/my_"];

/// Is this device number a loop device?
pub(crate) fn is_loop_dev(dev: &str) -> bool {
    dev.split(':').next() == Some("7")
}

/// The foreign-mount rows over the ROM, as (evidence string, is_image) pairs
pub(crate) fn foreign_rom_rows(rows: &[MountRow]) -> Vec<(String, bool)> {
    let roots = ROM_ROOTS;
    let data_dev = rows.iter().find(|r| r.target == Path::new("/data")).map(|r| r.dev.clone());
    let mut hits: Vec<(String, bool)> = Vec::new();
    for r in rows {
        let t = r.target.to_string_lossy();
        if !roots.iter().any(|root| t.starts_with(root)) {
            continue;
        }
        if r.root.starts_with("/adb/modules/") || r.root.starts_with("/data/adb/modules/") {
            continue;
        }
        let subtree_bind = r.root != "/";
        let off_userdata = data_dev.as_deref() == Some(r.dev.as_str());
        let loop_image = is_loop_dev(&r.dev);
        if subtree_bind || off_userdata || loop_image {
            hits.push((format!("{} (root={}, dev={})", t, r.root, r.dev), loop_image));
        }
    }
    hits
}

/// Every foreign-mount hit, evidence only
pub(crate) fn foreign_rom_mounts(rows: &[MountRow]) -> Vec<String> {
    foreign_rom_rows(rows).into_iter().map(|(h, _)| h).collect()
}

/// Only the mounted images
pub(crate) fn rom_image_mounts(rows: &[MountRow]) -> Vec<String> {
    foreign_rom_rows(rows).into_iter().filter(|(_, img)| *img).map(|(h, _)| h).collect()
}

/// Is this mountinfo line a tmpfs laid over a ROM path?
pub(crate) fn rom_tmpfs_target(line: &str) -> Option<PathBuf> {
    let (pre, post) = line.split_once(" - ")?;
    if post.split_whitespace().next()? != "tmpfs" {
        return None;
    }
    let target = pre.split_whitespace().nth(4)?;
    on_rom_path(target).then(|| PathBuf::from(unescape(target)))
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

/// Read the ROM-tmpfs takeover record: target -> the boot its tmpfs was last seen in.
///
/// There is deliberately no infallible sibling. There used to be (`absorbed_tmpfs` /
/// `absorbed_tmpfs_targets`, `unwrap_or_default()`), and `doctor` reached for it - which
/// turned "I could not read the record" into "there are no takeovers" and accused every
/// takeover whiteout of being a rule nothing explains. Every caller handles the error.
/// The fallible door, for the callers that must not treat a read error as "the record is
pub(crate) fn read_absorbed_tmpfs() -> std::io::Result<Vec<(PathBuf, String)>> {
    match fs::read_to_string(ABSORBED_TMPFS_LIST) {
        Ok(s) => Ok(parse_tmpfs_record(&s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// Targets only, fallibly
pub(crate) fn read_absorbed_tmpfs_targets() -> std::io::Result<HashSet<PathBuf>> {
    Ok(read_absorbed_tmpfs()?.into_iter().map(|(t, _)| t).collect())
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

fn tmpfs_entry_lives(seen_now: bool, seen_boot: &str, boot: &str, mounted: bool) -> bool {
    seen_now || mounted || seen_boot.is_empty() || seen_boot == boot
}

fn absorbed_tmpfs_body(entries: &[(PathBuf, String)]) -> String {
    let mut body = String::from(
        "# ROM directories absorb empties in place of a module's tmpfs.\n\
         # <target>\\t<boot id when its tmpfs was last seen> -- absorb re-derives this\n\
         # from the live mount table every boot and drops an entry whose tmpfs is gone,\n\
         # so uninstalling the owning module restores the directory. Not hand-edited:\n\
         # a hide you want to keep belongs in whiteouts.txt.\n",
    );
    for (t, boot) in entries {
        if let Err(why) = crate::mount::path_is_representable(t) {
            eprintln!(
                "nomount: not recording the ROM-tmpfs takeover of {}: {why}",
                t.display()
            );
            continue;
        }
        body.push_str(&t.to_string_lossy());
        body.push('\t');
        body.push_str(boot);
        body.push('\n');
    }
    body
}

fn set_absorbed_tmpfs(entries: &[(PathBuf, String)]) {
    if let Some(d) = Path::new(ABSORBED_TMPFS_LIST).parent() {
        let _ = fs::create_dir_all(d);
    }
    let body = absorbed_tmpfs_body(entries);
    if let Err(e) = crate::statefile::write_atomic(ABSORBED_TMPFS_LIST, &body) {
        eprintln!("nomount: could not record the ROM tmpfs takeovers: {e:#}");
    }
}

/// Re-apply the recorded ROM-tmpfs whiteouts
pub fn reapply_tmpfs_whiteouts(nm: &Nm) -> u32 {
    let mut n = 0u32;
    let record = match read_absorbed_tmpfs() {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "nomount: could not read {ABSORBED_TMPFS_LIST} ({e}) -- NO recorded ROM-directory \
                 hide was re-applied, so every one of them is visible this session"
            );
            return 0;
        }
    };
    let mut failed = 0u32;
    for (t, _) in record {
        if crate::whiteout::validate(&t.to_string_lossy()).is_err() {
            eprintln!("nomount: skipping invalid ROM-tmpfs entry {}", t.display());
            continue;
        }
        if let Err(e) = nm.whiteout(&t) {
            eprintln!(
                "nomount: could not re-apply the ROM-directory hide on {} ({e:#}) -- it is \
                 visible this session",
                t.display()
            );
            failed += 1;
        } else {
            n += 1;
        }
    }
    if failed > 0 {
        eprintln!("nomount: {failed} recorded ROM-directory hide(s) could not be re-applied");
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
    let Ok(raw) = fs::read(MOUNTINFO) else { return st };
    let (skips, _) = skip_list();
    let nm = Nm::new();
    let Some(boot) = boot_id() else {
        eprintln!(
            "nomount: cannot read this boot's id -- skipping the ROM-tmpfs pass rather than \
             recording takeovers with no stamp, which are never expired (a permanent hide)"
        );
        return st;
    };
    let mut record = match read_absorbed_tmpfs() {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "nomount: could not read {ABSORBED_TMPFS_LIST} ({e}) -- not touching the \
                 ROM-tmpfs takeovers this pass; rewriting from an empty read would un-hide \
                 every one of them"
            );
            return st;
        }
    };
    let durable = crate::whiteout::read().unwrap_or_default();
    let mut seen: HashSet<PathBuf> = HashSet::new();
    for target in raw
        .split(|b| *b == b'\n')
        .filter_map(|l| std::str::from_utf8(l).ok())
        .filter_map(rom_tmpfs_target)
    {
        if is_skipped(Path::new("/"), &target, &skips) {
            if record.iter().any(|(t, _)| *t == target) {
                if dry_run {
                    println!(
                        "would release the hide on {} (now on the opt-out list)",
                        target.display()
                    );
                } else {
                    let _ = nm.del(&target);
                    record.retain(|(t, _)| *t != target);
                    println!(
                        "released the hide on {} (now on the opt-out list)",
                        target.display()
                    );
                }
            }
            println!("skipping the tmpfs over {} (opt-out list)", target.display());
            st.declined += 1;
            continue;
        }
        if let Err(why) = crate::mount::path_is_representable(&target) {
            eprintln!(
                "nomount: LEAK the tmpfs over {} stays mounted: {why}, so absorb cannot record \
                 the takeover and will not make one it could never expire",
                target.display()
            );
            st.leaked += 1;
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
        let _ = umount_detach(&target);
        if still_mounted(&target) {
            eprintln!(
                "nomount: {} still has a mount on it after the unmount - leaving it for the \
                 next pass",
                target.display()
            );
            st.failed += 1;
            continue;
        }
        if was_durable {
            match crate::whiteout::forget_locked(&t_str) {
                Ok(_) => println!(
                    "moved {t_str} out of whiteouts.txt into absorb's own list: it came from a \
                     tmpfs, so it should stop hiding when that tmpfs does"
                ),
                Err(e) => {
                    eprintln!(
                        "nomount: {t_str} is still in whiteouts.txt ({e:#}) - not recording it \
                         in absorb's list too, because a path on both lists is hidden forever"
                    );
                    st.failed += 1;
                    continue;
                }
            }
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
                set_absorbed_tmpfs(&record);
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
    let mounted = mounted_targets();
    record.retain(|(t, seen_boot)| {
        let is_mounted = mounted.as_ref().is_none_or(|m| m.contains(t));
        if tmpfs_entry_lives(seen.contains(t), seen_boot, &boot, is_mounted) {
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

fn merge_absorbed(all: &mut Vec<(PathBuf, PathBuf)>, fresh: Vec<(PathBuf, PathBuf)>) {
    for p in fresh {
        match all.iter_mut().find(|(t, _)| *t == p.0) {
            Some(slot) => slot.1 = p.1,
            None => all.push(p),
        }
    }
}

/// `nomount absorb [--dry-run]`
pub fn run_absorb(dry_run: bool, include_dirs: bool, early: bool) -> Result<()> {
    let _pass = if dry_run { None } else { crate::mount::pass_lock() };
    let nm = Nm::new();
    nm.version()
        .context("hookless NoMount engine not responding")?;

    if !dry_run {
        prune_absorbed_record(early);
    }

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
    let rows = read_mountinfo(MOUNTINFO).unwrap_or_default();
    let aliases = mount_aliases(&rows);
    let (mut leaking, mut declined) = (tmpfs.leaked + tmpfs.failed, tmpfs.declined);
    let imaged: Vec<String> = rom_image_mounts(&rows);
    for h in &imaged {
        leaking += 1;
        eprintln!(
            "nomount: LEAK {h} is an image mounted over a ROM partition: absorb cannot \
             re-serve it (there is no file source to inject), so it stays visible in every \
             app's mount table. Remove it from the owning module."
        );
    }
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
            Disposition::Redundant => early || runtime_droppable(&s.target, &aliases),
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
        match (leaking + deferred as u32, declined) {
            (0, 0) => println!("nomount absorb: nothing mounted over the ROM (posture clean)"),
            (0, d) => println!(
                "nomount absorb: nothing to absorb; {d} mount(s) left by design and still visible"
            ),
            (n, d) => println!(
                "nomount absorb: nothing to absorb, but {n} foreign mount(s) remain, \
                 plus {d} more left by design - the posture is not clean"
            ),
        }
        return Ok(());
    }

    let (mut done, mut failed, mut skipped_dirs) = (0u32, 0u32, 0u32);
    let mut dropped = 0u32;
    let live_map = live_injects(&nm);
    let mut reasserted: HashSet<PathBuf> = HashSet::new();
    let mut fresh: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut record = read_absorbed_pairs();
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
            let _ = umount_detach(&c.target);
            if still_mounted(&c.target) {
                eprintln!(
                    "nomount: redundant {} still has a mount on it after the unmount - \
                     leaving it for the next pass",
                    c.target.display()
                );
                failed += 1;
                continue;
            }
            let at = servable(&c.target, &aliases);
            if !reasserted.insert(at.clone()) {
                continue;
            }
            dropped += 1;
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
        if !c.source.exists() {
            leaking += 1;
            eprintln!(
                "nomount: LEAK {} <- {} stays mounted: its source no longer exists, so \
                 absorbing it would drop the content instead of re-serving it",
                c.target.display(),
                c.source.display()
            );
            continue;
        }
        let _ = umount_detach(&c.target);
        if still_mounted(&c.target) {
            eprintln!(
                "nomount: {} still has a mount on it after the unmount - leaving it for the \
                 next pass (injecting anyway would strand it in mountinfo)",
                c.target.display()
            );
            failed += 1;
            continue;
        }
        let before = fresh.len();
        let fails = inject(&nm, &c.source, &c.target, &mut fresh, &live_map);
        let served = fresh.len() - before;
        if let Ok(all) = record.as_mut() {
            if served > 0 {
                merge_absorbed(all, fresh[before..].to_vec());
                all.sort();
                set_absorbed_pairs(all);
            }
        }
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
    match record {
        Ok(mut all) => {
            merge_absorbed(&mut all, fresh_pairs);
            all.sort();
            set_absorbed_pairs(&all);
        }
        Err(e) => eprintln!(
            "nomount: could not read {ABSORBED_LIST} ({e}) - not rewriting it, because an \
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
    let defer = if deferred > 0 {
        format!(", {deferred} my_* mount(s) deferred and still mounted")
    } else {
        String::new()
    };
    if dry_run {
        println!(
            "nomount absorb: {} mount(s) would be absorbed, {} ROM tmpfs, {skipped_dirs} directory bind(s) skipped{drops}{leaks}{defer} (dry run)",
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
            "nomount absorb: {done} mount(s) absorbed as {rules} rule(s), {} ROM tmpfs emptied mountlessly, {} failed{dirs}{drops}{leaks}{defer}",
            tmpfs.done,
            failed + tmpfs.failed
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_package_is_taken_from_the_first_hyphen_not_the_last() {
        let pkg = |p: &str| pkg_of_apk_target(Path::new(p));
        for (dir, want) in [
            ("com.aurora.store-wGPab65m-g9eKk4hn6AwhQ==", "com.aurora.store"),
            ("com.google.android.apps.podcasts-aFR-fM5j_05Sjby4cePVSQ==",
             "com.google.android.apps.podcasts"),
            ("com.secondream.novagram-eId8imI-ZGqO1myGu9Qy8g==", "com.secondream.novagram"),
            ("com.foo-b==", "com.foo"),
        ] {
            assert_eq!(
                pkg(&format!("/data/app/~~a==/{dir}/base.apk")).as_deref(),
                Some(want),
                "{dir}"
            );
        }
        assert_eq!(pkg("/data/app/~~a==/nodots-b==/base.apk"), None);
        assert_eq!(pkg("/system/app/Foo/Foo.apk"), None);
    }

    #[test]
    fn a_split_apk_row_is_not_repointed_onto_the_base_apk() {
        let split = Path::new("/data/app/~~a==/com.foo-a==/split_config.arm64_v8a.apk");
        let base = Path::new("/data/app/~~b==/com.foo-b==/base.apk");
        assert!(is_app_apk(split), "a split target is recordable in the first place");
        assert_ne!(
            split.file_name(),
            base.file_name(),
            "the guard that stops the re-point is the file-name comparison"
        );
    }

    #[test]
    fn a_repointed_apk_moves_its_row_and_an_uninstall_drops_it() {
        let old = PathBuf::from("/data/app/~~a==/com.foo-a==/base.apk");
        let now = PathBuf::from("/data/app/~~b==/com.foo-b==/base.apk");
        let gone = PathBuf::from("/data/app/~~c==/com.bar-c==/base.apk");
        let keep = PathBuf::from("/data/app/~~d==/com.baz-d==/base.apk");
        let src = PathBuf::from("/data/adb/rvhc/patched.apk");

        let pairs = vec![
            (old.clone(), src.clone()),
            (gone.clone(), src.clone()),
            (keep.clone(), src.clone()),
        ];
        let (next, changed) =
            apply_apk_refresh(pairs, &[(old.clone(), now.clone())], std::slice::from_ref(&gone));

        assert!(changed);
        assert!(next.iter().any(|(t, s)| *t == now && *s == src), "row follows the app");
        assert!(!next.iter().any(|(t, _)| *t == old), "the dead path is gone");
        assert!(!next.iter().any(|(t, _)| *t == gone), "an uninstall retires its row");
        assert!(next.iter().any(|(t, _)| *t == keep), "an untouched row survives");
    }

    #[test]
    fn a_repoint_onto_an_already_recorded_target_does_not_duplicate_it() {
        let old = PathBuf::from("/data/app/~~a==/com.foo-a==/base.apk");
        let now = PathBuf::from("/data/app/~~b==/com.foo-b==/base.apk");
        let src = PathBuf::from("/data/adb/rvhc/patched.apk");
        let (next, changed) = apply_apk_refresh(
            vec![(old.clone(), src.clone()), (now.clone(), src.clone())],
            &[(old, now.clone())],
            &[],
        );
        assert!(changed);
        assert_eq!(next.iter().filter(|(t, _)| *t == now).count(), 1);
        assert_eq!(next.len(), 1);
    }

    #[test]
    fn prune_drops_rows_from_uninstalled_modules() {
        let pairs = vec![
            (
                PathBuf::from("/system/etc/hosts"),
                PathBuf::from("/data/adb/modules/nmt06_selfmount/hosts"),
            ),
            (
                PathBuf::from("/system/etc/other"),
                PathBuf::from("/data/adb/modules/still_here/other"),
            ),
        ];
        let (kept, gone) = prune_absorbed_pairs(pairs, |id| id == "still_here", |_| true);
        assert_eq!(gone, vec!["nmt06_selfmount".to_string()]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].0, PathBuf::from("/system/etc/other"));
    }

    #[test]
    fn prune_keeps_a_live_module_whose_payload_is_not_built_yet() {
        let pairs = vec![(
            PathBuf::from("/system/etc/hosts"),
            PathBuf::from("/data/adb/modules/runtime_built/system/etc/hosts"),
        )];
        let (kept, gone) = prune_absorbed_pairs(pairs, |_| true, |_| true);
        assert!(gone.is_empty());
        assert_eq!(kept.len(), 1);
    }

    #[test]
    fn prune_keeps_staged_and_unattributable_rows() {
        let pairs = vec![
            (
                PathBuf::from("/system/a"),
                PathBuf::from("/data/adb/modules_update/upd/system/a"),
            ),
            (PathBuf::from("/system/b"), PathBuf::from("/data/local/tmp/b")),
        ];
        let (kept, gone) = prune_absorbed_pairs(pairs, |id| id == "upd", |_| true);
        assert!(gone.is_empty(), "staged or unattributable rows must survive");
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn owning_module_reads_both_trees() {
        assert_eq!(
            owning_module(Path::new("/data/adb/modules/foo/system/etc/x")).as_deref(),
            Some("foo")
        );
        assert_eq!(
            owning_module(Path::new("/data/adb/modules_update/foo/x")).as_deref(),
            Some("foo")
        );
        assert_eq!(owning_module(Path::new("/data/local/tmp/x")), None);
        assert_eq!(owning_module(Path::new("/data/adb/modules/")), None);
    }

    #[test]
    fn a_refresh_that_moved_nothing_reports_no_change() {
        let p = vec![(PathBuf::from("/data/app/~~a==/com.foo-a==/base.apk"), PathBuf::from("/x"))];
        let (_, changed) = apply_apk_refresh(p, &[], &[]);
        assert!(!changed);
    }

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

    #[test]
    fn one_undecodable_path_costs_one_row_not_the_table() {
        use std::os::unix::ffi::OsStrExt;
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(b"1 1 0:1 /before /data/before rw - t s rw\n");
        body.extend_from_slice(b"2 1 0:1 /caf\xe9 /data/caf\xe9 rw - t s rw\n");
        body.extend_from_slice(b"3 1 0:1 /after /data/after rw - t s rw\n");

        let rows = parse_mountinfo_bytes(&body);
        assert_eq!(rows.len(), 3, "the undecodable row must not take its neighbours");

        assert_eq!(rows[0].target, PathBuf::from("/data/before"));
        assert_eq!(rows[2].target, PathBuf::from("/data/after"));
        assert_eq!(
            rows[1].target.as_os_str().as_bytes(),
            b"/data/caf\xe9",
            "the non-UTF-8 target must survive byte for byte"
        );
    }

    #[test]
    fn re_absorbing_a_target_records_the_new_source() {
        let t = PathBuf::from("/product/app/A/A.apk");
        let old_src = PathBuf::from("/data/app/~~aaa==/pkg-1/base.apk");
        let new_src = PathBuf::from("/data/app/~~bbb==/pkg-2/base.apk");

        let mut all = vec![(t.clone(), old_src.clone())];
        merge_absorbed(&mut all, vec![(t.clone(), new_src.clone())]);

        assert_eq!(all.len(), 1, "the target must not be recorded twice");
        assert_eq!(
            all[0].1, new_src,
            "the record must name the source this pass served, not the first one ever absorbed"
        );

        let other = PathBuf::from("/product/app/B/B.apk");
        let other_src = PathBuf::from("/data/adb/modules/m/product/app/B/B.apk");
        merge_absorbed(&mut all, vec![(other.clone(), other_src.clone())]);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].1, new_src);
        assert_eq!(all[1], (other, other_src));
    }

    #[test]
    fn a_row_whose_source_vanished_is_dropped_even_with_no_owning_module() {
        let rvhc = (
            PathBuf::from("/data/app/~~x==/com.example-y==/base.apk"),
            PathBuf::from("/data/adb/rvhc/example-jhc.apk"),
        );
        let owned = (
            PathBuf::from("/product/app/A/A.apk"),
            PathBuf::from("/data/adb/modules/still_here/product/app/A/A.apk"),
        );

        let (kept, gone) = prune_absorbed_pairs(
            vec![rvhc.clone(), owned.clone()],
            |id| id == "still_here",
            |p| !p.starts_with("/data/adb/rvhc"),
        );
        assert_eq!(kept, vec![owned.clone()], "the unattributable dead row must go");
        assert_eq!(gone.len(), 1);
        assert!(gone[0].contains("rvhc"), "{gone:?}");

        let (kept, gone) = prune_absorbed_pairs(vec![rvhc.clone()], |_| true, |_| true);
        assert_eq!(kept, vec![rvhc], "a live source is not ours to drop");
        assert!(gone.is_empty());
    }

    #[test]
    fn an_octal_escaped_newline_cannot_forge_a_record_row() {
        let victim = "/data/app/~~aa==/com.victim-bb==/base.apk";
        let payload = "/data/adb/persist/pay.apk";
        let rows = parse_mountinfo(&format!(
            "1 1 0:1 / /system/etc/x\\012{victim}\\011{payload} rw - t s rw"
        ));
        let target = rows[0].target.clone();
        assert!(
            target.to_string_lossy().contains('\n'),
            "the escape must decode back to a real newline: {target:?}"
        );
        assert!(
            crate::mount::path_is_representable(&target).is_err(),
            "the shared gate must reject the decoded path"
        );

        let ok_t = PathBuf::from("/system/etc/ok");
        let ok_s = PathBuf::from("/data/adb/modules/ok/system/etc/ok");
        let body = absorbed_pairs_body(&[
            (target.clone(), PathBuf::from("/data/adb/modules/evil/x")),
            (ok_t.clone(), ok_s.clone()),
        ]);
        assert!(!body.contains(victim), "the forged line must not reach the record");
        let back = parse_absorbed_pairs(&body);
        assert_eq!(back, vec![(ok_t, ok_s)], "only the representable row may be written");

        let ok = PathBuf::from("/product/app/Ok");
        let body = absorbed_tmpfs_body(&[
            (target, "boot-1".to_string()),
            (ok.clone(), "boot-1".to_string()),
        ]);
        assert!(!body.contains(victim));
        let back = parse_tmpfs_record(&body);
        assert_eq!(back, vec![(ok, "boot-1".to_string())]);
    }
}
