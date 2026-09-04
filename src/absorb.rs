//! Convert other people's bind mounts into hookless injections.
//!
//! The Suite is mountless, but a third-party module can still run its own
//! `mount --bind` from a boot script, and every such mount is visible in
//! `/proc/*/mountinfo` to any app — which is the entire signal the zero-mount
//! posture exists to deny. Today that only holds because module authors
//! cooperate (OnePlus_Dialer_Universal literally checks for meta-nomount and
//! stands down). A module that does not know about NoMount punches straight
//! through it.
//!
//! Absorption removes the dependency on cooperation: after module scripts have
//! run, every mount whose source lives under `/data/adb` and whose target is on
//! a read-only ROM partition is re-served as a VFS injection and then unmounted.
//! The content stays available the whole time — the injection is added *first*,
//! and the still-present mount simply shadows it until it goes away.
//!
//! This is only possible because injection is mountless: no overlay- or
//! bind-based metamodule can absorb a mount, because it would have to create one.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::nm::Nm;

const MOUNTINFO: &str = "/proc/self/mountinfo";
/// Only sources under here are module content we may take over.
const MODULE_ROOT: &str = "/data/adb";
/// A mount backed by anything under here, landing outside it, is foreign content
/// over the ROM — worth reporting even when `MODULE_ROOT` does not cover it.
const FOREIGN_ROOT: &str = "/data";
/// Opt-out list: module ids or target path prefixes to leave mounted. `.txt`
/// to match its peer `whiteouts.txt` and because this file is meant to be
/// hand-edited -- an extensionless file makes an Android file manager ask which
/// app to open it with.
pub const SKIP_FILE: &str = "/data/adb/nomount/absorb-skip.txt";
/// Pre-v1.2.1 name, still honoured so an existing install keeps its opt-outs.
const SKIP_FILE_LEGACY: &str = "/data/adb/nomount/absorb-skip";
/// Rules absorb created, so `reload` knows they are wanted.
///
/// An absorbed rule belongs to no module *plan* -- it came from a bind whose
/// source can sit anywhere inside the owning module, including paths the plan
/// walk never visits. `reload` prunes every live rule the plan does not name, so
/// without this record a single Reload silently undid every absorption and the
/// mounts did not come back either: the content simply reverted to stock.
pub const ABSORBED_LIST: &str = "/data/adb/nomount/absorbed.list";
/// ROM directories absorb empties in place of another module's tmpfs.
///
/// Absorb-owned, deliberately NOT the user's durable `whiteouts.txt`: that list
/// is re-applied at every boot and nothing prunes it, so a tmpfs takeover written
/// there hid the ROM directory forever -- long after the module that mounted the
/// tmpfs was uninstalled (M-S8). This one is re-derived from the live mount table
/// on every absorb pass: an entry lives while its tmpfs keeps coming back and is
/// dropped when it stops.
pub const ABSORBED_TMPFS_LIST: &str = "/data/adb/nomount/absorbed-tmpfs.list";

/// Used when the skip file cannot be read at all. Keyed on the PATH BEING
/// HOOKED, not on who installed it: a hook framework's module id varies between
/// forks (`zygisk_lsposed`, `zygisk_lsposed_next`, `lsposed`, …) and an id list
/// silently misses every one it does not name, while the path it hooks is the
/// same for all of them. Losing the file must not quietly expose a framework, so
/// this is what absorb falls back to rather than "skip nothing".
const BUILTIN_SKIPS: &[&str] = &[
    // Prefixes: each covers the plain, `d` (debug), `32` and `64` variants.
    // BOTH apex names matter — ART lived in com.android.runtime before moving to
    // com.android.art, and frameworks still hook whichever exists. Vector
    // (JingMatrix) targets eight paths spread across the two, so keying on the
    // com.android.art name alone silently missed half of them.
    "/apex/com.android.art/bin/dex2oat",
    "/apex/com.android.runtime/bin/dex2oat",
    "/system/bin/dex2oat", // pre-apex layout
    "/system/bin/app_process",
];

/// Entries to leave alone: one per line, either a module id (matched against the
/// bind's source) or an absolute target prefix. Blank lines and `#` ignored.
/// The user's entries are ADDED to the built-ins, never substituted for them.
/// They used to replace them, which meant writing a single line into the skip
/// file silently dropped dex2oat and app_process protection — a footgun with a
/// delayed, silent failure mode, since dexopt runs on app install rather than at
/// boot. The built-ins are the floor; the file can only raise it.
fn skip_list() -> (Vec<String>, &'static str) {
    let mut entries: Vec<String> = BUILTIN_SKIPS.iter().map(|s| (*s).to_string()).collect();
    // Read BOTH files and union them: returning after the first readable one
    // silently ignored the legacy file whenever the new one existed. Report the
    // primary (new) file if present, else the legacy, else the built-ins.
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
    // dedup only removes ADJACENT duplicates, so it is a no-op on an unsorted vec.
    entries.sort();
    entries.dedup();
    (entries, from)
}

/// A module that provides Zygisk or an Xposed framework, detected by what it
/// ships rather than by its id.
///
/// Absorbing a hook framework's own bind is the one absorption that can break
/// something badly and late — dexopt runs on app install, not at boot, so the
/// damage surfaces hours later as "modules stopped applying". Id lists fail in
/// both directions here (Vector renames itself; Irena keeps `zygisk_lsposed`),
/// and a path list only covers the paths someone thought to enumerate. What
/// every one of them has in common is structure:
///
/// * a Zygisk **module** ships `zygisk/<abi>.so` — LSPosed and every fork,
///   PlayIntegrityFix, HMA, zygisk-detach
/// * a Zygisk **provider** ships the loader itself, `bin/zygiskd*` or
///   `bin/zygisk-ptrace*` — Zygisk Next (`zygisksu`), ReZygisk, NeoZygisk
///
/// Either marker means: leave everything this module mounts alone.
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

/// `/data/adb/modules/<id>` for a path inside a module tree.
pub(crate) fn module_dir_of(src: &Path) -> Option<PathBuf> {
    let s = src.to_string_lossy();
    let rest = s.split("/modules/").nth(1)?;
    let id = rest.split('/').next()?;
    if id.is_empty() {
        return None;
    }
    Some(PathBuf::from("/data/adb/modules").join(id))
}

/// Module ids that own a mount landing on a known hook path.
///
/// FINDING-2: identifying a hook framework by the files it ships lost to the
/// arms race. `is_hook_framework` looks for `zygisk/` or `bin/zygisk*`, and
/// against current releases it is 0-for-3 — Vector v2.2 ships `framework/` and
/// `daemon.apk`, ReZygisk ships `machikado.arm64`/`misaki.sig`, Zygisk Next
/// ships `mazoku`. Those names are deliberately obfuscated to defeat detectors,
/// and they defeat ours the same way. Chasing them is a treadmill.
///
/// What cannot be renamed is the TARGET: a hook framework has to land on
/// dex2oat or app_process to do its job. So identify by target, then protect by
/// module — once a module is known to hook, every mount it owns is declined,
/// including ones no list enumerates. The shipped-files check stays on as a
/// second, independent signal; neither is load-bearing alone.
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

/// Why a still-present module mount was left alone, when that was deliberate.
pub enum Declined {
    /// The module ships Zygisk/Xposed markers, so absorb never touches it.
    Framework(String),
    /// The module hooks a known path elsewhere, so all of its mounts are left
    /// alone — including this one, which is not itself on a hook path.
    HooksElsewhere(String),
    /// Named by the skip list (or the built-in fallback), which names its source.
    Listed(&'static str),
    /// `my_*` is served by a real bind, so converting the module's bind to an
    /// injection would trade a working mount for a zygote bootloop.
    MustBind,
}

/// What absorb will do about one foreign mount.
///
/// Absorb used to model only its own action -- "mounts I can convert" -- and
/// treated everything else as absent, which is how a bind sourced from
/// /data/local/tmp got reported as "posture already clean". The posture is a
/// claim about what is visible in mountinfo, not about how much absorb managed
/// to convert, so every foreign mount now lands in exactly one of these and
/// silence is unreachable while one exists.
pub enum Disposition {
    /// Convert it to injections.
    Absorb,
    /// Every file this bind serves is ALREADY a live injection from the same
    /// source file, so the mount adds nothing: drop it, add no rule.
    ///
    /// Worth its own verdict because both of the other answers are wrong for it.
    /// `Absorb` would re-serve rules that already exist, and for a directory bind
    /// would demand `--include-dirs` and snapshot a listing the module plan
    /// already maintains properly. `Leaking` is what `serve_mode` returns for the
    /// propagated twin of such a bind (`/mnt/vendor/my_product/...`, whose root is
    /// in NON_PARTITION_ROOTS) even though dropping it removes nothing: it is the
    /// same subtree as the servable path, already injected. Both were reported on
    /// an OP11 whose Bootanimation module still ran a legacy `mount --bind` over
    /// content NoMount was injecting anyway.
    Redundant,
    /// Still mounted on purpose.
    Declined(Declined),
    /// Still mounted because absorb cannot take it, and still visible to apps.
    Leaking(&'static str),
}

/// One foreign mount and its verdict.
pub struct Surveyed {
    pub target: PathBuf,
    pub source: PathBuf,
    pub disposition: Disposition,
}

/// `None` means nothing declined this mount — it is still mounted for some other
/// reason (absorb has not run, or it failed), which is the only case worth a warning.
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
        // Identified by a hook path it mounts SOMEWHERE ELSE, so this mount is
        // spared too even though its own target is ordinary.
        if hookers.contains(&id) {
            return Some(Declined::HooksElsewhere(id));
        }
    }
    is_skipped(src, target, skips).then_some(Declined::Listed(from))
}

/// True if this mount is explicitly excluded.
pub(crate) fn is_skipped(src: &Path, target: &Path, skips: &[String]) -> bool {
    if module_dir_of(src).is_some_and(|d| is_hook_framework(&d)) {
        return true;
    }
    let (s, t) = (src.to_string_lossy(), target.to_string_lossy());
    skips.iter().any(|k| {
        if k.starts_with('/') {
            t.starts_with(k.as_str())
        } else {
            // module id: match the /data/adb/modules/<id>/ path component
            s.contains(&format!("/modules/{k}/"))
        }
    })
}

/// One parsed `/proc/self/mountinfo` row (the fields we need).
#[derive(Debug, Clone)]
pub(crate) struct MountRow {
    pub dev: String,
    /// Path of this mount's root *within its filesystem*, not an absolute path.
    pub root: String,
    pub target: PathBuf,
}

/// Parse mountinfo. Format: `id parent maj:min root mountpoint opts... - fstype source super`.
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

/// mountinfo octal-escapes space, tab, newline and backslash.
fn unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let b = s.as_bytes();
    // Collect BYTES, not chars. `out.push(b[i] as char)` is Latin-1: every byte
    // >= 0x80 became U+0080..U+00FF and was then re-encoded as two UTF-8 bytes,
    // so any non-ASCII path that also contained an escape came out corrupted --
    // and the corrupted string is what umount2() and the injector are handed. It
    // needed both to bite (the no-backslash fast path above returns early), which
    // is why it survived: a module directory with an accent AND a space in its
    // name. Assembling bytes and decoding once keeps such a path exact.
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

/// Map each filesystem (maj:min) to where its ROOT is mounted, so a bind's
/// fs-relative `root` field can be turned back into an absolute path. A bind of
/// `/data/adb/x` reports `root=/adb/x` against the device `/data` is mounted on,
/// so resolving it needs this table — a plain prefix match on `root` is wrong.
pub(crate) fn fs_roots(rows: &[MountRow]) -> HashMap<String, PathBuf> {
    let mut m: HashMap<String, PathBuf> = HashMap::new();
    for r in rows.iter().filter(|r| r.root == "/") {
        m.entry(r.dev.clone())
            .and_modify(|cur| {
                // Shortest mountpoint wins: that is the real fs root, not a
                // later bind of the whole filesystem somewhere else.
                if r.target.as_os_str().len() < cur.as_os_str().len() {
                    *cur = r.target.clone();
                }
            })
            .or_insert_with(|| r.target.clone());
    }
    m
}

/// Absolute source path backing a bind row, if it can be resolved.
pub(crate) fn source_of(row: &MountRow, roots: &HashMap<String, PathBuf>) -> Option<PathBuf> {
    if row.root == "/" {
        return None; // a whole-filesystem mount, not a bind of a subtree
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
/// pre-Android-9 `/data/app/<pkg>-1/base.apk`, plus the `split_*.apk` siblings.
///
/// The one shape under `FOREIGN_ROOT` worth taking over. A patched-APK module
/// (ReVanced and friends) binds its APK here from its own script, which leaves an
/// `/adb/` token in every process's mount table -- issue #14. The engine serves
/// `/data` targets perfectly well (measured on OP15: rule served, zero mounts,
/// clean revert), so the old blanket "not on /data" refusal was a limit of the
/// absorb gate, not of the engine.
///
/// Deliberately narrow: anything looser and absorb would start eating unrelated
/// `/data` mounts, where a wrong take-over costs an app its data rather than a
/// ROM file that can be re-served.
pub(crate) fn is_app_apk(target: &Path) -> bool {
    if !target.starts_with("/data/app/") {
        return false;
    }
    let n = target.components().count();
    // /data/app/<container>/<pkg-dir>/<file> = 6, /data/app/<pkg-dir>/<file> = 5.
    if n != 5 && n != 6 {
        return false;
    }
    target
        .file_name()
        .and_then(|f| f.to_str())
        .is_some_and(|f| f == "base.apk" || (f.starts_with("split_") && f.ends_with(".apk")))
}

/// Is this mount module content laid over the ROM? OWNERSHIP only — whether the
/// target can actually be served is `mount::serve_mode`'s question, and asking
/// it here instead is what let absorb inject onto `/my_*` and `/apex`.
pub(crate) fn is_absorbable(src: &Path, target: &Path) -> bool {
    src.starts_with(MODULE_ROOT)
        && (!target.starts_with(FOREIGN_ROOT) || is_app_apk(target))
        && target.components().count() > 1
}

/// A foreign mount that exists in another mount namespace but not in ours.
pub struct Elsewhere {
    /// Which process's namespace it was seen in, for the report.
    pub seen_in: String,
    pub mount: Surveyed,
}

/// `mnt:[4026531841]`-style id, so two pids sharing a namespace are only read once.
fn mnt_ns_of(pid: &str) -> Option<String> {
    fs::read_link(format!("/proc/{pid}/ns/mnt")).ok().map(|p| p.to_string_lossy().into_owned())
}

/// The pids whose namespace an app actually inherits or is judged against: init,
/// and zygote (both bitnesses). Anything a module `nsenter`s into to make its
/// bind stick for apps has to be one of these.
fn namespace_probes() -> Vec<(String, String)> {
    let mut out = vec![("init".to_string(), "1".to_string())];
    let Ok(rd) = fs::read_dir("/proc") else { return out };
    for e in rd.filter_map(Result::ok) {
        let pid = e.file_name().to_string_lossy().into_owned();
        if !pid.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        // Match on CMDLINE, not comm. The ART runtime renames the zygote thread,
        // so `/proc/<pid>/comm` reads `main` — keying on comm matched nothing and
        // the whole cross-namespace check silently did nothing. cmdline still
        // says `zygote64`/`zygote`, and it is NUL-padded, hence the trim.
        let Ok(raw) = fs::read_to_string(format!("/proc/{pid}/cmdline")) else { continue };
        let name = raw.split('\0').next().unwrap_or("").trim();
        if name == "zygote64" || name == "zygote" {
            out.push((name.to_string(), pid));
        }
    }
    out
}

/// Foreign mounts visible in another namespace but not in ours.
///
/// absorb reads `/proc/self/mountinfo` and `umount2`s in its own namespace. A
/// module that replicates its bind with `nsenter --mount=/proc/<pid>/ns/mnt`
/// — custom-certificate-authorities does exactly this, into init AND zygote —
/// is therefore invisible to the survey and out of reach of the unmount, so a
/// "posture clean" verdict was only ever a claim about OUR namespace while the
/// mount was still plainly there for apps. We cannot remove these from here
/// (that needs setns, which is a different and much sharper tool), but staying
/// silent about them is the failure this whole reporting model exists to avoid.
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
        // Same namespace as us (the common case) has nothing new to say.
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

/// Live injections plus the mountpoint aliases needed to match a bind against
/// them, so absorb can recognise a mount whose content it is already serving.
///
/// Both halves come from state absorb already reads: `nm list` for the rules,
/// mountinfo for the aliases. Nothing here consults the module plan, so a rule
/// counts only if the engine is really serving it right now.
#[derive(Default)]
pub(crate) struct Redundancy {
    /// target -> source, uid-0 injects only. A per-UID rule does not make a
    /// global mount redundant: dropping the mount would expose the stock file to
    /// every other UID.
    live: HashMap<PathBuf, PathBuf>,
    /// Mountpoint pairs that are the same subtree, both directions. OnePlus
    /// mounts one filesystem at both `/my_product` and `/mnt/vendor/my_product`,
    /// so a module bind propagates to both and only one of the two paths is
    /// servable — the other is under `/mnt`, which `serve_mode` refuses.
    aliases: Vec<(PathBuf, PathBuf)>,
}

/// Stop walking a source this large rather than answer slowly: a bind big enough
/// to blow this budget is not the legacy two-file case this exists for, and
/// "not redundant" is the safe answer (absorb just handles it the old way).
const REDUNDANCY_FILE_BUDGET: usize = 5000;

/// The uid-0 injections, target -> source.
///
/// Reshaped from [`crate::nm::parse_list`], the one parser of `nm list` text
/// (`mount` and the plan lint derive their own shapes from the same rows). This used
/// to be its own reader and had already drifted from mount.rs's -- they split a
/// line differently -- with nothing to make them converge again.
///
/// Whiteouts and virtual dirs are dropped: neither can make a bind redundant.
/// So is every per-UID rule -- it serves one UID, and dropping a global mount
/// because of one would expose the stock file to every other UID.
pub(crate) fn live_injections(list: &str) -> HashMap<PathBuf, PathBuf> {
    crate::nm::parse_list(list)
        .into_iter()
        .filter(|r| r.uid == 0 && r.kind == crate::nm::LiveKind::Inject)
        .filter_map(|r| Some((r.target, r.source?)))
        .collect()
}

/// Mountpoints that are the same subtree, derived from mountinfo alone: identical
/// (device, filesystem-root) is exactly what "same content" means.
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

/// Relative paths of every regular file under `src`. A file source yields one
/// empty path, meaning "src itself". `None` if the walk is too big or unreadable
/// — an unknown listing must not be reported as fully covered.
fn files_under(src: &Path) -> Option<Vec<PathBuf>> {
    fn walk(dir: &Path, prefix: &Path, out: &mut Vec<PathBuf>) -> Option<()> {
        for e in std::fs::read_dir(dir).ok()?.flatten() {
            if out.len() >= REDUNDANCY_FILE_BUDGET {
                return None;
            }
            // Not `is_dir()`: that follows symlinks, and a symlinked directory
            // would be walked as content the bind does not actually carry.
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
    // An empty directory proves nothing is covered, so it is not redundant.
    (!out.is_empty()).then_some(out)
}

impl Redundancy {
    pub(crate) fn new(list: &str, rows: &[MountRow]) -> Self {
        Self { live: live_injections(list), aliases: mount_aliases(rows) }
    }

    /// Every path this target is reachable by: itself, plus the same tail under
    /// any mountpoint that is the same subtree.
    fn reachable(&self, target: &Path) -> Vec<PathBuf> {
        let mut out = vec![target.to_path_buf()];
        for (a, b) in &self.aliases {
            if let Ok(tail) = target.strip_prefix(a) {
                out.push(b.join(tail));
            }
        }
        out
    }

    /// True if a live injection already serves every file this bind carries, from
    /// the very same source file. Source identity is the point: a rule pointing at
    /// a DIFFERENT file at the same target means the mount is shadowing content
    /// the engine would otherwise serve, which is not redundant at all.
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

/// The verdict for one foreign mount. Split out of `survey` so it can be tested
/// without a /proc to read.
/// `None` means the mount is none of our business — not a report, not an action.
pub(crate) fn classify(
    src: &Path,
    target: &Path,
    skips: &[String],
    skip_src: &'static str,
    hookers: &HashSet<String>,
    red: &Redundancy,
) -> Option<Disposition> {
    // The target question belongs to mount.rs, not here — see `serve_mode`.
    // An app APK is the exception: serve_mode refuses everything under /data
    // because no ROM partition lives there, but this one path IS servable and is
    // the only /data shape absorb accepts (see `is_app_apk`).
    let mode = if is_app_apk(target) {
        crate::mount::Serve::Inject
    } else {
        crate::mount::serve_mode(target)
    };
    if !is_absorbable(src, target) {
        if !src.starts_with(MODULE_ROOT) {
            // Backed by /data but not by a module. Only interesting if it landed
            // somewhere we would otherwise serve: Android's own storage plumbing
            // binds /data/user -> /data_mirror/... and /data/media ->
            // /mnt/pass_through/..., which is stock, not a module leak, and reporting
            // those as leaks is worse than useless — nine of them drown the real one.
            return matches!(mode, crate::mount::Serve::Inject | crate::mount::Serve::Bind)
                .then_some(Disposition::Leaking(
                    "source is outside /data/adb, so there is no module content to re-serve",
                ));
        }
        // Root-managed content laid over a /data path that is not an app APK. The
        // engine could serve it, but absorb will not guess at arbitrary /data
        // targets; it is still a real mount carrying an /adb/ token in every
        // process's mount table, which is what the mountless posture exists to
        // deny. Say so rather than returning no verdict.
        return Some(Disposition::Leaking(
            "target is on /data and is not an app APK, which absorb does not take over",
        ));
    }
    if let Some(d) = declined_reason_with(src, target, skips, skip_src, hookers) {
        return Some(Disposition::Declined(d));
    }
    // Asked BEFORE serve_mode, because serve_mode answers "can I serve this
    // target?" and the whole point of a redundant bind is that nothing needs
    // serving — the rules are already live. Asked AFTER the declines, so a hook
    // framework stays skipped whatever its content looks like.
    if red.covers(src, target) {
        return Some(Disposition::Redundant);
    }
    Some(match mode {
        crate::mount::Serve::Inject => Disposition::Absorb,
        crate::mount::Serve::Bind => Disposition::Declined(Declined::MustBind),
        crate::mount::Serve::Refuse(why) => Disposition::Leaking(why),
    })
}

/// Every mount whose source is on /data and whose target is not — content some
/// module laid over the ROM, whoever owns it — paired with what absorb will do.
///
/// Deliberately wider than `MODULE_ROOT`: a module is free to bind from
/// /data/local/tmp (custom-certificate-authorities does, off a tmpfs), and that
/// mount is just as visible to an app as one we can convert. Stock ROM overlays
/// never appear here — their source is the partition itself, so `source_of`
/// returns None for them or a path outside /data.
pub fn survey() -> Result<Vec<Surveyed>> {
    survey_of(MOUNTINFO)
}

/// The same survey against any process's mountinfo, so another mount namespace
/// can be inspected the same way our own is.
pub fn survey_of(mountinfo: &str) -> Result<Vec<Surveyed>> {
    let body = std::fs::read_to_string(mountinfo).context("read mountinfo")?;
    let rows = parse_mountinfo(&body);
    let roots = fs_roots(&rows);
    let (skips, skip_src) = skip_list();
    let hookers = hooking_modules(&rows, &roots, &skips);
    // One `nm list` per survey, not per row. An engine that will not answer
    // leaves this empty, which only costs the redundancy shortcut: every mount
    // then classifies exactly as it did before this existed.
    let red = Redundancy::new(&Nm::new().list().unwrap_or_default(), &rows);

    let mut out: Vec<Surveyed> = rows
        .iter()
        .filter_map(|r| {
            let src = source_of(r, &roots)?;
            // Foreign = backed by /data. A target under /data/adb is a module's own
            // scratch space (fbind and friends): not ours. A target elsewhere on
            // /data is only ours when the SOURCE is root-managed content under
            // /data/adb — that is module content laid over a real app path, and it
            // is visible in that app's mount table.
            //
            // Discarding every /data target missed exactly that case. Issue #14 on
            // OP15: a YouTube module binds
            // /data/adb/rvhc/youtube-morphe-<abi>.apk over
            // /data/app/~~<hash>/com.google.android.youtube-<hash>/base.apk. absorb
            // never classified it, doctor never named it, and the Modules pane badged
            // the module "mountless" while it held a live root-managed mount — a
            // detector read /adb/ straight out of the process mount table.
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
    // Deepest target first, so nested mounts come off in the right order.
    out.sort_by_key(|s| std::cmp::Reverse(s.target.components().count()));
    Ok(out)
}

/// A mount we intend to act on: convert it, or — when its content is already
/// injected — simply drop it.
pub struct Candidate {
    pub target: PathBuf,
    pub source: PathBuf,
    /// Unmount only. Injecting would duplicate rules that already exist.
    pub redundant: bool,
}


/// Targets that currently have something mounted on them.
///
/// The mount pass needs this before it injects: adding a rule d_drops the
/// cached dentry for that name, and a mount hangs off a specific
/// (vfsmount, dentry) pair, so injecting over a live mount detaches it from
/// path resolution. umount2 then returns EINVAL — even with MNT_DETACH — and
/// the entry is stuck in mountinfo until reboot, which is the one thing the
/// zero-mount posture exists to prevent. Absorb runs after boot and cannot undo
/// it, so the unmount has to happen before the injection, not after.
/// `None` when the mount table could not be read. NOT an empty set: an empty set
/// means "nothing is mounted anywhere", which is the reading that made the mount
/// pass inject over every live mount and strand each one in mountinfo until
/// reboot while reporting `0 failed`.
pub(crate) fn mounted_targets() -> Option<std::collections::HashSet<PathBuf>> {
    let body = std::fs::read_to_string(MOUNTINFO).ok()?;
    Some(parse_mountinfo(&body).into_iter().map(|r| r.target).collect())
}

/// Targets absorb is currently serving. Read by `reload` so they survive a
/// reconcile, and by `run_mount` so a fresh pass starts from an empty record.
/// (target, source) for every absorbed rule that recorded one.
///
/// The file used to hold bare targets, which was enough for reload's prune guard
/// but not to REBUILD a rule: `run_mount` clears the engine at boot, so an
/// absorbed injection only came back if absorb saw the same bind again. For a
/// patched-APK module that means the module has to mount first every boot -- and
/// the mount is what marks other processes' mappings "(deleted)". Recording the
/// source lets the boot pass re-serve it directly, so the module never needs to
/// mount at all. Lines without a tab are the old format and yield no source.
pub fn absorbed_pairs() -> Vec<(PathBuf, PathBuf)> {
    read_absorbed_pairs().unwrap_or_default()
}

/// `Err` only when the record exists but could not be READ. A missing file is
/// `Ok(empty)`, because "nothing has been absorbed yet" is a real answer.
///
/// `reload`'s prune guard is the one caller that must not confuse the two: this
/// set is the ONLY thing protecting absorbed rules from being deleted, so an
/// unreadable file collapsing to an empty set makes reload drop every absorbed
/// rule and report `-N rules` as if that were the plan.
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

/// Label an APK the Suite serves so the app can actually read it.
///
/// An app runs as untrusted_app and can read `apk_data_file`, not
/// `adb_data_file` -- and everything under /data/adb carries adb_data_file,
/// including a copy we keep there. Serving such a file gives the app a null
/// Resources and it dies in handleBindApplication (measured on OP15:
/// GraphicsEnvironment.queryAngleChoice NPE, twice, once taking the system with
/// it). The label is an xattr and the boot pass relabels /data/adb/nomount, so a
/// hand-applied chcon does not survive: re-assert it every time we serve.
/// Returns whether the label is now correct. The result used to be discarded
/// entirely, so a setxattr that failed (EOPNOTSUPP, EPERM under a restrictive
/// policy, ENOENT on a source that vanished) still went on to `nm.add` and was
/// counted as "re-served" -- and the consequence, per the paragraph above, is the
/// app force-closing or taking the system with it. For a call whose failure is
/// documented as system-crashing, the caller has to be able to decline.
fn label_apk_readable(p: &Path) -> bool {
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()) else { return false };
    let ctx = c"u:object_r:apk_data_file:s0";
    // lsetxattr, not setxattr: `p` comes from absorbed.list, and setxattr FOLLOWS
    // symlinks -- so a symlinked source relabels whatever it points at as
    // apk_data_file. Writing that file needs root today, so this is
    // defence-in-depth, but it costs nothing and the record has no business
    // reaching through a link.
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
            "nomount: could not label {} apk_data_file ({}) - NOT serving it: an app cannot read adb_data_file, and serving it anyway gives a null Resources and a crash in handleBindApplication",
            p.display(),
            std::io::Error::last_os_error()
        );
        return false;
    }
    true
}

/// Re-serve the absorbed APK rules recorded by a previous run.
///
/// Skips a target already served and a source that has gone (module uninstalled),
/// so a stale record cannot resurrect a rule pointing at nothing.
pub fn reapply_absorbed(nm: &Nm) -> u32 {
    reapply_absorbed_pairs(nm, &absorbed_pairs())
}

/// Same, against a record read earlier -- `run_mount` has to snapshot it before it
/// clears the file.
pub fn reapply_absorbed_pairs(nm: &Nm, pairs: &[(PathBuf, PathBuf)]) -> u32 {
    // NOT unwrap_or_default(). This dump IS the "already live" guard, and an empty
    // string disarms it: every recorded pair is re-added, and re-adding a live
    // rule d_drops the dentry and marks the file "(deleted)" in /proc/<pid>/maps
    // for every process that mapped it — which absorb then reports as "re-served
    // N recorded APK rule(s)", i.e. the damage counted as work done. Skip the
    // re-serve instead; the next pass repeats it.
    let Ok(live) = nm.list() else {
        eprintln!(
            "nomount: cannot enumerate live rules - skipping the absorbed-rule re-serve this \
             pass (re-adding blind would d_drop rules that are already live)"
        );
        return 0;
    };
    // One parse, one set. This walked `live.lines()` per pair with its own
    // rsplit_once -- correct, but a fourth reader of a format `crate::nm::parse_list`
    // owns, and O(pairs x lines). The parser also peels ` (public)` and the
    // ` [UID: n]` identity, neither of which this could see.
    let live_targets: HashSet<PathBuf> = crate::nm::parse_list(&live)
        .into_iter()
        .filter(|r| r.kind == crate::nm::LiveKind::Inject)
        .map(|r| r.target)
        .collect();
    let mut n = 0;
    for (target, source) in pairs {
        if !is_app_apk(target) || !source.exists() || !target.exists() {
            continue;
        }
        if live_targets.contains(target) {
            continue;
        }
        // Decline rather than serve an unreadable label. The result was
        // discarded, so a failed relabel still went on to add the rule and count
        // it -- and the documented consequence is the app force-closing, or the
        // system going down with it, behind a "re-served N" success line.
        if !label_apk_readable(source) {
            continue;
        }
        if nm.add(target, source).is_ok() {
            n += 1;
        }
    }
    n
}

/// The absorbed TARGET set, derived from the pairs record (the file is always the
/// tab-separated pairs format now — see H18). `reload`'s prune guard is the only
/// consumer and it needs just the targets.
/// `Err` when the record exists but could not be read — see [`read_absorbed_pairs`].
/// There is deliberately no infallible twin: `reload`'s prune guard is the only
/// caller, and for that caller an empty set on error deletes every absorbed rule
/// on the device.
pub fn read_absorbed_targets() -> std::io::Result<HashSet<PathBuf>> {
    Ok(read_absorbed_pairs()?.into_iter().map(|(t, _)| t).collect())
}

/// Replace the record. `run_mount` calls this with an empty set: it issues
/// `nm clear`, so nothing absorb recorded is live any more and keeping the file
/// would make `reload` protect targets that no longer have a rule.
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
    // ATOMIC, and 0600 by construction. This file is the only record of which
    // patched APK is injected over which package -- the module fingerprint the
    // hiding posture exists to deny, and the input the boot-time re-serve needs --
    // so neither a half-written one nor an inherited 0666 is acceptable.
    // `write_atomic` writes through a fresh temp, which makes the mode a property
    // of the write rather than of the file's history; the `set_permissions` that
    // used to follow (and only ran AFTER the wide window it was fixing) is gone.
    if let Err(e) = crate::statefile::write_atomic(ABSORBED_LIST, &body) {
        eprintln!("nomount: could not record absorbed targets: {e:#}");
    }
}

/// Is anything still mounted here? The authority on whether an unmount worked:
/// umount2 reports EINVAL both for "never a mountpoint" and for "a peer already
/// took it away", and only the second is fine.
pub(crate) fn still_mounted(p: &Path) -> bool {
    std::fs::read_to_string(MOUNTINFO)
        .map(|b| parse_mountinfo(&b).iter().any(|r| r.target == p))
        // FAIL CLOSED. `unwrap_or(false)` said "nothing is mounted here" when the
        // question could not be asked at all -- and every caller reads a `false`
        // as permission to proceed: `unmount_before_serving` serves the target
        // (injecting over a live mount strands it in mountinfo until reboot,
        // which is the exact damage the doc above describes), and the two absorb
        // loops treat a failed umount2 as a stranded peer. "Could not read the
        // mount table" has to mean "assume it is still there", which costs one
        // unserved target and a message, not a permanent leak.
        .unwrap_or(true)
}

/// The path to re-assert rules at. `target` itself when it is servable; otherwise
/// the alias that is -- `/mnt/vendor/my_product/...` cannot carry an injection
/// (`/mnt` is not a ROM partition) but its twin `/my_product/...` can, and they
/// are the same subtree, so serving one serves both.
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
///
/// Only when re-asserting its rules afterwards is safe, and on `my_*` it is not.
/// Dropping the mount alone is not an option either: a rule registered behind a
/// bind is inert until re-added, so an unmount without the re-assert silently
/// reverts the path to the stock file. So `my_*` is reported and left alone --
/// the fix there is to delete the owning module's bind, after which the next
/// boot registers the rule with nothing shadowing it and no runtime re-add is
/// ever needed.
///
/// Measured, not theorised: absorbing the two `/my_product/media/bootanimation`
/// binds on an OP11 (Suite v1.3.22, engine v14) unmounted them, re-added four
/// `my_*` rules in a burst, and the device rebooted mid-command -- clean
/// `sys.boot.reason=reboot`, no tombstone, no crash record. That is the FD
/// allowlist hazard `mount.rs::my_hookless_enabled` says it is trialling.
pub(crate) fn runtime_droppable(target: &Path, aliases: &[(PathBuf, PathBuf)]) -> bool {
    // ANY component, not just the root: the twin of `/my_product/...` is
    // `/mnt/vendor/my_product/...`, whose root is `mnt`. And checked on the
    // target as well as on the servable path, because `serve_mode` only calls a
    // my_* target injectable while the `my_hookless` marker is present — the
    // hazard does not come and go with that marker.
    fn touches_my_partition(p: &Path) -> bool {
        p.components()
            .any(|c| c.as_os_str().to_str().is_some_and(|s| s.starts_with("my_")))
    }
    !touches_my_partition(target) && !touches_my_partition(&servable(target, aliases))
}

pub(crate) fn umount_detach(p: &Path) -> bool {
    // as_encoded_bytes(), NOT to_string_lossy(): a module is free to ship a
    // filename that is not UTF-8, and the lossy form substitutes U+FFFD -- so
    // the syscall would name a DIFFERENT path, the unmount would no-op on
    // ENOENT, and the caller would read an ordinary `false` rather than "this
    // path cannot be represented". The mount stays up and the posture report
    // says it came down. This file already tests paths with an emoji and a tab
    // in them, so odd names are in scope for it.
    let Ok(c) = CString::new(p.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) == 0 }
}

/// Is `target` already serving `source`? Compared by SIZE ALONE.
///
/// mtime is deliberately NOT compared. An injection mirrors the STOCK file's
/// mtime rather than the backing file's -- that is what removes a bind's
/// dev/ino/mtime tell -- so a rule that is serving perfectly still reports a
/// different mtime from its source. Measured on an OP11 carrying 118 rules: 0 of
/// 118 matched on mtime, while 116 of 118 matched on size and the two that did
/// not were the one genuine drift the byte-level sweep also found. Comparing
/// mtime therefore answered "not serving" for every live rule -- the answer that
/// costs a d_drop each time, which is precisely what this function exists to
/// avoid. Same size and different bytes is the residual it cannot see; `check`
/// hashes both ends and still reports that.
///
/// Re-adding a live rule is not free: `nm add` d_drops the cached dentry, and any
/// process that already MAPPED the file keeps the now-unhashed one, which the
/// kernel renders as "…/file (deleted)" in /proc/<pid>/maps ever after. Measured
/// on OP15 with a probe holding an mmap: idle 12s clean, `uid apply` clean,
/// re-adding the same rule flipped it to (deleted). So a re-assert has to be able
/// to tell "listed but not serving" (worth the drop) from "already serving"
/// (pure cost).
fn already_serving(target: &Path, source: &Path) -> bool {
    let (Ok(t), Ok(s)) = (fs::metadata(target), fs::metadata(source)) else { return false };
    t.len() == s.len()
}

/// `nm add`, but guaranteed to re-point a target that already has a rule.
///
/// A plain `add` over a live rule re-points correctly when the target sits in a
/// real ROM directory -- and does NOT when it sits inside a directory the engine
/// materialised itself. Measured on an OP15, engine v26:
///
///     /system/etc/nmt_x.txt      (stock dir)    add A, add B -> serves B
///     /system/etc/nmt/collide    (virtual dir)  add A, add B -> serves A
///
/// The rule table takes the second source either way; only the virtual case
/// keeps serving the first one's bytes. Absorb is exactly where that bites: it
/// unmounts BEFORE injecting (see the note on unmount ordering above), so if the
/// re-point silently does nothing, the content the bind was serving is simply
/// gone for the rest of the session -- no mount, and a rule pointing somewhere
/// it is not actually reading from.
///
/// `del` first sidesteps the whole distinction. It costs one netlink round trip,
/// fails harmlessly when there was no rule, and the APK re-point path in this
/// file has always done it this way.
fn add_repointing(nm: &Nm, target: &Path, source: &Path, live: &LiveMap) -> bool {
    match live.get(target) {
        // Already serving exactly this. Re-issuing would drop and rebuild a
        // correct rule for nothing, and every drop is a window where the path
        // resolves to stock.
        //
        // "The table names this source" is NOT proof the injection is live. A
        // rule added while a bind shadowed the same name is inert until it is
        // added again, and this function is only ever called after absorb has
        // unmounted such a bind -- so trusting the table short-circuits exactly
        // the case the re-assert exists for. Measured on an OP11: both
        // /my_product/media/bootanimation rules were listed, both inert, absorb
        // dropped the bind, re-added neither, reported 0 failed, and the path
        // served the stock file for the rest of the session. Ask the filesystem,
        // not the rule table.
        Some(cur) if cur.as_path() == source && already_serving(target, source) => true,
        Some(prev) => {
            let prev = prev.clone();
            let _ = nm.del(target);
            if nm.add(target, source).is_ok() {
                return true;
            }
            #[allow(clippy::needless_return)]
            // The del already happened and absorb has already unmounted, so
            // doing nothing here leaves the path on stock. Put back what was
            // there; it is stale, but it is content rather than nothing.
            if nm.add(target, &prev).is_ok() {
                eprintln!(
                    "nomount: absorb: could not re-point {} at {} -- restored the previous rule",
                    target.display(),
                    source.display()
                );
            } else {
                eprintln!(
                    "nomount: absorb: {} now has NO rule -- re-point and restore both failed",
                    target.display()
                );
            }
            false
        }
        // No live rule: a bare add cannot destroy anything, and there is no
        // stale dentry to drop because nothing was serving this path.
        None => nm.add(target, source).is_ok(),
    }
}

/// Live `target -> source` for injects, read once per pass.
type LiveMap = std::collections::HashMap<PathBuf, PathBuf>;

/// Snapshot the engine's inject rules. An unreadable list yields an empty map,
/// which degrades `add_repointing` to the bare-add branch -- the pre-session
/// behaviour, which is safe: it cannot delete a rule it does not know about.
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

/// Inject `source` at `target`. A directory bind is expanded to one rule per
/// file rather than a single directory rule: a directory rule REPLACES the stock
/// directory, hiding every entry the module did not ship, which is the same
/// whole-partition masking that bootloops zygote.
///
/// Records each (target, source) pair actually served into `out`, and returns how
/// many adds FAILED.
///
/// Errors are accumulated, not propagated with `?`: the bind is already unmounted
/// by the time this runs, so bailing on the first failed `nm.add` would leave the
/// rest of a directory's files reverted to stock. Serve as much as possible and
/// let the caller report the count. `out` carries the (target, source) PAIRS so
/// the caller can record a directory bind's children -- the old code returned bare
/// child targets and the caller then matched them against the parent candidate,
/// recording nothing for a directory bind (M-S12).
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
/// yields `com.foo`. The trailing `-<hash>` (or `-1` on the old layout) is the
/// install generation, and it is exactly what changes when the app updates.
pub(crate) fn pkg_of_apk_target(target: &Path) -> Option<String> {
    if !is_app_apk(target) {
        return None;
    }
    let dir = target.parent()?.file_name()?.to_str()?;
    let (pkg, _gen) = dir.rsplit_once('-')?;
    // A package name is dotted and never empty; anything else means the layout
    // changed under us and guessing would re-point a rule at the wrong app.
    (!pkg.is_empty() && pkg.contains('.')).then(|| pkg.to_string())
}

/// Where PackageManager says the package lives right now.
///
/// Three outcomes, kept distinct so a caller never mistakes a transient failure
/// for an uninstall: `Err` = pm itself failed (ENOENT on PATH, non-zero exit,
/// binder not up at boot); `Ok(None)` = pm ran and reports the package absent;
/// `Ok(Some)` = the current path. Invoked by absolute path so a stripped PATH in
/// the boot environment does not read as "uninstalled".
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

/// Re-point absorbed APK rules at the app's current path.
///
/// An absorbed rule names `/data/app/~~<hash>==/<pkg>-<hash>==/base.apk`, and both
/// hashes are regenerated when the app updates: the rule then points at a path
/// that no longer exists, so the app silently reverts to the stock APK until the
/// next boot re-absorbs. PackageManager knows the new path, so ask it.
///
/// Returns (repointed, stale) — stale being rules whose package is simply gone
/// (uninstalled), which are dropped rather than re-pointed.
///
/// THE RECORD MOVES WITH THE RULE. Re-pointing the live rule and leaving
/// `absorbed.list` naming the old `/data/app/…` path made this function a
/// one-shot: every reader of the record gates on `target.exists()`
/// (`reapply_absorbed_pairs`, and `run_mount` through it), so from the next boot
/// the stale row was skipped forever and the package silently reverted to the
/// stock APK — with no live rule left for a later pass to find, because the boot
/// `nm clear` had dropped it. That defeats the record's stated purpose in as many
/// words ("the source lets the boot pass re-serve it without waiting for the
/// owning module to mount again"); it only ever kept working for a module that
/// re-binds on every boot, which is the case the record exists to make
/// unnecessary. Dead rows accumulated too, since nothing pruned them.
pub fn refresh_app_apks(nm: &Nm) -> (u32, u32) {
    let (mut repointed, mut stale) = (0u32, 0u32);
    let Ok(list) = nm.list() else { return (0, 0) };
    let mut pm_failed = false;
    // What the record has to be told, collected here and applied once at the end.
    let mut moved: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut dropped: Vec<PathBuf> = Vec::new();
    // `crate::nm::parse_list`, not a fourth hand-rolled reader. This one split on
    // the FIRST ` -> ` and peeled only the ` [UID: n]` suffix -- exactly the drift
    // that parser's doc names as the reason it exists ("one split on the FIRST
    // ` -> `, the others on the last; only one peeled ` (public)`"). The missing
    // `(public)` peel was not cosmetic: it would have left `source` as
    // "…/base.apk (public)", failed `source.exists()`, and dropped the rule
    // through the "package is gone" arm below -- deleting a live rule and counting
    // it as an uninstall. Unreachable only because `is_pm_published()` cannot grant
    // the flag to a /data/app target, which is not a property this function should
    // depend on.
    // One parse, two uses: the walk below, and the live map `add_repointing`
    // needs to know what the destination is currently served from. Building it
    // from the same dump costs nothing and avoids a second `nm list`.
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
            // pm failed (binder not up at boot, non-zero exit): leave the rule
            // alone. Treating this as "uninstalled" and deleting dropped every
            // absorbed APK at once on a transient failure. Log once, not per rule.
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
                // ADD FIRST, then drop the old rule -- and only if the add took.
                //
                // `del` then `add` is what `add_repointing` does for a target that
                // already has a rule, and it is wrong here: the two targets are
                // different paths, so there is nothing to re-point, and a failed
                // add left the package with NO rule at all -- silently, since the
                // status was discarded and `repointed` simply did not increment.
                // `add_repointing`'s own note is the standard this was missing:
                // "doing nothing here leaves the path on stock". The old target no
                // longer exists on disk (that is the precondition for being in
                // this branch), so it cannot be restored either; not destroying it
                // until the replacement is live is the only order that can fail
                // safely.
                if add_repointing(nm, &now, &source, &live) {
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
            // pm answered: the package is gone, or the path is unchanged with no
            // servable source — the rule points at a path that no longer exists, so
            // drop it.
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

/// Carry a re-point (and an uninstall) into the absorbed record.
///
/// `read_absorbed_pairs`, not the infallible twin, and the file is LEFT ALONE on
/// a read error -- the same discipline `run_mount` and `run_absorb` both apply by
/// hand, and for the same reason: `set_absorbed_pairs` truncates before writing,
/// so rewriting from an empty read destroys every patched-APK rule on the device.
fn rewrite_absorbed_after_refresh(moved: &[(PathBuf, PathBuf)], dropped: &[PathBuf]) {
    let all = match read_absorbed_pairs() {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "nomount: could not read {ABSORBED_LIST} ({e}) -- NOT rewriting it, so the \
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

/// Pure half of [`rewrite_absorbed_after_refresh`]: re-aim the rows a re-point
/// moved, drop the rows an uninstall retired, and say whether anything changed.
///
/// Deduplicated on the target, because a partially-completed earlier pass can
/// leave the destination already recorded -- two rows for one target would make
/// the boot pass serve it twice.
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
    pairs.sort();
    pairs.dedup_by(|a, b| a.0 == b.0);
    let changed = pairs != before;
    (pairs, changed)
}

/// ROM partitions a module might try to empty. A tmpfs anywhere under one of
/// these is never stock: measured on OP15, 21 mounts land inside a ROM partition
/// (vfat firmware, ext4 dsp, the OEM's own overlayfs) and not one of them is a
/// tmpfs -- stock keeps those at /dev, /mnt, /apex, /linkerconfig and /tmp.
pub(crate) const ROM_ROOTS: &[&str] =
    &["/system/", "/product/", "/vendor/", "/system_ext/", "/odm/", "/oem/", "/my_"];

/// Is this device number a loop device? `mountinfo` field 3 is `maj:min`, and
/// loop is major 7 on every Linux (`Documentation/admin-guide/devices.txt`).
///
/// This is what identifies a mounted IMAGE. An image is mounted whole, so its
/// mount root is "/" and its device is its own -- neither of the two tests below
/// can see it, which is why the check that claimed to cover "a loop image" could
/// not. The alternative predicate ("its device differs from the partition it sits
/// inside") would have flagged the stock OEM mounts the comment below lists, so
/// the identity of the backing device is what makes this precise instead.
pub(crate) fn is_loop_dev(dev: &str) -> bool {
    dev.split(':').next() == Some("7")
}

/// The foreign-mount rows over the ROM, as (evidence string, is_image) pairs.
///
/// Pure, so the predicate can be tested without a /proc to read -- the same split
/// `classify` uses. Two callers want two slices of the same walk: the check wants
/// every hit, and `run_absorb` wants the images alone, because those are the ones
/// its survey structurally cannot see.
pub(crate) fn foreign_rom_rows(rows: &[MountRow]) -> Vec<(String, bool)> {
    let roots = ROM_ROOTS;
    // maj:min of /data, so a mount served off userdata is recognised by device
    // rather than by the source path (which mountinfo does not carry usefully here).
    let data_dev = rows.iter().find(|r| r.target == Path::new("/data")).map(|r| r.dev.clone());
    let mut hits: Vec<(String, bool)> = Vec::new();
    for r in rows {
        let t = r.target.to_string_lossy();
        if !roots.iter().any(|root| t.starts_with(root)) {
            continue;
        }
        // A bind sourced from /data/adb/modules is a MODULE mount, which is the
        // one thing this check is not about: its own text says "outside the module
        // system" and its owner string says "a mount made outside /data/adb".
        // Both were false for the 85 my_* binds the Suite itself makes, so a stock
        // install reported them here AND in zero-mount posture -- two red rows for
        // one cause, one of them describing the opposite of what happened.
        // zero-mount posture owns module mounts; this owns everything else.
        //
        // mountinfo's root is relative to the source filesystem, so a bind off
        // userdata reads as /adb/modules/... rather than /data/adb/modules/...
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

/// Every foreign-mount hit, evidence only.
pub(crate) fn foreign_rom_mounts(rows: &[MountRow]) -> Vec<String> {
    foreign_rom_rows(rows).into_iter().map(|(h, _)| h).collect()
}

/// Only the mounted IMAGES. `run_absorb` reports these itself: `source_of()`
/// answers None for a whole-filesystem mount, so they never reach `classify()`
/// and never appear in a survey.
pub(crate) fn rom_image_mounts(rows: &[MountRow]) -> Vec<String> {
    foreign_rom_rows(rows).into_iter().filter(|(_, img)| *img).map(|(h, _)| h).collect()
}

/// Is this mountinfo line a tmpfs laid over a ROM path?
///
/// A module that wants a stock directory to look empty mounts an empty tmpfs over
/// it -- the ReVanced installer does exactly this to `/product/app/<App>` from a
/// post-fs-data.d script, so its /data/app copy wins the PackageManager scan. It
/// has no source under /data/adb, so every source-keyed check we have is blind to
/// it while it sits in every process's mountinfo.
pub(crate) fn rom_tmpfs_target(line: &str) -> Option<PathBuf> {
    let (pre, post) = line.split_once(" - ")?;
    if post.split_whitespace().next()? != "tmpfs" {
        return None;
    }
    let target = pre.split_whitespace().nth(4)?;
    ROM_ROOTS.iter().any(|r| target.starts_with(r)).then(|| PathBuf::from(unescape(target)))
}

/// This boot, as the kernel names it. `None` when it cannot be read, which
/// disables expiry rather than guessing: an entry with no stamp is kept.
fn boot_id() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Is this directory empty right now? `None` when it cannot be read at all.
fn dir_is_empty(p: &Path) -> Option<bool> {
    fs::read_dir(p).ok().map(|mut e| e.next().is_none())
}

/// The ROM-tmpfs takeovers on record: target -> the boot in which its tmpfs was
/// last SEEN mounted (empty string when the boot id was unreadable then).
pub(crate) fn absorbed_tmpfs() -> Vec<(PathBuf, String)> {
    fs::read_to_string(ABSORBED_TMPFS_LIST).map(|s| parse_tmpfs_record(&s)).unwrap_or_default()
}

/// Pure: one `<target>\t<boot id>` per line. A line without a tab is read as a
/// target with no stamp, which is never expired -- so a hand-written entry, or
/// one from a build that did not stamp yet, hides until it is removed by hand.
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

/// Just the targets. `reload`'s prune guard needs no more than that.
pub fn absorbed_tmpfs_targets() -> HashSet<PathBuf> {
    absorbed_tmpfs().into_iter().map(|(t, _)| t).collect()
}

/// Does a recorded takeover survive this pass?
///
/// Pure, because the answer is the whole of M-S8's reverse path and getting it
/// wrong in either direction is a visible regression: too eager and the ROM
/// directory fills back in under a module that still empties it every boot, too
/// lazy and the hide is the permanent one this finding is about.
fn tmpfs_entry_lives(seen_now: bool, seen_boot: &str, boot: &str, mounted: bool) -> bool {
    // Seen this pass, still mounted (an opt-out, or an unmount that failed), or
    // last seen in THIS boot -- absorb unmounts the tmpfs itself, so every later
    // pass in the same boot finds it gone and must not read that as an uninstall.
    // An unstamped entry is never expired: a fresh sighting cannot be told from
    // an old one.
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
    // Atomic: this list is what re-applies the ROM-tmpfs whiteouts after the
    // boot pass's `nm clear`, so a truncated one silently un-hides them.
    if let Err(e) = crate::statefile::write_atomic(ABSORBED_TMPFS_LIST, &body) {
        eprintln!("nomount: could not record the ROM tmpfs takeovers: {e:#}");
    }
}

/// Re-apply the recorded ROM-tmpfs whiteouts. Called by the boot pass after
/// `nm clear`, which drops them along with every other rule.
///
/// Deliberately re-applies rather than re-derives: `run_mount` runs at
/// post-fs-data, where a module's own script may not have re-mounted its tmpfs
/// yet, and a mid-session `Re-apply` runs long after absorb already unmounted it.
/// Deciding "the tmpfs is gone for good" from either point would put the stock
/// directory back under a module that still wants it empty. Absorb, which runs
/// after boot_completed, is the only place that can tell -- see
/// `absorb_rom_tmpfs`, which confirms or expires each entry.
pub fn reapply_tmpfs_whiteouts(nm: &Nm) -> u32 {
    let mut n = 0u32;
    for (t, _) in absorbed_tmpfs() {
        // Same gate `whiteout::apply` uses: a hand-edited entry that names a
        // partition root or a /data path must not reach the engine from here.
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

/// What one ROM-tmpfs pass did, in the same buckets `run_absorb` reports the
/// bind survey in -- a tmpfs left mounted is just as visible to an app as a bind
/// is, so it must reach the same summary rather than be quietly dropped.
#[derive(Default)]
struct TmpfsPass {
    /// Emptied mountlessly (or, on a dry run, would be).
    done: u32,
    failed: u32,
    /// Still mounted, still visible, and not by design.
    leaked: u32,
    /// Still mounted on purpose (the opt-out list).
    declined: u32,
}

/// Take over the "make this ROM directory look empty" trick: drop the tmpfs and
/// hide the path with a whiteout instead.
///
/// The whiteout is the mountless equivalent -- the directory reads as absent
/// rather than empty, which is the same answer to a PackageManager scan.
///
/// It is recorded in absorb's OWN list, not appended to the user's durable
/// `whiteouts.txt` (M-S8). That list is re-applied at every boot with nothing
/// that ever prunes it, so a tmpfs takeover was permanent: uninstall the module
/// that mounted it and the ROM directory stayed hidden forever, until the user
/// happened to run `whiteout remove` on a path they never added. Here the record
/// is re-derived from the live mount table each boot instead -- an entry is
/// confirmed while its tmpfs keeps coming back, and expired when it stops -- and
/// `run_mount` re-applies it in between so nothing regresses to stock mid-session.
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
        // The opt-out list applies here too. Converting a tmpfs to a whiteout
        // swaps "directory empty" for "directory absent"; measured on OP15 across
        // several boots those behave the same even for a system app that a
        // /data/app package UPDATES -- YouTube installed, launched and ran with
        // /product/app/YouTube whiteouted. Keep the opt-out anyway: one ROM, one
        // app, and leaving a takeover alone should be a line in absorb-skip.txt
        // rather than a rebuild.
        if is_skipped(Path::new("/"), &target, &skips) {
            println!("skipping the tmpfs over {} (opt-out list)", target.display());
            st.declined += 1;
            continue;
        }
        // OWNERSHIP (M-S8). Every other path in absorb requires the source to be
        // under /data/adb before taking a mount over; this one cannot, because a
        // fresh tmpfs HAS no source -- mountinfo gives it root `/` and device
        // `none`, so `source_of` returns nothing and a source test would either
        // reject every tmpfs (killing the feature) or nothing at all. What can be
        // asserted is the shape of the trick itself: an EMPTY tmpfs over a ROM
        // path means "pretend this directory has no entries", and a whiteout says
        // exactly that. A tmpfs with files in it means the opposite -- the module
        // is SERVING that content -- and converting it would delete the module's
        // own files from view. Say so and leave it mounted.
        let t_str = target.to_string_lossy().into_owned();
        let was_durable = durable.contains(&t_str);
        // Is this takeover already ours, from a previous pass?
        let ours = was_durable || record.iter().any(|(t, _)| *t == target);
        match dir_is_empty(&target) {
            Some(true) => {}
            // Unreadable AND already on one of our records: OUR OWN whiteout is
            // what makes it unreadable. A whiteout d_drops the dentry so the path
            // resolves to ENOENT -- that is the feature -- and `run_mount`
            // re-applies every recorded takeover at post-fs-data. So from the
            // SECOND boot after a takeover this test could never see the directory
            // again, and the leak branch below fired every pass: either the tmpfs
            // was stranded in mountinfo forever (never unmounted, "LEAK" printed
            // on every pass, zero-mount posture broken) or, if it could not mount
            // over the d_dropped path at all, the entry expired and the ROM
            // directory was un-hidden -- giving a 2-boot oscillation where the
            // module's hide is off every other boot. Both silent.
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
        // Drop OUR OWN live rule on the path FIRST. A whiteout there (ours, from a
        // previous pass, re-applied at boot) d_drops the dentry, which detaches the
        // mount from path resolution -- umount2 then cannot find the mountpoint and
        // the tmpfs is stranded until reboot. Same trap the inject-over-a-mountpoint
        // comment below describes, reached from the other direction. Measured on
        // OP15: with the whiteout already applied, every absorb reported "1 failed"
        // and the tmpfs never went away.
        //
        // Scoped to rules absorb itself created (M-S8): this used to be an
        // unconditional `nm del`, which would just as happily drop a rule another
        // module legitimately owns at that path. Ours are the ones on one of the two
        // records -- absorb's own list, or the durable list an older Suite wrote
        // this very takeover into.
        if ours {
            let _ = nm.del(&target);
        }
        if !umount_detach(&target) && still_mounted(&target) {
            eprintln!("nomount: cannot unmount the tmpfs over {}", target.display());
            st.failed += 1;
            continue;
        }
        // Hand over a takeover an older Suite wrote into the user's durable list:
        // that list is re-applied at every boot with nothing that ever prunes it,
        // which is the permanent hide this finding is about. Done AFTER the unmount
        // succeeded, so a takeover that fails half-way leaves the old record intact.
        // The hide itself is re-applied a few lines down and recorded in absorb's
        // list instead, so from now on it expires with the tmpfs.
        if was_durable {
            println!(
                "moving {t_str} out of whiteouts.txt into absorb's own list: it came from a \
                 tmpfs, so it should stop hiding when that tmpfs does"
            );
            let _ = crate::whiteout::remove(&t_str);
        }
        // `whiteout::add` is no longer the right door -- it writes the durable
        // list. Its validation is, though: it is what refuses a partition root
        // (`/my_product` matches ROM_ROOTS on its own) and any `..`.
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
    // EXPIRY -- the reverse path the durable list never had. Absorb runs from
    // service.sh after boot_completed, so every module's post-fs-data script has
    // had its chance: a recorded target with no tmpfs over it, last seen in an
    // EARLIER boot, belongs to a module that no longer asks for it (uninstalled,
    // or the trick dropped). Drop the whiteout and the record, and the ROM
    // directory comes back on its own.
    //
    // Keyed on the boot id rather than on "is it mounted right now", because
    // absorb unmounts the tmpfs itself: every later pass in the SAME boot (the
    // late pass, uidwatch) sees it gone, and expiring there would unhide a
    // directory the owning module is still emptying every boot. An entry with no
    // stamp at all is never expired -- we cannot tell a fresh sighting from an
    // old one.
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

/// `nomount absorb [--dry-run]`.
///
/// `early` is the post-fs-data pass. See `Commands::Absorb::early`: it exists
/// solely to widen what may be taken over to include `my_*` targets, and nothing
/// else about the run changes. Deliberately NOT pushed down into
/// `disposition_of`, so `survey()` -- and therefore doctor and the WebUI -- keep
/// describing each mount the same way whoever is asking; only the ACTION is
/// phase-dependent, and a mount this pass defers is reported as deferred rather
/// than silently dropped from the count.
pub fn run_absorb(dry_run: bool, include_dirs: bool, early: bool) -> Result<()> {
    // Serialise against a concurrent mount/reload (M-S9): those clear and rebuild
    // the engine, and absorb unmounts and re-adds rules -- interleaving the two
    // corrupts both. A dry run changes nothing, so it needs no lock.
    let _pass = if dry_run { None } else { crate::mount::pass_lock() };
    let nm = Nm::new();
    nm.version()
        .context("hookless NoMount engine not responding")?;

    // Report the whole picture BEFORE acting, so a mount absorb cannot take is
    // never implied to be absent. "Nothing to absorb" and "nothing is mounted"
    // are different claims and only the second one is the posture.
    // Before surveying: a rule pointing at an APK path the app has moved away from
    // is not a mount, so the survey would never see it, and the app would sit on
    // the stock APK until a reboot. Cheap when there are none (no absorbed APK
    // rules means no work).
    if !dry_run {
        // Re-serve what a previous run recorded. This runs from service.sh AFTER
        // boot_completed, which is the timing that works: the same rule applied at
        // post-fs-data, before PackageManager scans, corrupts the package (null
        // Resources, then a system crash -- see mount.rs). Post-boot it is exactly
        // what absorb itself does when it takes a bind over, so a module that no
        // longer mounts (or is uninstalled) still gets its content served.
        let reserved = reapply_absorbed(&nm);
        if reserved > 0 {
            println!("re-served {reserved} recorded APK rule(s)");
        }
        let (repointed, stale) = refresh_app_apks(&nm);
        if repointed > 0 || stale > 0 {
            println!("refreshed {repointed} app APK rule(s), dropped {stale} for an uninstalled app");
        }
    }
    // A tmpfs over the ROM is not module content laid over a path, so the survey
    // (which keys on the source) never sees it. Handle it first: it is the loudest
    // mount of the lot and the one no source-keyed check ever reported.
    let tmpfs = absorb_rom_tmpfs(dry_run);
    let surveyed = survey()?;
    // Same mountinfo the survey classified from, so a redundant target resolves
    // to the same servable twin here as it did there.
    let aliases = std::fs::read_to_string(MOUNTINFO)
        .map(|b| mount_aliases(&parse_mountinfo(&b)))
        .unwrap_or_default();
    // Seeded from the tmpfs pass: a tmpfs absorb would not convert is still a
    // mount over the ROM, and the "posture clean" line below must not be reachable
    // while one is up.
    // tmpfs.failed belongs in `leaking` too. The only way to reach it while the
    // tmpfs is still UP is the `umount_detach && still_mounted` branch in
    // absorb_rom_tmpfs — i.e. exactly a foreign mount that survived. Leaving it
    // out let the summary print "0 ROM tmpfs emptied mountlessly (1 failed)" and
    // then, as its FINAL line, "nothing mounted over the ROM (posture clean)"
    // about a mount sitting in every process's mountinfo. The other two failure
    // modes there have already unmounted, so counting all of tmpfs.failed here can
    // at worst over-report a leak, which is the safe direction for this line.
    let (mut leaking, mut declined) = (tmpfs.leaked + tmpfs.failed, tmpfs.declined);
    // ...and from the mount table directly, for the one shape the SURVEY cannot
    // see at all. `source_of()` answers None for a whole-filesystem mount (root
    // "/"), so an IMAGE mounted over a ROM path -- `mount -o loop x.img
    // /product/app/Foo` -- never reaches `classify()` and never appears in
    // `surveyed`. Absorb cannot take one over either: there is no per-file source
    // under /data/adb to re-serve it from, which is why this only counts. But it
    // is a mount over the ROM in every app's mountinfo, and the "posture clean"
    // line below is a claim about mountinfo, not about how much absorb converted.
    let imaged: Vec<String> = std::fs::read_to_string(MOUNTINFO)
        .map(|b| rom_image_mounts(&parse_mountinfo(&b)))
        .unwrap_or_default();
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
            // Still a foreign mount at the end of the run, so it counts as one.
            Disposition::Redundant => {
                leaking += 1;
                eprintln!(
                    "nomount: LEAK {} <- {} is redundant (its content is already injected) but stays mounted: re-asserting a my_* rule at runtime has rebooted a device, and unmounting without that re-assert reverts the path to the stock file. Delete the bind from the owning module's post-fs-data.sh instead -- the next boot then serves it by injection with nothing to absorb",
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

    // Same reasoning as the leak bucket: something we cannot act on still has to
    // be said, or the summary line below overstates what absorb achieved.
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

    // `runtime_droppable` is exactly the "does this touch a my_* partition"
    // question, so it is the gate for BOTH dispositions here -- reused rather
    // than restated, so the two can never drift apart.
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
    // Say what was put off, and until when. A my_* mount that this pass will not
    // touch is not "left by design" -- the early pass CAN take it -- so reporting
    // it in the declined bucket would be a different claim from the true one.
    if deferred > 0 {
        println!(
            "nomount absorb: {deferred} my_* mount(s) deferred to the pre-zygote pass \
             (absorbing them on a live system has rebooted a device); they are taken at the \
             next boot if the my_hookless trial is enabled"
        );
    }
    if cands.is_empty() {
        // A ROM tmpfs is taken over above, not through the candidate list, so say
        // so here -- otherwise a run that emptied one still reported "nothing to
        // absorb", which reads as "we did nothing".
        if tmpfs.done > 0 || tmpfs.failed > 0 {
            println!(
                "nomount absorb: {} ROM tmpfs emptied mountlessly ({} failed)",
                tmpfs.done, tmpfs.failed
            );
        }
        // "Nothing to absorb" is not "nothing is mounted". A declined mount is
        // still a mount and still visible to an app, so only claim a clean
        // posture when mountinfo genuinely holds no foreign mount at all.
        match (leaking, declined) {
            (0, 0) => println!("nomount absorb: nothing mounted over the ROM (posture clean)"),
            (0, d) => println!(
                "nomount absorb: nothing to absorb; {d} mount(s) left by design and still visible"
            ),
            (n, d) => println!(
                "nomount absorb: nothing to absorb, but {n} foreign mount(s) remain, \
                 plus {d} more left by design — the posture is NOT clean"
            ),
        }
        return Ok(());
    }

    let (mut done, mut failed, mut skipped_dirs) = (0u32, 0u32, 0u32);
    let mut dropped = 0u32;
    // One re-assert per servable target: the same rules are reachable from both
    // mountpoints of a propagated bind, and re-adding them twice in a burst is
    // exactly what preceded the reboot this path now avoids on my_*.
    // One snapshot for the whole pass: add_repointing needs to know what a
    // target is currently served from before it drops anything.
    let live_map = live_injects(&nm);
    let mut reasserted: HashSet<PathBuf> = HashSet::new();
    // Recorded so `reload` does not prune them: an absorbed rule is not in any
    // module plan, and the reconcile drops whatever the plan does not name. Held
    // as (target, source) pairs so a directory bind's children are recorded too.
    let mut fresh: Vec<(PathBuf, PathBuf)> = Vec::new();
    for c in &cands {
        // Apply the same directory rule the real run uses, so a dry run can never
        // promise an action the real run would decline.
        let is_dir_bind = c.source.is_dir();
        // A redundant bind skips the directory guard: that guard exists because
        // absorb would have to snapshot a listing, and here it creates nothing.
        // The rules covering this content are the module plan's, so `reload`
        // keeps them current instead of freezing today's listing.
        if c.redundant {
            if dry_run {
                println!(
                    "would DROP redundant mount {} <- {}",
                    c.target.display(),
                    c.source.display()
                );
                dropped += 1;
                continue;
            }
            // A peer of an already-dropped mount is gone too: one `mount --bind`
            // under shared propagation appears once per mountpoint, so unmounting
            // either takes both. umount2 then fails on the second with EINVAL,
            // which is success, not failure -- ask mountinfo, not errno.
            if !umount_detach(&c.target) && still_mounted(&c.target) {
                eprintln!(
                    "nomount: cannot unmount redundant {} - leaving it alone",
                    c.target.display()
                );
                failed += 1;
                continue;
            }
            dropped += 1;
            // Re-issue the rules even though `nm list` already has them. A rule
            // added while a bind shadowed the same name never took effect: the
            // engine hangs its injection off a dentry the mount had already
            // claimed, so the path kept resolving to the stock file and only
            // started serving module content when the rule was added again.
            // Measured on an OP11: after the unmount, the target still read the
            // ROM's bootanimation.zip until `nm add` was repeated verbatim.
            // Idempotent, so re-adding a rule that IS live costs nothing.
            let at = servable(&c.target, &aliases);
            if !reasserted.insert(at.clone()) {
                continue;
            }
            // No `already_serving` guard here: `c.source` is usually a
            // DIRECTORY, and one directory's own size says nothing about the
            // files inside it -- on the OP11 pair it compared 106 against 3440
            // and answered "not serving" for content that was half correct. The
            // check that matters is per file, and it lives in `add_repointing`,
            // which is the only place holding the two files a rule names.
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
                    "would SKIP directory bind {} <- {} (needs --include-dirs)",
                    c.target.display(), c.source.display()
                );
                skipped_dirs += 1;
            } else {
                println!("would absorb {} <- {}", c.target.display(), c.source.display());
            }
            continue;
        }
        // A DIRECTORY bind becomes one rule per file -- a static snapshot of the
        // listing as it is right now. Anything the owning module adds to that
        // directory later would simply never appear, and unlike a file bind we
        // cannot tell whether it intends to. Opt-in only.
        if is_dir_bind && !include_dirs {
            println!(
                "skipping directory bind {} <- {} (use --include-dirs; injection would \
                 snapshot the listing and miss files added later)",
                c.target.display(), c.source.display()
            );
            skipped_dirs += 1;
            continue;
        }
        // Unmount FIRST, then inject. Inject-first looks safer (the mount shadows
        // the injection, so content is never absent) but is actually fatal: adding
        // a rule d_drops the cached dentry for that name, and a mount hangs off a
        // specific (vfsmount, dentry) pair. Dropping it detaches the mount from
        // path resolution, so umount2() then returns EINVAL -- the path is no
        // longer a mountpoint -- and the entry is stranded in mountinfo until
        // reboot while the content silently reverts to the file underneath.
        // Verified on-device against LSPosed's dex2oat bind.
        //
        // Unmounting first costs a brief window where the stock file shows
        // through. That is strictly better than an unremovable mount, and it also
        // means nm_alloc_rule mirrors metadata from the REAL stock file rather
        // than through the bind -- which is what makes absorption remove the
        // bind's dev/ino/mtime tell instead of preserving it.
        // ...and CONFIRM against mountinfo, like the redundant branch above and
        // the tmpfs pass both already do. umount2 reports EINVAL both for "never a
        // mountpoint" and for "a peer already took it away", and only the second
        // is fine — so the main path, the one place that trusted umount2 alone,
        // printed "cannot unmount X" and then SKIPPED the inject for a mount that
        // was already gone. A false failure and content genuinely left unserved,
        // which the deepest-first sort makes routine on a multi-mountpoint tree.
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
    // Written even when nothing was absorbed this run: a partially-failed inject
    // still created rules, and those are exactly the ones reload must not drop.
    // `fresh` already carries the (target, source) pairs -- including a directory
    // bind's children, which the old parent-matching filter dropped (M-S12).
    let rules = fresh.len() as u32;
    let fresh_pairs: Vec<(PathBuf, PathBuf)> = fresh;
    // Written unconditionally, and ONLY in the tab-separated pairs format:
    // `set_absorbed` used to run right after this and rewrite absorbed.list in the
    // legacy bare-target form, so `absorbed_pairs()` (which requires a tab) came
    // back empty forever and the APK re-serve feature was dead (H18).
    //
    // `read_absorbed_pairs`, NOT `absorbed_pairs()`. The infallible twin is
    // unwrap_or_default, so a record that exists but cannot be READ collapsed to
    // an empty Vec here -- and `set_absorbed_pairs` truncates before writing, so
    // one pass over an unreadable file destroyed every patched-APK rule on the
    // device, permanently, and reported the run as a success. `run_mount` refuses
    // exactly this by hand, with the note "rewriting it from an empty read would
    // lose every patched-APK rule for good"; the same call in this file did not.
    //
    // On a read error, leave the file ALONE. The cost is that this pass's fresh
    // rules go unrecorded until the next successful one, so a `reload` in between
    // may prune them -- recoverable, and the next absorb re-creates them. Losing
    // the file is not recoverable at all.
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

    // A leak is worth restating in the summary line: the per-mount notice above
    // scrolls away, and "12 absorbed" reads like success on its own.
    let leaks = if leaking > 0 {
        format!(", {leaking} NOT absorbed and still mounted")
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

    /// The record has to follow the rule. Leaving it on the old `/data/app/…`
    /// path made every reader skip it forever (they all gate on `target.exists()`),
    /// so the patched APK stopped being re-served at boot and the row could never
    /// be repaired -- there was no live rule left for a later pass to find.
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

    /// A partially-completed earlier pass can leave the destination already
    /// recorded. Two rows for one target would have the boot pass serve it twice.
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

    /// Nothing to say means nothing is written: `set_absorbed_pairs` truncates
    /// before it writes, so a needless rewrite is a needless window.
    #[test]
    fn a_refresh_that_moved_nothing_reports_no_change() {
        let p = vec![(PathBuf::from("/data/app/~~a==/com.foo-a==/base.apk"), PathBuf::from("/x"))];
        let (_, changed) = apply_apk_refresh(p, &[], &[]);
        assert!(!changed);
    }

    // The real row this was derived from, captured on-device from a file bind.
    const SAMPLE: &str = "\
205 1 254:78 / /data rw,nosuid,nodev,noatime shared:2 - f2fs /dev/block/dm-78 rw
10222 205 254:78 /local/tmp/bt/src/f /data/local/tmp/bt/dst/f rw,noatime shared:60 - f2fs /dev/block/dm-78 rw
900 205 254:78 /adb/modules/foo/system/bin/x /system/bin/x rw,noatime shared:9 - f2fs /dev/block/dm-78 rw
35 1 0:35 / /product ro,noatime - erofs /dev/block/dm-25 ro";

    /// Issue #14: a ReVanced module binds its patched APK over the installed app
    /// from its own service.sh. That target is on /data, which absorb used to
    /// refuse outright, so the Suite reported a clean posture while the bind sat
    /// in every process's mount table.
    /// An app update regenerates both hashes in
    /// /data/app/~~<hash>==/<pkg>-<hash>==/base.apk, so an absorbed rule has to be
    /// re-pointed by package name rather than by remembering the old path.
    /// The ReVanced installer empties the stock system-app dir with a tmpfs from a
    /// post-fs-data.d script. It has no source under /data/adb, so every
    /// source-keyed check missed it while it sat in every process's mountinfo.
    #[test]
    fn a_tmpfs_over_the_rom_is_recognised() {
        let line = "359 149 0:129 / /product/app/YouTube rw,relatime shared:77 - tmpfs none rw,seclabel";
        assert_eq!(rom_tmpfs_target(line).as_deref(), Some(Path::new("/product/app/YouTube")));
    }

    /// M-S8: the record is absorb's own, keyed on the boot in which the tmpfs was
    /// last seen, so an entry can expire. Lines from an older build carry no stamp.
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

    /// The expiry rule, which is the whole reverse path M-S8 asked for -- and the
    /// regression it must not cause: absorb unmounts the tmpfs itself, so a second
    /// pass in the SAME boot always finds it gone and must keep hiding anyway.
    #[test]
    fn a_takeover_expires_only_after_a_boot_without_its_tmpfs() {
        // Seen in this very pass.
        assert!(tmpfs_entry_lives(true, "old-boot", "this-boot", false));
        // Not seen now, but seen earlier in THIS boot: absorb's own unmount.
        assert!(tmpfs_entry_lives(false, "this-boot", "this-boot", false));
        // Still mounted (opt-out, or an unmount that failed): not ours to expire.
        assert!(tmpfs_entry_lives(false, "old-boot", "this-boot", true));
        // Unstamped: kept, because an old sighting cannot be told from a new one.
        assert!(tmpfs_entry_lives(false, "", "this-boot", false));
        // The one case that expires: a whole boot went by with no tmpfs there, so
        // the module that wanted the directory empty is gone.
        assert!(!tmpfs_entry_lives(false, "old-boot", "this-boot", false));
    }

    /// `/my_` is a ROM_ROOTS prefix, so a tmpfs mounted on the PARTITION ROOT
    /// itself is recognised -- and must then be refused, because hiding a whole
    /// partition is the forkSystemServer abort every other guard here exists for.
    /// `whiteout::validate` is that refusal, which is why the takeover still calls
    /// it now that it no longer goes through `whiteout::add`.
    #[test]
    fn a_tmpfs_over_a_partition_root_is_recognised_but_never_hidden() {
        let line = "360 149 0:130 / /my_product rw,relatime shared:78 - tmpfs none rw,seclabel";
        assert_eq!(rom_tmpfs_target(line).as_deref(), Some(Path::new("/my_product")));
        assert!(crate::whiteout::validate("/my_product").is_err());
        assert!(crate::whiteout::validate("/product/app/YouTube").is_ok());
    }

    /// Stock tmpfs mounts live outside the ROM partitions, and real filesystems
    /// inside them (firmware vfat, dsp ext4, the OEM's overlayfs) are not ours.
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

    /// Guessing a package from a path that is not an app APK, or from a directory
    /// with no generation suffix, would re-point a live rule at the wrong file.
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

    /// The gate stays shut for everything else under /data: a wrong take-over
    /// there costs an app its data, not a ROM file that can be re-served.
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
        // field 4 is fs-relative: /adb/... must resolve against /data, not /
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
        // The same hook, installed under three different fork ids.
        let tgt = Path::new("/apex/com.android.art/bin/dex2oat64");
        let key: Vec<String> = vec!["/apex/com.android.art/bin/dex2oat".into()];
        for id in ["zygisk_lsposed", "zygisk_lsposed_next", "lsposed", "some_new_fork"] {
            let src = PathBuf::from(format!("/data/adb/modules/{id}/bin/dex2oat"));
            assert!(is_skipped(&src, tgt, &key), "path key must cover fork id {id}");
        }
        // An id key, by contrast, only ever covers the one id it names.
        let idkey: Vec<String> = vec!["zygisk_lsposed".into()];
        let other = PathBuf::from("/data/adb/modules/zygisk_lsposed_next/bin/dex2oat");
        assert!(!is_skipped(&other, tgt, &idkey), "id key cannot cover a renamed fork");
    }

    #[test]
    fn builtin_covers_every_dex2oat_path_vector_hooks() {
        // The exact set from JingMatrix/Vector's Dex2OatServer.kt.
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
        // and does not over-reach
        assert!(!is_skipped(&src, Path::new("/product/etc/foo.xml"), &builtins));
    }

    /// Real modules, real failures. SystemlessDebloater binds its dummy.apk over
    /// stock APKs — on a OnePlus those live on my_*, where an injection bootloops
    /// zygote. custom-certificate-authorities binds a /data/local/tmp tmpfs over
    /// the cacerts apex. Absorb used to accept all three.
    #[test]
    fn a_target_mount_rs_would_not_inject_is_never_absorbed() {
        let none: Vec<String> = vec![];
        let modsrc = PathBuf::from("/data/adb/modules/SystemlessDebloater/dummy.apk");

        // my_* -> mount.rs serves these with a real bind, so absorb must decline.
        assert!(matches!(
            classify(&modsrc, Path::new("/my_product/app/Foo/Foo.apk"), &none, "test", &HashSet::new(), &Redundancy::default()).unwrap(),
            Disposition::Declined(Declined::MustBind)
        ));
        // apex is in NON_PARTITION_ROOTS: not ours to serve at all.
        assert!(matches!(
            classify(&modsrc, Path::new("/apex/com.android.conscrypt/cacerts"), &none, "test", &HashSet::new(), &Redundancy::default()).unwrap(),
            Disposition::Leaking(_)
        ));
        // A bare partition root would mask the whole partition.
        assert!(matches!(
            classify(&modsrc, Path::new("/product"), &none, "test", &HashSet::new(), &Redundancy::default()).unwrap(),
            Disposition::Leaking(_)
        ));
        // …and an ordinary ROM path still absorbs.
        assert!(matches!(
            classify(&modsrc, Path::new("/system/app/Foo/Foo.apk"), &none, "test", &HashSet::new(), &Redundancy::default()).unwrap(),
            Disposition::Absorb
        ));
    }

    /// Issue #14: a YouTube module binds its patched APK straight over the installed
    /// one -- source root-managed under /data/adb, target a real app path on /data.
    /// Every /data target used to be discarded as "module scratch space", so nobody
    /// surveyed it: absorb ignored it, doctor never named it, and the Modules pane
    /// badged the module mountless while a detector read /adb/ out of the process
    /// mount table.
    ///
    /// It was reported as an unfixable leak on the premise that hookless cannot
    /// serve /data. That premise was wrong -- measured on OP15, a rule over a /data
    /// file serves correctly and creates no mount -- so this is now ABSORBED: the
    /// APK is re-served as an injection and the bind goes away.
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

        // The neighbouring cases must not change: a module's own scratch space on
        // /data/adb stays unreported, and so does a non-module /data source.
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
        // custom-certificate-authorities: `mount --bind /data/local/tmp/custom-ca-copy
        // /system/etc/security/cacerts`. Absorb cannot re-serve a tmpfs it does not
        // own, but staying quiet about it is what made the posture claim false.
        let d = classify(
            Path::new("/data/local/tmp/custom-ca-copy"),
            Path::new("/system/etc/security/cacerts"),
            &[],
            "test",
            &HashSet::new(),
            &Redundancy::default(),
        );
        assert!(matches!(d, Some(Disposition::Leaking(_))), "must be reported as a leak");

        // But Android's OWN storage plumbing is not a module leak: it binds
        // /data/user -> /data_mirror/... and /data/media -> /mnt/pass_through/...
        // Nine of these on a stock OP15 buried the one that mattered.
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
        // Ordering matters: a framework mount onto an injectable target must be
        // declined for being a framework, not silently absorbed.
        let src = PathBuf::from("/data/adb/modules/anything/bin/dex2oat");
        let builtins: Vec<String> = BUILTIN_SKIPS.iter().map(|s| s.to_string()).collect();
        assert!(matches!(
            classify(&src, Path::new("/system/bin/app_process64"), &builtins, "built-in", &HashSet::new(), &Redundancy::default()).unwrap(),
            Disposition::Declined(Declined::Listed(_))
        ));
    }

    /// FINDING-2, the case marker-detection cannot reach: a framework that ships
    /// none of the known files (ReZygisk's `machikado.arm64`, Zygisk Next's
    /// `mazoku`) but still binds dex2oat. Identifying it by that target must then
    /// protect the ORDINARY mount it also owns.
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

        // Its unrelated mount is spared...
        let d = classify(
            Path::new("/data/adb/modules/obfuscated_fw/system/etc/f"),
            Path::new("/system/etc/f"),
            &builtins,
            "test",
            &hookers,
            &Redundancy::default(),
        );
        assert!(matches!(d, Some(Disposition::Declined(Declined::HooksElsewhere(_)))));

        // ...while an ordinary module's identical-shaped mount still absorbs.
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

    /// Two mountpoints of one filesystem subtree are the same content. OnePlus
    /// mounts `254:34 /` at both `/my_product` and `/mnt/vendor/my_product`, which
    /// is why a single `mount --bind` there shows up twice in mountinfo.
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
        // Both directions, so either path can be the one absorb was handed.
        assert!(a.contains(&(
            PathBuf::from("/my_product"),
            PathBuf::from("/mnt/vendor/my_product")
        )));
        // A lone mountpoint is nobody's alias.
        assert!(!a.iter().any(|(x, _)| x == Path::new("/data")));
    }

    /// A per-UID rule serves one UID. Dropping a global mount because of one
    /// would expose the stock file to every other UID.
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

    /// The case this exists for: a module still bind-mounts a directory whose
    /// files NoMount is already injecting, and the bind propagated to a second
    /// mountpoint that `serve_mode` refuses (`/mnt/...`). Both are redundant.
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
        // The twin absorb calls "not a ROM partition": same subtree, so the rules
        // that cover the servable path cover this one too.
        assert!(red.covers(&src, Path::new("/mnt/vendor/my_product/media/bootanimation")));

        // One file not covered is enough to disqualify the whole bind: dropping it
        // would expose the stock file underneath that one name.
        std::fs::write(src.join("extra.zip"), b"x").unwrap();
        assert!(!red.covers(&src, Path::new("/my_product/media/bootanimation")));
    }

    /// A rule at the right target but pointing at a DIFFERENT file means the mount
    /// is shadowing content the engine would otherwise serve — the opposite of
    /// redundant, and unmounting it would change what apps read.
    #[test]
    fn a_rule_from_another_source_does_not_make_a_bind_redundant() {
        let d = tempfile::tempdir().unwrap();
        let src = d.path().join("f");
        std::fs::write(&src, b"x").unwrap();
        let red = Redundancy::new("/system/etc/f -> /data/adb/modules/other/system/etc/f", &[]);
        assert!(!red.covers(&src, Path::new("/system/etc/f")));
        // ...and with the rule naming this very file, it is.
        let red = Redundancy::new(&format!("/system/etc/f -> {}", src.display()), &[]);
        assert!(red.covers(&src, Path::new("/system/etc/f")));
    }

    /// An empty directory proves nothing, and a missing source proves nothing.
    #[test]
    fn nothing_to_prove_is_not_redundant() {
        let d = tempfile::tempdir().unwrap();
        let empty = d.path().join("empty");
        std::fs::create_dir_all(&empty).unwrap();
        let red = Redundancy::new("/system/etc/x -> /whatever", &[]);
        assert!(!red.covers(&empty, Path::new("/system/etc/x")));
        assert!(!red.covers(&d.path().join("missing"), Path::new("/system/etc/x")));
    }

    /// Whether a target is serving its source is judged on SIZE, not mtime. An
    /// injection mirrors the stock file's mtime on purpose, so a rule that serves
    /// perfectly still reports a different mtime from the file it serves --
    /// measured on an OP11, where 0 of 118 live rules matched on mtime and 116
    /// matched on size. An mtime comparison would call every one of them "not
    /// serving" and re-issue it, which is the d_drop this guard exists to avoid.
    #[test]
    fn serving_is_judged_on_size_not_mtime() {
        let d = tempfile::tempdir().unwrap();
        let served = d.path().join("served");
        let source = d.path().join("source");
        std::fs::write(&served, b"1234").unwrap();
        std::fs::write(&source, b"1234").unwrap();
        // Push the source's mtime far from the served file's, the way an
        // injection that mirrors stock metadata leaves them.
        let c = std::ffi::CString::new(source.to_str().unwrap()).unwrap();
        let times = libc::utimbuf { actime: 1_000_000, modtime: 1_000_000 };
        assert_eq!(unsafe { libc::utime(c.as_ptr(), &times) }, 0);
        assert!(already_serving(&served, &source));
        // A size difference is the drift this must still catch: it is what a
        // dropped bind leaves behind when the rule underneath never took effect.
        std::fs::write(&served, b"12345").unwrap();
        assert!(!already_serving(&served, &source));
        // Nothing to compare is not "serving".
        assert!(!already_serving(&d.path().join("gone"), &source));
    }

    /// A redundant bind is only actionable while Android runs if re-asserting its
    /// rules afterwards is safe. On `my_*` it is not, so it is reported instead.
    #[test]
    fn my_partitions_are_never_dropped_at_runtime() {
        let aliases = vec![(
            PathBuf::from("/mnt/vendor/my_product"),
            PathBuf::from("/my_product"),
        )];
        // Both the servable path and its /mnt twin resolve to a my_* rule.
        assert!(!runtime_droppable(Path::new("/my_product/media/bootanimation"), &aliases));
        assert!(!runtime_droppable(
            Path::new("/mnt/vendor/my_product/media/bootanimation"),
            &aliases
        ));
        // An ordinary partition stays actionable.
        assert!(runtime_droppable(Path::new("/system/etc/f"), &aliases));
        assert!(runtime_droppable(Path::new("/product/media/x.zip"), &[]));
    }

    /// `/mnt/...` cannot carry an injection, but its same-subtree twin can, and
    /// that is where the rules have to be re-asserted.
    #[test]
    fn the_servable_twin_is_where_rules_land() {
        // Deliberately not a my_* pair: `serve_mode` only treats my_* as injectable
        // while the `my_hookless` marker exists, which is a property of the device
        // under test, not of this function.
        let aliases = vec![
            (PathBuf::from("/mnt/vendor/product"), PathBuf::from("/product")),
            (PathBuf::from("/product"), PathBuf::from("/mnt/vendor/product")),
        ];
        assert_eq!(
            servable(Path::new("/mnt/vendor/product/media/b"), &aliases),
            PathBuf::from("/product/media/b")
        );
        // Already servable: unchanged.
        assert_eq!(
            servable(Path::new("/system/etc/f"), &aliases),
            PathBuf::from("/system/etc/f")
        );
        // No alias to fall back on: returned as-is, and the caller's
        // runtime_droppable/serve_mode checks still refuse it.
        assert_eq!(
            servable(Path::new("/mnt/vendor/other/f"), &aliases),
            PathBuf::from("/mnt/vendor/other/f")
        );
    }

    /// The built-ins are a floor the skip file cannot lower.
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

    /// A non-ASCII path that ALSO contains an escape must survive intact.
    ///
    /// Both are needed to reproduce: without a backslash `unescape` returns the
    /// string untouched. With one, the old byte-at-a-time `as char` was Latin-1,
    /// so each byte of a multi-byte character became its own U+00xx and was
    /// re-encoded -- handing umount2() and the injector a path that no longer
    /// names the mount.
    #[test]
    fn unescape_preserves_non_ascii() {
        let rows = parse_mountinfo("1 1 0:1 /caf\u{e9}\\040mod /data/caf\u{e9}\\040mod rw - t s rw");
        assert_eq!(rows[0].root, "/café mod");
        assert_eq!(rows[0].target, PathBuf::from("/data/café mod"));

        // Emoji: 4-byte UTF-8, the worst case for the old code.
        let rows = parse_mountinfo("1 1 0:1 /a\u{1F600}b\\040c /x\u{1F600}y\\040z rw - t s rw");
        assert_eq!(rows[0].root, "/a\u{1F600}b c");
        assert_eq!(rows[0].target, PathBuf::from("/x\u{1F600}y z"));

        // The escapes mountinfo actually emits still decode.
        let rows = parse_mountinfo("1 1 0:1 /a\\011b /c\\012d rw - t s rw");
        assert_eq!(rows[0].root, "/a\tb");
        assert_eq!(rows[0].target, PathBuf::from("/c\nd"));
    }
}
