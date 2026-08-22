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
    for f in [SKIP_FILE, SKIP_FILE_LEGACY] {
        if let Ok(s) = std::fs::read_to_string(f) {
            entries.extend(
                s.lines()
                    .map(|l| l.trim())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .map(str::to_string),
            );
            entries.dedup();
            return (entries, f);
        }
    }
    (entries, "the built-in list")
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

/// Parse `nm list` into uid-0 injections. Mirrors mount.rs `parse_live_rules`,
/// minus the whiteout/virtual-dir kinds, which can never make a bind redundant.
pub(crate) fn live_injections(list: &str) -> HashMap<PathBuf, PathBuf> {
    let mut out = HashMap::new();
    for l in list.lines() {
        // A ` [UID: N]` suffix means the rule is scoped to one UID. Skip it
        // rather than key on it: see the `live` field.
        if l.contains(" [UID:") {
            continue;
        }
        let l = l.trim();
        if l.is_empty() || l.ends_with(" (whiteout)") || l.ends_with(" (virtual dir)") {
            continue;
        }
        // Source is after the LAST ` -> `, so a target containing one survives.
        if let Some((t, src)) = l.rsplit_once(" -> ") {
            out.insert(PathBuf::from(t.trim()), PathBuf::from(src.trim()));
        }
    }
    out
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
pub(crate) fn mounted_targets() -> std::collections::HashSet<PathBuf> {
    let Ok(body) = std::fs::read_to_string(MOUNTINFO) else {
        return Default::default();
    };
    parse_mountinfo(&body).into_iter().map(|r| r.target).collect()
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
    fs::read_to_string(ABSORBED_LIST)
        .map(|s| {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .filter_map(|l| l.split_once('\t'))
                .map(|(t, src)| (PathBuf::from(t), PathBuf::from(src)))
                .collect()
        })
        .unwrap_or_default()
}

/// Re-serve the absorbed APK rules recorded by a previous run.
///
/// Skips a target already served and a source that has gone (module uninstalled),
/// so a stale record cannot resurrect a rule pointing at nothing.
/// Label an APK the Suite serves so the app can actually read it.
///
/// An app runs as untrusted_app and can read `apk_data_file`, not
/// `adb_data_file` -- and everything under /data/adb carries adb_data_file,
/// including a copy we keep there. Serving such a file gives the app a null
/// Resources and it dies in handleBindApplication (measured on OP15:
/// GraphicsEnvironment.queryAngleChoice NPE, twice, once taking the system with
/// it). The label is an xattr and the boot pass relabels /data/adb/nomount, so a
/// hand-applied chcon does not survive: re-assert it every time we serve.
fn label_apk_readable(p: &Path) {
    let Ok(c) = std::ffi::CString::new(p.as_os_str().as_encoded_bytes()) else { return };
    let ctx = c"u:object_r:apk_data_file:s0";
    unsafe {
        libc::setxattr(
            c.as_ptr(),
            c"security.selinux".as_ptr(),
            ctx.as_ptr().cast(),
            ctx.to_bytes_with_nul().len(),
            0,
        );
    }
}

pub fn reapply_absorbed(nm: &Nm) -> u32 {
    reapply_absorbed_pairs(nm, &absorbed_pairs())
}

/// Same, against a record read earlier -- `run_mount` has to snapshot it before it
/// clears the file.
pub fn reapply_absorbed_pairs(nm: &Nm, pairs: &[(PathBuf, PathBuf)]) -> u32 {
    let live = nm.list().unwrap_or_default();
    let mut n = 0;
    for (target, source) in pairs {
        if !is_app_apk(target) || !source.exists() || !target.exists() {
            continue;
        }
        if live.lines().any(|l| l.split(" -> ").next().is_some_and(|t| t.trim() == target.to_string_lossy())) {
            continue;
        }
        label_apk_readable(source);
        let _ = fs::symlink_metadata(target);
        if nm.add(target, source).is_ok() {
            n += 1;
        }
    }
    n
}

pub fn absorbed_targets() -> HashSet<PathBuf> {
    fs::read_to_string(ABSORBED_LIST)
        .map(|s| {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| PathBuf::from(l.split('\t').next().unwrap_or(l)))
                .collect()
        })
        .unwrap_or_default()
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
    if let Err(e) = fs::write(ABSORBED_LIST, &body) {
        eprintln!("nomount: could not record absorbed targets: {e:#}");
    }
}

pub fn set_absorbed(targets: &[PathBuf]) {
    if let Some(d) = Path::new(ABSORBED_LIST).parent() {
        let _ = fs::create_dir_all(d);
    }
    let mut body =
        String::from("# Targets absorb re-serves as injections; reload keeps these.\n");
    for t in targets {
        body.push_str(&t.to_string_lossy());
        body.push('\n');
    }
    // Not discarded: `reload` reads this list to keep absorbed rules across a
    // delta apply, so losing it silently means those targets come back as real
    // mounts on the next reload with nothing explaining why.
    if let Err(e) = fs::write(ABSORBED_LIST, &body) {
        eprintln!(
            "nomount: could not record absorbed targets in {ABSORBED_LIST}: {e} — \
             `nomount reload` will not know to keep them, and they may return as mounts"
        );
    }
}

/// Is anything still mounted here? The authority on whether an unmount worked:
/// umount2 reports EINVAL both for "never a mountpoint" and for "a peer already
/// took it away", and only the second is fine.
pub(crate) fn still_mounted(p: &Path) -> bool {
    std::fs::read_to_string(MOUNTINFO)
        .map(|b| parse_mountinfo(&b).iter().any(|r| r.target == p))
        .unwrap_or(false)
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
    let Ok(c) = CString::new(p.to_string_lossy().as_bytes()) else {
        return false;
    };
    unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) == 0 }
}

/// Inject `source` at `target`. A directory bind is expanded to one rule per
/// file rather than a single directory rule: a directory rule REPLACES the stock
/// directory, hiding every entry the module did not ship, which is the same
/// whole-partition masking that bootloops zygote.
/// Is `target` already serving `source`? Compared by size and mtime, which is
/// what an effective injection makes identical -- the rule mirrors the backing
/// file's metadata.
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
    t.len() == s.len() && t.modified().ok() == s.modified().ok()
}

fn inject(nm: &Nm, source: &Path, target: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if source.is_dir() {
        for e in std::fs::read_dir(source)?.flatten() {
            let ft = e.file_type()?;
            let child_src = e.path();
            let child_tgt = target.join(e.file_name());
            if ft.is_dir() {
                inject(nm, &child_src, &child_tgt, out)?;
            } else {
                nm.add(&child_tgt, &child_src)?;
                out.push(child_tgt);
            }
        }
    } else {
        nm.add(target, source)?;
        out.push(target.to_path_buf());
    }
    Ok(())
}

/// `nomount absorb [--dry-run]`.
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
fn current_apk_of(pkg: &str) -> Option<PathBuf> {
    let out = std::process::Command::new("pm").args(["path", pkg]).output().ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("package:"))
        .map(|p| PathBuf::from(p.trim()))
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
pub fn refresh_app_apks(nm: &Nm) -> (u32, u32) {
    let (mut repointed, mut stale) = (0u32, 0u32);
    let Ok(list) = nm.list() else { return (0, 0) };
    for line in list.lines() {
        let Some((target, source)) = line.split_once(" -> ") else { continue };
        let target = Path::new(target.trim());
        // A UID-scoped rule prints a trailing "[UID: n]"; the source ends there.
        let source = PathBuf::from(source.split(" [").next().unwrap_or(source).trim());
        if !is_app_apk(target) || target.exists() {
            continue;
        }
        let Some(pkg) = pkg_of_apk_target(target) else { continue };
        match current_apk_of(&pkg) {
            Some(now) if now != target && source.exists() => {
                let _ = nm.del(target);
                if nm.add(&now, &source).is_ok() {
                    repointed += 1;
                }
            }
            _ => {
                let _ = nm.del(target);
                stale += 1;
            }
        }
    }
    (repointed, stale)
}

/// ROM partitions a module might try to empty. A tmpfs anywhere under one of
/// these is never stock: measured on OP15, 21 mounts land inside a ROM partition
/// (vfat firmware, ext4 dsp, the OEM's own overlayfs) and not one of them is a
/// tmpfs -- stock keeps those at /dev, /mnt, /apex, /linkerconfig and /tmp.
const ROM_ROOTS: &[&str] =
    &["/system/", "/product/", "/vendor/", "/system_ext/", "/odm/", "/oem/", "/my_"];

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

/// Take over the "make this ROM directory look empty" trick: drop the tmpfs and
/// record a durable whiteout for the path instead.
///
/// The whiteout is the mountless equivalent -- the directory reads as absent
/// rather than empty, which is the same answer to a PackageManager scan -- and it
/// is re-applied at boot from whiteouts.txt, so the module can re-mount its tmpfs
/// every boot and we simply take it over again.
fn absorb_rom_tmpfs(dry_run: bool) -> (u32, u32) {
    let Ok(body) = fs::read_to_string(MOUNTINFO) else { return (0, 0) };
    let (skips, _) = skip_list();
    let (mut done, mut failed) = (0u32, 0u32);
    for target in body.lines().filter_map(rom_tmpfs_target) {
        // The opt-out list applies here too. Converting a tmpfs to a whiteout
        // hides the ROM directory outright, and for a system app that a
        // /data/app package UPDATES that is not always equivalent -- the update
        // rides on the system base. Leaving one alone must be one line in
        // absorb-skip.txt, not a rebuild.
        if is_skipped(Path::new("/"), &target, &skips) {
            println!("skipping the tmpfs over {} (opt-out list)", target.display());
            continue;
        }
        if dry_run {
            println!("would empty {} mountlessly (tmpfs -> durable whiteout)", target.display());
            done += 1;
            continue;
        }
        // Drop any live rule on the path FIRST. A whiteout there (ours, from a
        // previous pass, re-applied at boot from whiteouts.txt) d_drops the
        // dentry, which detaches the mount from path resolution -- umount2 then
        // cannot find the mountpoint and the tmpfs is stranded until reboot.
        // Same trap the inject-over-a-mountpoint comment below describes, reached
        // from the other direction. Measured on OP15: with the whiteout already
        // applied, every absorb reported "1 failed" and the tmpfs never went away.
        let nm = Nm::new();
        let _ = nm.del(&target);
        if !umount_detach(&target) && still_mounted(&target) {
            eprintln!("nomount: cannot unmount the tmpfs over {}", target.display());
            failed += 1;
            continue;
        }
        match crate::whiteout::add(&target.to_string_lossy(), true) {
            Ok(()) => done += 1,
            Err(e) => {
                eprintln!("nomount: {} unmounted but the whiteout failed: {e:#}", target.display());
                failed += 1;
            }
        }
    }
    (done, failed)
}

pub fn run_absorb(dry_run: bool, include_dirs: bool) -> Result<()> {
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
    let (tmpfs_done, tmpfs_failed) = absorb_rom_tmpfs(dry_run);
    let surveyed = survey()?;
    // Same mountinfo the survey classified from, so a redundant target resolves
    // to the same servable twin here as it did there.
    let aliases = std::fs::read_to_string(MOUNTINFO)
        .map(|b| mount_aliases(&parse_mountinfo(&b)))
        .unwrap_or_default();
    let (mut leaking, mut declined) = (0u32, 0u32);
    for s in &surveyed {
        if matches!(s.disposition, Disposition::Declined(_)) {
            declined += 1;
        }
        match &s.disposition {
            Disposition::Absorb => {}
            Disposition::Redundant if runtime_droppable(&s.target, &aliases) => println!(
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

    let cands: Vec<Candidate> = surveyed
        .into_iter()
        .filter(|s| match s.disposition {
            Disposition::Absorb => true,
            Disposition::Redundant => runtime_droppable(&s.target, &aliases),
            _ => false,
        })
        .map(|s| Candidate {
            redundant: matches!(s.disposition, Disposition::Redundant),
            target: s.target,
            source: s.source,
        })
        .collect();
    if cands.is_empty() {
        // A ROM tmpfs is taken over above, not through the candidate list, so say
        // so here -- otherwise a run that emptied one still reported "nothing to
        // absorb", which reads as "we did nothing".
        if tmpfs_done > 0 || tmpfs_failed > 0 {
            println!(
                "nomount absorb: {tmpfs_done} ROM tmpfs emptied mountlessly                  ({tmpfs_failed} failed)"
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
    let mut reasserted: HashSet<PathBuf> = HashSet::new();
    // Recorded so `reload` does not prune them: an absorbed rule is not in any
    // module plan, and the reconcile drops whatever the plan does not name.
    let mut fresh: Vec<PathBuf> = Vec::new();
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
            // Already serving: re-adding would only d_drop a dentry other
            // processes may be mapping, for no gain (see `already_serving`).
            if already_serving(&at, &c.source) {
                continue;
            }
            let mut refreshed = Vec::new();
            if let Err(e) = inject(&nm, &c.source, &at, &mut refreshed) {
                eprintln!(
                    "nomount: {} unmounted but re-asserting its rules failed: {e:#} - content may have reverted to the stock file",
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
        if !umount_detach(&c.target) {
            eprintln!(
                "nomount: cannot unmount {} - leaving it alone (injecting anyway would \
                 strand it in mountinfo)",
                c.target.display()
            );
            failed += 1;
            continue;
        }
        match inject(&nm, &c.source, &c.target, &mut fresh) {
            Ok(()) => done += 1,
            Err(e) => {
                eprintln!("nomount: absorb of {} failed: {e:#}", c.target.display());
                failed += 1;
            }
        }
    }
    // Written even when nothing was absorbed this run: a partially-failed inject
    // still created rules, and those are exactly the ones reload must not drop.
    let rules = fresh.len() as u32;
    // Pair each fresh target with the source we just served it from, so a later
    // boot can re-serve it without the owning module mounting first.
    let fresh_pairs: Vec<(PathBuf, PathBuf)> = fresh
        .iter()
        .filter_map(|t| {
            cands.iter().find(|c| &c.target == t).map(|c| (t.clone(), c.source.clone()))
        })
        .collect();
    if !fresh_pairs.is_empty() {
        let mut all = absorbed_pairs();
        for p in fresh_pairs {
            if !all.iter().any(|(t, _)| *t == p.0) {
                all.push(p);
            }
        }
        all.sort();
        set_absorbed_pairs(&all);
    }
    let mut recorded: Vec<PathBuf> = absorbed_targets().into_iter().chain(fresh).collect();
    recorded.sort();
    recorded.dedup();
    set_absorbed(&recorded);

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
            "nomount absorb: {} mount(s) would be absorbed, {tmpfs_done} ROM tmpfs, {skipped_dirs} directory bind(s) skipped{drops}{leaks} (dry run)",
            cands.len() as u32 - skipped_dirs - dropped
        );
    } else {
        let dirs = if skipped_dirs > 0 {
            format!(", {skipped_dirs} directory bind(s) skipped")
        } else {
            String::new()
        };
        println!(
            "nomount absorb: {done} mount(s) absorbed as {rules} rule(s), {tmpfs_done} ROM tmpfs emptied mountlessly, {} failed{dirs}{drops}{leaks}", failed + tmpfs_failed
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
