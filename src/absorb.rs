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
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 4])
                .ok()
                .and_then(|o| u8::from_str_radix(o, 8).ok())
            {
                out.push(v as char);
                i += 4;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
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

/// Is this mount module content laid over the ROM? OWNERSHIP only — whether the
/// target can actually be served is `mount::serve_mode`'s question, and asking
/// it here instead is what let absorb inject onto `/my_*` and `/apex`.
pub(crate) fn is_absorbable(src: &Path, target: &Path) -> bool {
    src.starts_with(MODULE_ROOT)
        && !target.starts_with(FOREIGN_ROOT)
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

/// The verdict for one foreign mount. Split out of `survey` so it can be tested
/// without a /proc to read.
/// `None` means the mount is none of our business — not a report, not an action.
pub(crate) fn classify(
    src: &Path,
    target: &Path,
    skips: &[String],
    skip_src: &'static str,
    hookers: &HashSet<String>,
) -> Option<Disposition> {
    // The target question belongs to mount.rs, not here — see `serve_mode`.
    let mode = crate::mount::serve_mode(target);
    if !is_absorbable(src, target) {
        // Backed by /data but not by a module. Only interesting if it landed
        // somewhere we would otherwise serve: Android's own storage plumbing
        // binds /data/user -> /data_mirror/... and /data/media ->
        // /mnt/pass_through/..., which is stock, not a module leak, and reporting
        // those as leaks is worse than useless — nine of them drown the real one.
        return matches!(mode, crate::mount::Serve::Inject | crate::mount::Serve::Bind).then_some(
            Disposition::Leaking(
                "source is outside /data/adb, so there is no module content to re-serve",
            ),
        );
    }
    if let Some(d) = declined_reason_with(src, target, skips, skip_src, hookers) {
        return Some(Disposition::Declined(d));
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

    let mut out: Vec<Surveyed> = rows
        .iter()
        .filter_map(|r| {
            let src = source_of(r, &roots)?;
            // Foreign = backed by /data, landing off /data. A target under /data
            // is the module's own scratch space (fbind and friends): not ours.
            if !src.starts_with(FOREIGN_ROOT) || r.target.starts_with(FOREIGN_ROOT) {
                return None;
            }
            if r.target.components().count() <= 1 {
                return None;
            }
            let disposition = classify(&src, &r.target, &skips, skip_src, &hookers)?;
            Some(Surveyed { target: r.target.clone(), source: src, disposition })
        })
        .collect();
    // Deepest target first, so nested mounts come off in the right order.
    out.sort_by_key(|s| std::cmp::Reverse(s.target.components().count()));
    Ok(out)
}

/// A mount we intend to convert.
pub struct Candidate {
    pub target: PathBuf,
    pub source: PathBuf,
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
pub fn absorbed_targets() -> HashSet<PathBuf> {
    fs::read_to_string(ABSORBED_LIST)
        .map(|s| {
            s.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(PathBuf::from)
                .collect()
        })
        .unwrap_or_default()
}

/// Replace the record. `run_mount` calls this with an empty set: it issues
/// `nm clear`, so nothing absorb recorded is live any more and keeping the file
/// would make `reload` protect targets that no longer have a rule.
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
    let _ = fs::write(ABSORBED_LIST, body);
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
pub fn run_absorb(dry_run: bool, include_dirs: bool) -> Result<()> {
    let nm = Nm::new();
    nm.version()
        .context("hookless NoMount engine not responding")?;

    // Report the whole picture BEFORE acting, so a mount absorb cannot take is
    // never implied to be absent. "Nothing to absorb" and "nothing is mounted"
    // are different claims and only the second one is the posture.
    let surveyed = survey()?;
    let (mut leaking, mut declined) = (0u32, 0u32);
    for s in &surveyed {
        if matches!(s.disposition, Disposition::Declined(_)) {
            declined += 1;
        }
        match &s.disposition {
            Disposition::Absorb => {}
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
        .filter(|s| matches!(s.disposition, Disposition::Absorb))
        .map(|s| Candidate { target: s.target, source: s.source })
        .collect();
    if cands.is_empty() {
        // "Nothing to absorb" is not "nothing is mounted". A declined mount is
        // still a mount and still visible to an app, so only claim a clean
        // posture when mountinfo genuinely holds no foreign mount at all.
        match (leaking, declined) {
            (0, 0) => println!("nomount absorb: nothing mounted over the ROM (posture clean)"),
            (0, d) => println!(
                "nomount absorb: nothing to absorb; {d} mount(s) left by design and still visible"
            ),
            (n, d) => println!(
                "nomount absorb: nothing to absorb, but {n} foreign mount(s) remain \
                 ({d} left by design) — the posture is NOT clean"
            ),
        }
        return Ok(());
    }

    let (mut done, mut failed, mut skipped_dirs) = (0u32, 0u32, 0u32);
    // Recorded so `reload` does not prune them: an absorbed rule is not in any
    // module plan, and the reconcile drops whatever the plan does not name.
    let mut fresh: Vec<PathBuf> = Vec::new();
    for c in &cands {
        // Apply the same directory rule the real run uses, so a dry run can never
        // promise an action the real run would decline.
        let is_dir_bind = c.source.is_dir();
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
    if dry_run {
        println!(
            "nomount absorb: {} mount(s) would be absorbed, {skipped_dirs} directory bind(s) skipped{leaks} (dry run)",
            cands.len() as u32 - skipped_dirs
        );
    } else {
        let dirs = if skipped_dirs > 0 {
            format!(", {skipped_dirs} directory bind(s) skipped")
        } else {
            String::new()
        };
        println!(
            "nomount absorb: {done} mount(s) absorbed as {rules} rule(s), {failed} failed{dirs}{leaks}"
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
            classify(&modsrc, Path::new("/my_product/app/Foo/Foo.apk"), &none, "test", &HashSet::new()).unwrap(),
            Disposition::Declined(Declined::MustBind)
        ));
        // apex is in NON_PARTITION_ROOTS: not ours to serve at all.
        assert!(matches!(
            classify(&modsrc, Path::new("/apex/com.android.conscrypt/cacerts"), &none, "test", &HashSet::new()).unwrap(),
            Disposition::Leaking(_)
        ));
        // A bare partition root would mask the whole partition.
        assert!(matches!(
            classify(&modsrc, Path::new("/product"), &none, "test", &HashSet::new()).unwrap(),
            Disposition::Leaking(_)
        ));
        // …and an ordinary ROM path still absorbs.
        assert!(matches!(
            classify(&modsrc, Path::new("/system/app/Foo/Foo.apk"), &none, "test", &HashSet::new()).unwrap(),
            Disposition::Absorb
        ));
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
                classify(Path::new(s), Path::new(t), &[], "test", &HashSet::new()).is_none(),
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
            classify(&src, Path::new("/system/bin/app_process64"), &builtins, "built-in", &HashSet::new()).unwrap(),
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
        );
        assert!(matches!(d, Some(Disposition::Declined(Declined::HooksElsewhere(_)))));

        // ...while an ordinary module's identical-shaped mount still absorbs.
        let d = classify(
            Path::new("/data/adb/modules/plain_mod/system/etc/g"),
            Path::new("/system/etc/g"),
            &builtins,
            "test",
            &hookers,
        );
        assert!(matches!(d, Some(Disposition::Absorb)));
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
}
