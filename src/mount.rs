//! Metamodule mount pass for the NoMount Suite.
//!
//! For every enabled module the Suite classifies content and routes it:
//! - RRO `**/overlay/*.apk` dirs        → real overlayfs via [`crate::overlay`]
//! - `.replace` markers / char devices  → whiteout via `nm w`
//! - everything else (files, symlinks)  → hookless VFS redirect via `nm add`
//!
//! The Suite does NOT manage root/su — su is provided independently and
//! mountlessly by the kernel's sucompat. Keeping su out of the mount pass means
//! root can never break from a Suite bug, and there is no su mount for a scanner
//! to flag.

use std::collections::{HashMap, HashSet};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

/// Magisk's whiteout marker is a 0:0 char device. Unix-only; on non-unix hosts
/// (the Windows `cargo test` build) this is always false — the crate only *runs*
/// on Android, this just lets the pure-logic tests compile here.
#[cfg(unix)]
fn is_char_dev(ft: &fs::FileType) -> bool { ft.is_char_device() }
#[cfg(not(unix))]
fn is_char_dev(_ft: &fs::FileType) -> bool { false }

use anyhow::{Context, Result};

use crate::nm::Nm;

const MODULES_DIR: &str = "/data/adb/modules";

// Modules that do their own mounting/redirection (or ship their own su, like a
// kernelnosu module) — injecting their files double-handles the same targets, and
// for a su binary would break root. Extend at runtime via the blocklist file.
const BUILTIN_BLOCKLIST: &[&str] = &["kernelnosu", "scene_swap_controller", "AAaTempSpoof"];
const BLOCKLIST_FILE: &str = "/data/adb/nomount/blocklist";

// Top-level module roots that exist on-device but must NEVER be injected into
// (writable, virtual, or ramdisk mounts). Any OTHER top-level module dir whose
// "/<name>" is a real directory is treated as a partition to inject — so partition
// discovery is dynamic (product/, my_*/, vendor/, whatever THIS device ships) with
// no hardcoded per-OEM list. Module-metadata dirs (META-INF/, webroot/, common/…)
// are excluded for free: their "/<name>" doesn't exist on the device.
const NON_PARTITION_ROOTS: &[&str] = &[
    "data", "data_mirror", "mnt", "dev", "proc", "sys", "cache", "metadata", "config",
    "storage", "sdcard", "apex", "tmp", "debug_ramdisk", "linkerconfig",
    "postinstall", "second_stage_resources", "bin", "sbin",
];

/// DISCOVERY: should we walk a top-level module dir `<name>`? Yes if `/<name>`
/// resolves to a directory (following symlinks, so a device where `/system_ext`
/// is a symlink into /system is still walked), and it isn't a non-injectable root.
fn is_partition_dir(name: &str) -> bool {
    !name.is_empty()
        && !NON_PARTITION_ROOTS.contains(&name)
        && Path::new(&format!("/{name}")).is_dir()
}

/// CANONICALIZATION: is `<name>` a REAL separate partition, so `system/<name>/...`
/// should be rewritten to `/<name>/...`? Uses symlink_metadata (lstat), NOT
/// is_dir(): a /system-symlink like `/etc -> /system/etc` must NOT canonicalize
/// (that would send `system/etc/...` to `/etc/...`); only a real mount (/vendor,
/// /product, /odm, /my_product) qualifies. A symlinked root keeps `/system/<name>`.
fn is_real_partition(name: &str) -> bool {
    !name.is_empty()
        && !NON_PARTITION_ROOTS.contains(&name)
        && fs::symlink_metadata(format!("/{name}"))
            .map(|m| m.is_dir())
            .unwrap_or(false)
}

/// Resolve a module-relative path to its absolute target.
///
/// Classic layout ships everything under `system/`, but `system/<X>` where `<X>`
/// is really a separate top-level partition (`/vendor`, `/product`, `/odm`,
/// `/system_ext`, `/system_dlkm`, `/my_product`, …) must land on `/<X>`, like
/// magic-mount does. This is dynamic (any partition THIS device has), so it also
/// covers `system_dlkm`/`oem`/`my_*` that a hardcoded alias list would miss. A
/// plain /system subdir (`system/app`, `system/bin`) is not a root partition, so
/// it stays under `/system`.
fn resolve_target_path(relative: &Path) -> Option<PathBuf> {
    let s = relative.to_str()?;
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix("system/") {
        let x = rest.split('/').next().unwrap_or("");
        if is_real_partition(x) {
            return Some(PathBuf::from(format!("/{rest}")));
        }
    }
    Some(PathBuf::from(format!("/{s}")))
}

/// A target on an OnePlus/Oppo `my_*` partition, which must be served by a real
/// bind (see bind.rs) because hookless injection there bootloops zygote.
fn is_my_partition(target: &Path) -> bool {
    target
        .components()
        .nth(1)
        .and_then(|c| c.as_os_str().to_str())
        .map(|s| s.starts_with("my_"))
        .unwrap_or(false)
}

/// True if `target` is a partition ROOT (`/product`, `/system`, `/vendor`, …) rather than
/// something inside one.
///
/// A rule on a partition root would redirect the WHOLE partition to the module's copy,
/// masking every stock entry under it — never what a module means. Modules commonly ship
/// `system/product` (etc.) as a SYMLINK to their own top-level `product/` to make the
/// classic and auto_mount layouts converge (e.g. OxygenCustomizer: `system/product ->
/// ../product`). `file_type()` does not follow symlinks, so such an entry is not seen as a
/// directory and would otherwise be injected as a "file", and `resolve_target_path` maps
/// `system/product` through the SAR alias to exactly `/product`.
///
/// Concretely that produced `nm add /product <mod>/system/product`, which made
/// `/product/overlay` resolve to the module's overlay dir — hiding the stock overlays. At
/// boot, zygote's OverlayConfig then could not see `/product/overlay/OplusGmsConfigOverlayCommon`
/// and fell back to the `/my_product/cust/<region>/overlay` twin, which is NOT in zygote's FD
/// allowlist -> `FileDescriptorInfo::CreateFromFd` JNI FatalError at the first
/// `forkSystemServer` -> SIGABRT -> bootloop. Skipping partition-root targets fixes it; the
/// real content is still injected via the module's own top-level partition dirs.
fn is_partition_root(target: &Path) -> bool {
    target.components().skip(1).count() == 1
}

/// Does this module bind its OWN my_* content (so we must not bind it too and
/// stack a duplicate mount)? A module only counts as self-managing if one of its
/// boot scripts actually references mounting/binding a my_* path -- checking for
/// mere script *existence* (the old heuristic) wrongly skipped my_* for any module
/// that ships a service.sh for an unrelated reason. bind::apply() also skips a
/// target that is already mounted, as a second guard.
fn self_binds_my(mdir: &Path) -> bool {
    for s in ["post-fs-data.sh", "service.sh", "post-mount.sh"] {
        if let Ok(body) = fs::read_to_string(mdir.join(s)) {
            let lower = body.to_lowercase();
            if lower.contains("my_") && (lower.contains("mount") || lower.contains("bind")) {
                return true;
            }
        }
    }
    false
}

fn module_enabled(dir: &Path) -> bool {
    !dir.join("disable").exists()
        && !dir.join("remove").exists()
        && !dir.join("skip_mount").exists()
}

fn load_blocklist() -> HashSet<String> {
    let mut set: HashSet<String> = BUILTIN_BLOCKLIST.iter().map(|s| (*s).to_string()).collect();
    if let Ok(contents) = fs::read_to_string(BLOCKLIST_FILE) {
        for line in contents.lines() {
            let id = line.trim();
            if !id.is_empty() && !id.starts_with('#') {
                set.insert(id.to_string());
            }
        }
    }
    set
}

struct Stats {
    applied: u32,
    failed: u32,
    whiteouts: u32,
}

/// What the Suite intends to do for one module entry.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlanKind {
    /// Redirect `target` at `source` (hookless, mountless).
    Inject,
    /// Make `target` appear absent (`.replace` marker or 0:0 char device).
    Whiteout,
    /// Real file-over-file bind (my_* partitions hookless can't serve).
    Bind,
}

/// One intended operation, resolved but not yet applied.
///
/// Separating "what we would do" from "doing it" is what lets `nomount doctor`
/// lint the exact same decisions the mount pass will make, before a reboot
/// turns a bad rule into a bootloop.
pub(crate) struct PlanEntry {
    pub module: String,
    pub target: PathBuf,
    pub source: PathBuf,
    pub kind: PlanKind,
}

/// Recursively resolve a module subtree rooted at `dir` into plan entries.
/// `.replace`/char-device markers become whiteouts; every other file — including
/// RRO overlay APKs — becomes a hookless redirect. Symlinks are treated as files
/// (file_type does not follow). RRO overlay dirs are NOT special-cased: their APKs
/// are hookless-injected into e.g. `/product/overlay`, and OverlayManagerService +
/// idmap2 pick them up at the system_server scan (which runs after this
/// post-fs-data pass). So RRO works with no overlayfs mount — zero mounts total.
fn plan_tree(module: &str, module_root: &Path, dir: &Path, self_manages: bool, out: &mut Vec<PlanEntry>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        let source = entry.path();
        let rel = match source.strip_prefix(module_root) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let Some(target) = resolve_target_path(rel) else {
            continue;
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();

        if ft.is_dir() {
            plan_tree(module, module_root, &source, self_manages, out);
        } else if name == ".replace" {
            // Whiteout the parent dir (module wants to replace, not merge, it).
            // Never whiteout a bare partition root: masking a whole partition bootloops
            // (forkSystemServer SIGABRT), exactly as an inject on a root does below.
            if let Some(parent) = target.parent() {
                // Skip a partition root (bootloop) and my_* (bind can't whiteout).
                if is_partition_root(parent) || is_my_partition(parent) {
                    continue;
                }
                out.push(PlanEntry {
                    module: module.to_string(),
                    target: parent.to_path_buf(),
                    source: source.clone(),
                    kind: PlanKind::Whiteout,
                });
            }
        } else if is_char_dev(&ft) {
            // A 0:0 char device is Magisk's whiteout marker. Refuse it on a partition
            // root for the same bootloop reason, and on my_* (bind can't whiteout).
            if is_partition_root(&target) || is_my_partition(&target) {
                continue;
            }
            out.push(PlanEntry {
                module: module.to_string(),
                target,
                source,
                kind: PlanKind::Whiteout,
            });
        } else if is_partition_root(&target) {
            // A non-directory entry resolving to a bare partition root — a module's
            // layout-convergence symlink (e.g. `system/product -> ../product`). Injecting it
            // would redirect the entire partition; skip it. The real content still comes from
            // the module's own top-level partition dir. Real `system/<partition>` DIRECTORIES
            // are unaffected: they take the is_dir() branch above and recurse as before.
            continue;
        } else if is_my_partition(&target) {
            // my_* bootloops under hookless (zygote FD allowlist), so it needs a real
            // bind. But a module that ships its own post-fs-data.sh/service.sh already
            // binds its my_* content (often a processed copy); binding it again would
            // double-mount and could shadow the wrong version, so leave those to it.
            if self_manages {
                continue;
            }
            out.push(PlanEntry {
                module: module.to_string(),
                target,
                source,
                kind: PlanKind::Bind,
            });
        } else {
            out.push(PlanEntry {
                module: module.to_string(),
                target,
                source,
                kind: PlanKind::Inject,
            });
        }
    }
}

/// Build the full plan for every enabled, non-blocklisted module.
/// Returns the entries plus how many modules were skipped by the blocklist.
pub(crate) fn collect_plan() -> (Vec<PlanEntry>, u32) {
    let blocklist = load_blocklist();
    let mut plan = Vec::new();
    let mut skipped = 0u32;
    let Ok(dirs) = fs::read_dir(MODULES_DIR) else {
        return (plan, skipped);
    };
    for entry in dirs.flatten() {
        let mdir = entry.path();
        if !mdir.is_dir() || !module_enabled(&mdir) {
            continue;
        }
        let Some(id) = mdir.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if blocklist.contains(id) {
            skipped += 1;
            continue;
        }
        let id = id.to_string();
        // A module that binds its own my_* content manages it itself; we skip its
        // my_* binds (see plan_tree) to avoid a duplicate mount. Its hookless
        // content is still served normally.
        let self_manages = self_binds_my(&mdir);
        // "system/" is the classic layout; auto_mount modules (e.g. OxygenCustomizer)
        // ship content directly under module-root partition dirs. Process every
        // top-level dir that maps to a real on-device partition — dynamically, so any
        // OEM's partitions are handled. resolve_target_path maps "<root>/…" -> "/<root>/…"
        // (and applies the SAR aliases for "system/vendor" etc.).
        if let Ok(entries) = fs::read_dir(&mdir) {
            for e in entries.flatten() {
                if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                let name = e.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                // A partition iff "/<name>" is a real directory on this device and not a
                // non-injectable root; module-metadata dirs (META-INF/, webroot/, …) fail
                // this and are skipped. my_* partitions ARE walked now: hookless bootloops
                // on them (zygote FD allowlist), so plan_tree routes their files to a real
                // bind (PlanKind::Bind) instead of injection. Discovery follows symlinks so
                // a symlinked top-level root is still walked (canonicalization uses lstat).
                if !is_partition_dir(name) {
                    continue;
                }
                plan_tree(&id, &mdir, &e.path(), self_manages, &mut plan);
            }
        }
    }
    (plan, skipped)
}

/// `nomount plan`: print the resolved plan (target, kind, source) without applying.
pub fn run_plan() -> Result<()> {
    let (plan, skipped) = collect_plan();
    for e in &plan {
        let k = match e.kind {
            PlanKind::Inject => "inject",
            PlanKind::Whiteout => "whiteout",
            PlanKind::Bind => "bind",
        };
        println!("{k:8} {} <- {} [{}]", e.target.display(), e.source.display(), e.module);
    }
    let binds = plan.iter().filter(|e| e.kind == PlanKind::Bind).count();
    println!("({} entries: {} binds, {skipped} blocklisted)", plan.len(), binds);
    Ok(())
}

/// A live leaf rule from `nm list`.
enum LiveRule {
    Inject(PathBuf),
    Whiteout,
}

/// Parse `nm list` into live leaf rules keyed by target: injects (`T -> S`) and
/// whiteouts (`T (whiteout)`). Engine-managed virtual dirs (`T (virtual dir)`) and
/// any ` [UID: N]` suffix are ignored. Suffix/rsplit matching so a target path
/// containing spaces/parens/arrows is not mis-split (source is after the LAST
/// ` -> `; whiteout is a suffix).
fn parse_live_rules(list: &str) -> HashMap<PathBuf, LiveRule> {
    let mut out = HashMap::new();
    for l in list.lines() {
        let l = l.split(" [UID:").next().unwrap_or(l).trim();
        if l.is_empty() {
            continue;
        }
        if let Some(t) = l.strip_suffix(" (whiteout)") {
            out.insert(PathBuf::from(t.trim()), LiveRule::Whiteout);
        } else if l.ends_with(" (virtual dir)") {
            continue;
        } else if let Some((t, s)) = l.rsplit_once(" -> ") {
            out.insert(PathBuf::from(t.trim()), LiveRule::Inject(PathBuf::from(s.trim())));
        }
    }
    out
}

/// `nomount reload`: gap-free hot load/unload. Diffs the desired plan against the
/// live rule set and applies ONLY the delta -- no `clear`, so injections never
/// drop. Install a module then reload => just its files go live; remove a module
/// then reload => just its files go away. Also reconciles my_* binds.
pub fn run_reload() -> Result<()> {
    let nm = Nm::new();
    nm.version()
        .context("hookless NoMount engine not responding -- is the CONFIG_NOMOUNT kernel loaded?")?;

    let (plan, skipped) = collect_plan();

    // Desired, split by handling: hookless leaf rules vs my_* binds.
    let mut desired_hookless: HashMap<&Path, &PlanEntry> = HashMap::new();
    let mut desired_binds: HashSet<&Path> = HashSet::new();
    for e in &plan {
        match e.kind {
            PlanKind::Bind => {
                desired_binds.insert(e.target.as_path());
            }
            _ => {
                desired_hookless.insert(e.target.as_path(), e);
            }
        }
    }

    // An unreadable live set means the delta can't be computed safely -- fail
    // rather than silently mass-re-add and stop pruning.
    let live_txt = nm.list().context("nm list failed during reload")?;
    let live = parse_live_rules(&live_txt);

    let (mut added, mut changed, mut removed, mut failed) = (0u32, 0u32, 0u32, 0u32);
    // Add new rules, and re-apply a live rule whose SOURCE or KIND changed (not
    // just presence): a target moving between modules or flipping inject<->whiteout
    // must update, or the stale rule would be frozen until a full mount.
    for (t, e) in &desired_hookless {
        let up_to_date = match live.get(*t) {
            Some(LiveRule::Inject(src)) => {
                e.kind == PlanKind::Inject && src.as_path() == e.source.as_path()
            }
            Some(LiveRule::Whiteout) => e.kind == PlanKind::Whiteout,
            None => false,
        };
        if up_to_date {
            continue;
        }
        let existed = live.contains_key(*t);
        if existed {
            let _ = nm.del(&e.target); // drop the stale rule before re-adding
        }
        let r = match e.kind {
            PlanKind::Inject => nm.add(&e.target, &e.source),
            PlanKind::Whiteout => nm.whiteout(&e.target),
            PlanKind::Bind => unreachable!(),
        };
        match r {
            Ok(_) => {
                if existed {
                    changed += 1;
                } else {
                    added += 1;
                }
            }
            Err(_) => failed += 1,
        }
    }
    // Remove live rules no longer desired (skip any that are now bind targets).
    for t in live.keys() {
        if !desired_hookless.contains_key(t.as_path()) && !desired_binds.contains(t.as_path()) {
            if nm.del(t).is_ok() {
                removed += 1;
            } else {
                failed += 1;
            }
        }
    }

    // Reconcile my_* binds against binds.list.
    let live_binds = crate::bind::tracked();
    let (mut bind_added, mut bind_removed) = (0u32, 0u32);
    for t in &live_binds {
        if !desired_binds.contains(t.as_path()) {
            crate::bind::umount_one(t);
            bind_removed += 1;
        }
    }
    let live_bind_set: HashSet<&Path> = live_binds.iter().map(|p| p.as_path()).collect();
    for e in plan.iter().filter(|e| e.kind == PlanKind::Bind) {
        if !live_bind_set.contains(e.target.as_path()) {
            match crate::bind::apply(&e.source, &e.target) {
                Ok(_) => bind_added += 1,
                Err(_) => failed += 1,
            }
        }
    }

    println!(
        "nomount reload: +{added} ~{changed} -{removed} rules, +{bind_added} -{bind_removed} binds, \
         {failed} failed, {skipped} blocklisted (gap-free)"
    );
    Ok(())
}

/// Metamodule entry point (`nomount mount`): rebuild rules from the current set
/// of enabled modules and mount RRO overlays. The Suite deliberately does NOT
/// touch root/su: su is provided independently by the kernel's sucompat,
/// mountlessly. Keeping su out of the Suite means a Suite bug can never break
/// root, and there is no su mount for a scanner to flag.
pub fn run_mount() -> Result<()> {
    let nm = Nm::new();
    nm.version()
        .context("hookless NoMount engine not responding -- is the CONFIG_NOMOUNT kernel loaded?")?;

    // Start clean so uninstalled/updated modules don't leave stale rules, and tear
    // down any my_* binds from the previous pass so removed modules don't leak one.
    let _ = nm.clear();
    crate::bind::teardown_all();

    let (plan, skipped) = collect_plan();
    let mut served: HashSet<&str> = HashSet::new();
    let mut binds = 0u32;
    let mut st = Stats {
        applied: 0,
        failed: 0,
        whiteouts: 0,
    };
    for e in &plan {
        served.insert(e.module.as_str());
        match e.kind {
            PlanKind::Whiteout => match nm.whiteout(&e.target) {
                Ok(()) => st.whiteouts += 1,
                Err(_) => st.failed += 1,
            },
            PlanKind::Inject => match nm.add(&e.target, &e.source) {
                Ok(()) => st.applied += 1,
                Err(_) => st.failed += 1,
            },
            PlanKind::Bind => match crate::bind::apply(&e.source, &e.target) {
                Ok(()) => binds += 1,
                Err(_) => st.failed += 1,
            },
        }
    }
    let modules = served.len();
    let surface = if binds > 0 { "hookless + my_* bind" } else { "mountless (RRO via hookless)" };

    println!(
        "nomount(suite): {modules} modules | {} rules, {} whiteouts, {binds} my_* binds, {} failed, \
         {skipped} skipped | {surface}",
        st.applied, st.whiteouts, st.failed
    );
    Ok(())
}
