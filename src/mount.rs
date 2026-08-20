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

/// Does this directory carry overlayfs's `trusted.overlay.opaque=y`?
///
/// The third whiteout dialect a module can speak, alongside `.replace` and the
/// 0:0 char device. `trusted.*` is root-only, which is why it needs a raw
/// getxattr rather than anything in std.
#[cfg(unix)]
fn is_opaque_dir(p: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let (Ok(path), Ok(name)) = (
        CString::new(p.as_os_str().as_bytes()),
        CString::new("trusted.overlay.opaque"),
    ) else {
        return false;
    };
    let mut buf = [0u8; 4];
    let n = unsafe {
        libc::getxattr(path.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len())
    };
    n > 0 && buf[0] == b'y'
}
#[cfg(not(unix))]
fn is_opaque_dir(_p: &Path) -> bool { false }

use anyhow::{Context, Result};

use crate::nm::Nm;

const MODULES_DIR: &str = "/data/adb/modules";

// Modules that do their own mounting/redirection (or ship their own su, like a
// kernelnosu module) — injecting their files double-handles the same targets, and
// for a su binary would break root. Extend at runtime via the blocklist file.
const BUILTIN_BLOCKLIST: &[&str] = &["kernelnosu", "scene_swap_controller", "AAaTempSpoof"];
// NOTE: module ids, one per line — NOT the per-app hide list. The two shared this
// path until v1.3.12: hiding an app also told this pass to skip a module of that
// name, and every module-skip entry showed up in the WebUI's hidden-apps list with
// a delete button, one click away from injecting a self-mounting module. Per-app
// hiding lives in `uidhide` now (see blocklist.rs, which migrates an existing file).
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

/// EXPERIMENTAL: route `my_*` targets through hookless inject instead of a real
/// bind. Off by default (bind). Enabled by `NM_MY_HOOKLESS=1` in the metamount
/// env or a `/data/adb/nomount/my_hookless` marker. Safe to trial because the
/// GUARD_MAX=3 self-disable recovers a bootloop and records incident.log: if a
/// leaf my_* inject really trips zygote's FD allowlist at forkSystemServer, boot
/// fails <=3x and the Suite disables itself. If it boots clean, the bind fallback
/// was unnecessary and my_* can be served mountlessly like every other partition.
fn my_hookless_enabled() -> bool {
    std::env::var_os("NM_MY_HOOKLESS")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false)
        || Path::new("/data/adb/nomount/my_hookless").exists()
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

/// How a target may be served -- the single answer both the native module plan
/// and `absorb` must obey.
///
/// These used to be two rules. `plan_tree` consulted `NON_PARTITION_ROOTS`,
/// `is_partition_root` and `is_my_partition`; absorb had its own weaker test
/// (source under /data/adb, target not under /data) and so would happily inject
/// where this file refuses to -- `/my_*`, which bootloops zygote, and `/apex`,
/// which is not ours at all. Absorbing someone else's bind must never do
/// something we would not do for our own module content, so there is now one
/// predicate and two callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Serve {
    /// Hookless injection works here.
    Inject,
    /// Must be a real bind: injection on `my_*` trips zygote's FD allowlist.
    Bind,
    /// Not ours to serve, with the reason for a human.
    Refuse(&'static str),
}

pub(crate) fn serve_mode(target: &Path) -> Serve {
    let Some(root) = target.components().nth(1).and_then(|c| c.as_os_str().to_str()) else {
        return Serve::Refuse("not a path under a partition");
    };
    if NON_PARTITION_ROOTS.contains(&root) {
        return Serve::Refuse("not a ROM partition");
    }
    if is_partition_root(target) {
        return Serve::Refuse("a bare partition root (injecting one bootloops zygote)");
    }
    if is_my_partition(target) && !my_hookless_enabled() {
        return Serve::Bind;
    }
    Serve::Inject
}

/// Can this entry actually produce a rule?
///
/// Injection serves a symlink's TARGET, so a link whose target does not exist
/// yields nothing: the engine accepts the add and no rule appears. Counting that
/// as applied is what made `reload` report `+3 rules` where only 2 existed, and
/// `plan` list an entry that never materialises. `exists()` follows symlinks,
/// which is exactly the question being asked. Whiteouts and binds are unaffected
/// — a whiteout needs no backing, and a bind fails loudly on its own.
fn source_resolves(e: &PlanEntry) -> bool {
    e.kind != PlanKind::Inject || e.source.exists()
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
fn plan_tree(module: &str, module_root: &Path, dir: &Path, out: &mut Vec<PlanEntry>) {
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
            // A directory carrying `trusted.overlay.opaque=y` means the same thing
            // as a `.replace` file inside it: serve MY contents, hide the stock
            // directory underneath. It is not an exotic case — it is the branch
            // PlayIntegrityFork (and anything sharing its installer) takes on
            // KernelSU and APatch, where `.replace` and the 0:0 char device are
            // only used for Magisk. We read the other two markers and were blind
            // to this one, so the module installed cleanly and hid nothing: an
            // empty opaque dir has no files, so plan_tree recursed into it and
            // emitted nothing at all.
            if is_opaque_dir(&source) && !is_partition_root(&target) && !is_my_partition(&target) {
                out.push(PlanEntry {
                    module: module.to_string(),
                    target: target.clone(),
                    source: source.clone(),
                    kind: PlanKind::Whiteout,
                });
            }
            plan_tree(module, module_root, &source, out);
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
            // Always served. This used to be skipped when a text heuristic decided the
            // module's boot scripts "looked like" they mounted my_* themselves, which
            // silently dropped the module's ENTIRE my_* content on a grep over shell
            // source -- unpredictable, and invisible when it misfired. With
            // NM_MY_HOOKLESS nothing here bind-mounts, so the duplicate-mount hazard it
            // guarded against is gone; if a module does bind its own path, that real
            // mount simply takes precedence over the injection.
            let kind = if my_hookless_enabled() { PlanKind::Inject } else { PlanKind::Bind };
            out.push(PlanEntry {
                module: module.to_string(),
                target,
                source,
                kind,
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
/// A module whiteout is skipped unless it hides cleanly.
///
/// `.replace` and Magisk's char-device marker both ask us to make a stock entry
/// disappear, and off overlayfs that leaves the parent directory describing an
/// entry that is no longer listed (see [`crate::whiteout`]). Applying it anyway
/// would put a measurable hole on the device with nothing about it in any output
/// the user reads, so the default is to decline and say why.
///
/// The override is the durable list rather than a new switch: a path the user
/// added with `nomount whiteout add <path> --force` is a decision already made,
/// so honour it here too.
/// Drop any mount sitting on a target we are about to serve.
///
/// Injecting d_drops the cached dentry for that name, and a mount hangs off a
/// specific (vfsmount, dentry) pair — so injecting over a live mount detaches
/// it from path resolution, umount2 then fails with EINVAL even with
/// MNT_DETACH, and the entry is stranded in mountinfo until reboot. Absorb runs
/// after boot and cannot undo that, so a module whose own script mounts earlier
/// than this pass would leave a permanent entry behind. Seen in the field: a
/// bootanimation module binding at post-fs-data, injected over here, two
/// unremovable mounts.
fn unmount_before_serving(targets: &std::collections::HashSet<PathBuf>, target: &Path) {
    if !targets.contains(target) {
        return;
    }
    if crate::absorb::umount_detach(target) {
        eprintln!("nomount: unmounted {} before serving it", target.display());
    } else {
        eprintln!(
            "nomount: {} is mounted and will not unmount; serving it anyway would strand \
             that mount in mountinfo, so it is left alone",
            target.display()
        );
    }
}

/// Does applying this whiteout leave a measurable hole? It is APPLIED either
/// way now — this only decides whether the trade gets reported.
///
/// POLICY (2026-08-17): a module whiteout off overlayfs used to be declined, and
/// as of engine v13 most of them leave no hole at all -- the kernel recomputes
/// the parent's size and nlink from the listing it serves. What remains is the
/// multi-block erofs case, where the padding has no closed form. Originally:
/// because on erofs a directory's own metadata describes its contents exactly
/// (`st_size == 12*(entries incl . and ..) + name bytes`) and hiding an entry
/// without moving the size is something no real filesystem does. That protected
/// against a detector that stats a directory and counts its entries — at the
/// price of silently neutering every module built on `.replace`. A survey of 197
/// popular modules found ~14% of them are exactly that: debloaters, DRM
/// disablers, OTA removers, which ship no files and consist ENTIRELY of hides.
/// They installed, reported success, and did nothing.
///
/// The trade was judged the wrong way round. A real bind mount — what magic
/// mount uses for the same job — leaves a mountinfo entry plus a foreign
/// filesystem's size, block count and statfs type on a ROM path: strictly louder
/// than a directory whose size is stale by one entry. So the hide now happens,
/// and `doctor` names the paths that carry the hole instead of hiding the fact.
///
/// The proper fix is kernel-side (correct the parent's size and nlink in
/// getattr); until then this is the honest default.
pub(crate) fn whiteout_leaves_hole(target: &Path) -> bool {
    if !crate::whiteout::measurable_hole(target) {
        return false;
    }
    // Cached: this is called once per planned whiteout (and again in the doctor
    // rollup), and each call re-read and re-parsed whiteouts.txt from disk.
    static FORCED: std::sync::OnceLock<HashSet<PathBuf>> = std::sync::OnceLock::new();
    let forced = FORCED.get_or_init(|| {
        crate::whiteout::read().unwrap_or_default().into_iter().map(PathBuf::from).collect()
    });
    !forced.contains(target)
}

fn whiteout_allowed(target: &Path, module: &str) -> bool {
    if whiteout_leaves_hole(target) {
        eprintln!(
            "nomount: applying whiteout {} from {module}: its parent is multi-block erofs (or \
             the engine predates v13), so the size and link count still count the hidden entry \
             and cannot be recomputed. Applied because declining it would make {module} a \
             no-op; see `nomount doctor`.",
            target.display()
        );
    }
    true
}

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
                plan_tree(&id, &mdir, &e.path(), &mut plan);
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
        // Two different ways a planned entry never becomes a rule. Both were
        // silent before: the module installs, the manager says enabled, nothing
        // happens. A debloat module is ENTIRELY these entries, so "planned" read
        // as "working" when it did nothing at all.
        let note = if !source_resolves(e) {
            "  << UNSERVABLE: source does not resolve, no rule will be created"
        } else if e.kind == PlanKind::Whiteout && whiteout_leaves_hole(&e.target) {
            "  << applied, but the parent's size/nlink still count it (multi-block erofs)"
        } else {
            ""
        };
        println!("{k:8} {} <- {} [{}]{note}", e.target.display(), e.source.display(), e.module);
    }
    let binds = plan.iter().filter(|e| e.kind == PlanKind::Bind).count();
    let dead = plan.iter().filter(|e| !source_resolves(e)).count();
    let declined = plan.iter()
        .filter(|e| e.kind == PlanKind::Whiteout && whiteout_leaves_hole(&e.target))
        .count();
    let mut extra = String::new();
    if dead > 0 { extra.push_str(&format!(", {dead} unservable")); }
    if declined > 0 { extra.push_str(&format!(", {declined} whiteout(s) leaving a measurable hole")); }
    println!("({} entries: {} binds, {skipped} blocklisted{extra})", plan.len(), binds);
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
fn parse_live_rules(list: &str) -> HashMap<(PathBuf, u32), LiveRule> {
    let mut out = HashMap::new();
    for l in list.lines() {
        // Keep the UID: it is part of a rule's identity. Collapsing it meant a
        // per-UID rule and a global one for the same target shared a key, and
        // `nm del <target>` (always uid 0) could never remove the per-UID one --
        // so it re-counted as a failure on every reload, forever.
        let uid: u32 = l
            .split_once(" [UID:")
            .and_then(|(_, r)| r.trim_start().trim_end_matches(']').trim().parse().ok())
            .unwrap_or(0);
        let l = l.split(" [UID:").next().unwrap_or(l).trim();
        if l.is_empty() {
            continue;
        }
        if let Some(t) = l.strip_suffix(" (whiteout)") {
            out.insert((PathBuf::from(t.trim()), uid), LiveRule::Whiteout);
        } else if l.ends_with(" (virtual dir)") {
            continue;
        } else if let Some((t, s)) = l.rsplit_once(" -> ") {
            out.insert((PathBuf::from(t.trim()), uid), LiveRule::Inject(PathBuf::from(s.trim())));
        }
    }
    out
}

/// May the reconcile drop this live rule?
///
/// Only when the module plan does not want it AND neither durable list claims it.
/// `wanted` is the plan's answer; the two sets are the rules the plan structurally
/// cannot describe -- a stock path hidden by `nomount whiteout add`, and a rule
/// `absorb` created from another module's bind.
fn prunable(
    target: &Path,
    wanted: bool,
    durable_whiteouts: &HashSet<PathBuf>,
    absorbed: &HashSet<PathBuf>,
) -> bool {
    !wanted && !durable_whiteouts.contains(target) && !absorbed.contains(target)
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
    let mut desired_bind_src: HashMap<&Path, &Path> = HashMap::new();
    for e in &plan {
        match e.kind {
            PlanKind::Bind => {
                desired_bind_src.insert(e.target.as_path(), e.source.as_path());
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

    // Rules the Suite wants that no MODULE plan can account for. The prune pass
    // below drops every live rule the plan does not name, and these two are named
    // nowhere in it:
    //   * a durable whiteout (`nomount whiteout add`) hides a STOCK path, so it has
    //     no module and no backing file;
    //   * an absorbed rule came from another module's bind, whose source may sit at
    //     any path inside that module -- including ones the plan walk never visits.
    // Both were therefore deleted by a single Reload while their on-disk list still
    // said "applied", and neither came back until a reboot: the whiteout stopped
    // hiding, and the absorbed content silently reverted to the stock file.
    let durable_whiteouts: HashSet<PathBuf> =
        crate::whiteout::read().unwrap_or_default().into_iter().map(PathBuf::from).collect();
    let absorbed = crate::absorb::absorbed_targets();

    let (mut added, mut changed, mut removed, mut failed) = (0u32, 0u32, 0u32, 0u32);
    // Add new rules, and re-apply a live rule whose SOURCE or KIND changed (not
    // just presence): a target moving between modules or flipping inject<->whiteout
    // must update, or the stale rule would be frozen until a full mount.
    let mounted = crate::absorb::mounted_targets();
    for (t, e) in &desired_hookless {
        let up_to_date = match live.get(&((*t).to_path_buf(), 0)) {
            Some(LiveRule::Inject(src)) => {
                e.kind == PlanKind::Inject && src.as_path() == e.source.as_path()
            }
            Some(LiveRule::Whiteout) => e.kind == PlanKind::Whiteout,
            None => false,
        };
        if up_to_date {
            continue;
        }
        // No point issuing an add that cannot produce a rule; counting it as
        // applied is the overcount this guards against.
        if !source_resolves(e) {
            failed += 1;
            continue;
        }
        let existed = live.contains_key(&((*t).to_path_buf(), 0));
        if existed {
            let _ = nm.del(&e.target); // drop the stale rule before re-adding
        }
        unmount_before_serving(&mounted, &e.target);
        let r = match e.kind {
            PlanKind::Inject => nm.add(&e.target, &e.source),
            PlanKind::Whiteout => {
                if !whiteout_allowed(&e.target, &e.module) {
                    continue;
                }
                nm.whiteout(&e.target)
            }
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
    // Re-apply any durable whiteout the engine is not currently serving, so a
    // reload CONVERGES on the saved list instead of merely not destroying it.
    for w in &durable_whiteouts {
        if live.contains_key(&(w.clone(), 0)) {
            continue;
        }
        // Same gate `whiteout::apply` uses. Without it a hand-edited entry that
        // apply() refuses (a partition root, a /data path) would still be pushed
        // to the engine from here -- the two paths must agree on what is legal.
        if crate::whiteout::validate(&w.to_string_lossy()).is_err() {
            eprintln!("nomount: skipping invalid whiteout entry {}", w.display());
            failed += 1;
            continue;
        }
        match nm.whiteout(w) {
            Ok(()) => added += 1,
            Err(_) => failed += 1,
        }
    }

    // Remove live rules no longer desired (skip any that are now bind targets,
    // and anything durable/absorbed that the module plan cannot describe).
    for (t, _uid) in live.keys() {
        let wanted = desired_hookless.contains_key(t.as_path())
            || desired_bind_src.contains_key(t.as_path());
        if !prunable(t, wanted, &durable_whiteouts, &absorbed) {
            continue;
        }
        if nm.del(t).is_ok() {
            removed += 1;
        } else {
            failed += 1;
        }
    }

    // Reconcile my_* binds against binds.list, keyed on (target, source): a bind
    // whose backing source changed must re-bind, not just added/removed targets.
    let live_binds = crate::bind::tracked();
    let (mut bind_added, mut bind_removed) = (0u32, 0u32);
    // Umount any live bind not desired at its current source (removed OR changed);
    // a changed backing is dropped here so apply() below re-binds the new source.
    for (t, s) in &live_binds {
        if desired_bind_src.get(t.as_path()).copied() != Some(s.as_path()) {
            crate::bind::umount_one(t);
            bind_removed += 1;
        }
    }
    // Still-correct binds (right target AND source) are already mounted; skip them.
    let live_ok: HashSet<&Path> = live_binds
        .iter()
        .filter(|(t, s)| desired_bind_src.get(t.as_path()).copied() == Some(s.as_path()))
        .map(|(t, _)| t.as_path())
        .collect();
    for e in plan.iter().filter(|e| e.kind == PlanKind::Bind) {
        if !live_ok.contains(e.target.as_path()) {
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

    // Measure the ROM's directory shape and tell the engine, BEFORE any rule
    // exists: a synthesized dir inherits its parent's superblock, which on an
    // overlay-backed path is overlayfs and says nothing about the layer whose
    // shape its stock siblings show. Userspace can just read a directory and
    // check, so it does; a failure to prove it leaves the engine as it was.
    let packed = crate::dirshape::rom_dirs_are_dirent_packed();
    if let Err(e) = nm.set_dir_shape(packed) {
        eprintln!("nomount: could not set the directory-shape knob: {e:#}");
    }

    // Start clean so uninstalled/updated modules don't leave stale rules, and tear
    // down any my_* binds from the previous pass so removed modules don't leak one.
    let _ = nm.clear();
    // `clear` dropped the kernel's hidden-UID set along with the rules — per-UID
    // hiding is runtime state and CLEAR_ALL is its reset. Without this, every mount
    // pass after boot (the WebUI's Re-apply button is one) silently unhid every app
    // on the list for the rest of the session.
    //
    // Re-hide BEFORE the rules go back in, not after: hiding is per-UID state that
    // does not depend on any rule existing, so asserting it first means a hidden app
    // is never able to observe the window in which the pass is adding injections.
    // Resolved from the cached appid mirror, so this also works at post-fs-data,
    // before `packages.list` is meaningful — apps are hidden from the moment the
    // injections exist rather than from boot_completed onwards.
    let hidden = crate::cli::handlers::reapply_blocklist(&nm, true);
    crate::bind::teardown_all();
    // `clear` dropped every absorbed rule too, so the record of them is now a lie.
    // Left behind, `reload` would protect targets that no longer carry a rule.
    // service.sh re-runs absorb after boot and repopulates it.
    crate::absorb::set_absorbed(&[]);

    let (plan, skipped) = collect_plan();
    let mut served: HashSet<&str> = HashSet::new();
    let mut binds = 0u32;
    let mut st = Stats {
        applied: 0,
        failed: 0,
        whiteouts: 0,
    };
    let mounted = crate::absorb::mounted_targets();
    for e in &plan {
        served.insert(e.module.as_str());
        unmount_before_serving(&mounted, &e.target);
        match e.kind {
            PlanKind::Whiteout => {
                if !whiteout_allowed(&e.target, &e.module) {
                    continue;
                }
                match nm.whiteout(&e.target) {
                    Ok(()) => st.whiteouts += 1,
                    Err(_) => st.failed += 1,
                }
            }
            PlanKind::Inject if !source_resolves(e) => st.failed += 1,
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
         {skipped} skipped | {} hidden{} | {surface}",
        st.applied,
        st.whiteouts,
        st.failed,
        hidden.hidden,
        if hidden.failed > 0 { format!(", {} hide failed", hidden.failed) } else { String::new() }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of `serve_mode` is that absorb gets the SAME answer this
    /// file acts on, so these are the cases where the two used to disagree.
    #[test]
    fn serve_mode_refuses_what_plan_tree_refuses() {
        assert_eq!(serve_mode(Path::new("/system/bin/x")), Serve::Inject);
        assert_eq!(serve_mode(Path::new("/product/etc/foo.xml")), Serve::Inject);
        // my_* is bind-served unless the experimental flag is on.
        if !my_hookless_enabled() {
            assert_eq!(serve_mode(Path::new("/my_product/app/Foo/Foo.apk")), Serve::Bind);
        }
        // NON_PARTITION_ROOTS, a bare partition root, and the filesystem root.
        assert!(matches!(serve_mode(Path::new("/apex/com.android.art/x")), Serve::Refuse(_)));
        assert!(matches!(serve_mode(Path::new("/data/adb/x")), Serve::Refuse(_)));
        assert!(matches!(serve_mode(Path::new("/system")), Serve::Refuse(_)));
        assert!(matches!(serve_mode(Path::new("/")), Serve::Refuse(_)));
    }

    /// A Reload used to delete every durable whiteout and every absorbed rule,
    /// because neither appears in any module plan. The on-disk lists still said
    /// "applied", so the hide simply stopped and the absorbed content reverted.
    #[test]
    fn reload_never_prunes_durable_or_absorbed_rules() {
        let durable: HashSet<PathBuf> = ["/system/etc/tell.conf"].iter().map(PathBuf::from).collect();
        let absorbed: HashSet<PathBuf> = ["/system/etc/absorbed.xml"].iter().map(PathBuf::from).collect();
        let none = HashSet::new();

        // Claimed by a durable list -> never pruned, even though no plan wants it.
        assert!(!prunable(Path::new("/system/etc/tell.conf"), false, &durable, &absorbed));
        assert!(!prunable(Path::new("/system/etc/absorbed.xml"), false, &durable, &absorbed));
        // Wanted by the plan -> never pruned either.
        assert!(!prunable(Path::new("/system/app/Foo.apk"), true, &none, &none));
        // Claimed by nobody -> this is the stale rule prune exists for.
        assert!(prunable(Path::new("/system/app/Gone.apk"), false, &durable, &absorbed));
    }

    #[test]
    fn live_rules_are_keyed_including_uid() {
        let m = parse_live_rules("/a -> /b\n/a -> /c [UID: 1000]\n/d (whiteout)\n/e (virtual dir)\n");
        assert_eq!(m.len(), 3);
        assert!(m.contains_key(&(PathBuf::from("/a"), 0)));
        assert!(m.contains_key(&(PathBuf::from("/a"), 1000)));
        assert!(m.contains_key(&(PathBuf::from("/d"), 0)));
    }
}
