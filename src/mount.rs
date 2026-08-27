//! Metamodule mount pass for the NoMount Suite.
//!
//! For every enabled module the Suite classifies content and routes it:
//! - `.replace` markers / char devices  → whiteout via `nm w`
//! - everything else (files, symlinks)  → hookless VFS redirect via `nm add`
//!
//! RRO overlay APKs are NOT special-cased and there is no overlayfs mount: their
//! APKs are injected into e.g. `/product/overlay` like any other file, and
//! OverlayManagerService + idmap2 pick them up at the system_server scan, which
//! runs after this post-fs-data pass. See `resolve_dir` below. Zero mounts total.
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
///
/// `lgetxattr`, not `getxattr`: `p` is a path inside a module tree, and the plain
/// call follows symlinks -- so a module symlinking to a directory that carries
/// the attribute would have its link read as an opaque whiteout marker, expanding
/// into a whiteout per stock entry of a directory the module never named. A
/// symlink is never itself an opaque dir, so ENODATA is the right answer.
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
        libc::lgetxattr(path.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len())
    };
    n > 0 && buf[0] == b'y'
}
#[cfg(not(unix))]
fn is_opaque_dir(_p: &Path) -> bool { false }

use anyhow::{Context, Result};

use crate::nm::Nm;

pub(crate) const MODULES_DIR: &str = "/data/adb/modules";
/// Serialises the whole-engine passes (`mount`, `reload`, `absorb`) against each
/// other. `run_mount` opens with `nm.clear()`, so a concurrent reload/absorb could
/// see the engine momentarily empty (or two passes could interleave adds and
/// prunes). One process-wide advisory flock closes that window.
const PASS_LOCK: &str = "/data/adb/nomount/pass.lock";

/// RAII holder for the pass lock; the flock releases when it drops.
pub(crate) struct PassLock(std::fs::File);

/// How long a pass will wait for another pass before giving up and running
/// unserialised. Bounded on purpose -- see `pass_lock`.
/// Shared with `bind::Lock`, which is the other engine-wide lock and must not
/// out-wait this one (see its `acquire`).
pub(crate) const PASS_LOCK_WAIT: u64 = 25;

/// Take the process-wide pass lock. Best-effort: a failure to create or lock the
/// file must never block boot, so this returns `None` and the caller proceeds
/// unserialised rather than aborting. Held for the whole pass via the returned
/// guard.
///
/// The wait is BOUNDED (`LOCK_NB` in a retry loop, not a blocking `LOCK_EX`).
/// An unbounded wait here reaches much further than this function:
/// * `service.sh` runs `absorb` in the FOREGROUND and un-timed, and everything
///   after it -- whiteout apply, the authoritative `uid apply`, the package
///   watcher, the selfcheck canary -- is gated on it returning. A WebUI-driven
///   `reload` at the wrong moment would stall per-UID hiding for the rest of the
///   boot, with nothing in the log saying why.
/// * `uidwatch.sh` reaps its own handler lock once its mtime is >= 60s old, on
///   the reasoning that only a SIGKILLed handler leaves one behind. A handler
///   merely WAITING here is indistinguishable from a dead one, so it would be
///   reaped, and mutual exclusion is lost for the rest of the session.
///
/// Timing out and proceeding unserialised is the lesser evil: the passes are
/// idempotent, and a missed serialisation is recoverable where a stalled boot is
/// not. Say so on stderr so it is not silent.
pub(crate) fn pass_lock() -> Option<PassLock> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false) // the file only carries the flock; never clobber it
        .mode(0o600)
        .open(PASS_LOCK)
        .ok()?;
    for _ in 0..(PASS_LOCK_WAIT * 10) {
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Some(PassLock(f));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    eprintln!(
        "nomount: another pass still holds {PASS_LOCK} after {PASS_LOCK_WAIT}s; \
         continuing unserialised rather than stalling the boot"
    );
    None
}

impl Drop for PassLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

// Modules that do their own mounting/redirection (or ship their own su, like a
// kernelnosu module) — injecting their files double-handles the same targets, and
// for a su binary would break root. Extend at runtime via the blocklist file.
const BUILTIN_BLOCKLIST: &[&str] = &["kernelnosu", "scene_swap_controller", "AAaTempSpoof"];
// NOTE: module ids, one per line — NOT the per-app hide list. The two shared this
// path until v1.3.13: hiding an app also told this pass to skip a module of that
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
// `d` is the debugfs shortcut (`/d -> /sys/kernel/debug`), and it is listed
// because discovery FOLLOWS symlinks: `/d`.is_dir() answers true, so a module
// shipping a top-level `d/` tree was walked and its files injected into debugfs
// (measured on an OP15). Nothing belonging to a ROM partition lives there.
// `/etc -> /system/etc` is deliberately NOT listed: that symlink points at real
// ROM content, so an inject through it lands on the same dentry as the
// `system/etc` path a module would normally ship.
const NON_PARTITION_ROOTS: &[&str] = &[
    "data", "data_mirror", "mnt", "dev", "proc", "sys", "cache", "metadata", "config",
    "storage", "sdcard", "apex", "tmp", "debug_ramdisk", "linkerconfig",
    "postinstall", "second_stage_resources", "bin", "sbin", "d",
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
/// A partition root (`/system`, `/product`) -- or `/` itself.
///
/// The `== 1` test alone answered FALSE for `/`, which has zero components after
/// the root: the one path where serving a rule is most catastrophic was the one
/// path this said was fine. Nothing reached it that way in practice (`serve_mode`
/// refuses `/` for want of a partition component, and the kernel's
/// `nm_target_too_shallow` refuses it again), but a predicate named
/// `is_partition_root` returning false for the filesystem root is a trap for the
/// next caller. `<= 1` says what the name claims.
fn is_partition_root(target: &Path) -> bool {
    target.components().skip(1).count() <= 1
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
///
/// The claim was only half true until M-S10: `plan_tree` never actually CALLED
/// this, it re-implemented a subset, and the subset was weaker again --
/// `NON_PARTITION_ROOTS` was enforced only where module roots are discovered, so
/// a module shipping a top-level `d/` tree was walked and injected into debugfs.
/// Every plan entry that is served now routes through here, and a `Refuse` is a
/// skip with the reason printed.
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
    // `/product/product/...`, `/system/system/...`: the path repeats a partition
    // name, which no module can mean. It is what the installer's partition
    // handler produces when a module ships BOTH a top-level `product/` and a
    // `system/product/` -- it moves the second INTO the first instead of merging
    // them, nesting the subtree one level too deep.
    //
    // Serving it anyway is worse than doing nothing: the content appears at a
    // directory the ROM does not have, so nothing that wants the file finds it
    // there, and the engine has materialised a top-level directory whose sole
    // contents are injected -- a free existence oracle, for a path that helps
    // nobody. Refuse, and let `doctor` tell the user to ship one layout or the
    // other. Measured on an OP15: a module shipping both produced
    // /product/product/etc/... and every rule involved looked healthy.
    if let Some(second) = target.components().nth(2).and_then(|c| c.as_os_str().to_str()) {
        if second == root && is_partition_root(Path::new(&format!("/{root}"))) {
            return Serve::Refuse(
                "the path repeats a partition name -- the module ships both `<part>/` and \
                 `system/<part>/`, and the installer nested one inside the other",
            );
        }
    }
    if is_my_partition(target) && !my_hookless_enabled() {
        return Serve::Bind;
    }
    Serve::Inject
}

/// May a whiteout be applied to `target`?
///
/// Deliberately NOT `serve_mode`. A whiteout serves nothing: no bind, no
/// injection, no source file behind it -- the engine just d_drops the dentry.
/// That is the same operation `nomount whiteout add` performs, and it works on
/// every ROM partition including `my_*`. So the Bind/Inject split does not apply
/// here; the only refusals that carry over are the ones about WHICH path may be
/// touched at all, never HOW it would have been served.
///
/// This guard used to be `is_partition_root(t) || is_my_partition(t)`, on the
/// reasoning that "bind can't whiteout". True, but irrelevant -- a whiteout never
/// reaches bind.rs. The effect was that a module shipping a 0:0 char device under
/// `/my_product` or `/my_stock`, which is where OnePlus/Oppo keep a third of the
/// preinstalled apps, installed cleanly and hid nothing, silently. Verified on an
/// OP15 (CPH2747): the CLI hides `/my_stock/app/OplusOperationManual` live, while
/// the identical char device in a module tree was dropped from the plan.
pub(crate) fn can_whiteout(target: &Path) -> Result<(), &'static str> {
    let Some(root) = target.components().nth(1).and_then(|c| c.as_os_str().to_str()) else {
        return Err("not a path under a partition");
    };
    if NON_PARTITION_ROOTS.contains(&root) {
        return Err("not a ROM partition");
    }
    if is_partition_root(target) {
        return Err("a bare partition root (masking one bootloops zygote)");
    }
    Ok(())
}

/// A leaf inject must land on a FILE (or on nothing — a synthesized virtual
/// entry). If the resolved target is a live directory on-device, or a live
/// mountpoint, the module shipped a file or symlink named like a stock ROM
/// directory (`product/overlay`, `product/app`, `system/priv-app`), and a rule
/// there masks the WHOLE directory — the same stock-hiding, zygote-bootlooping
/// mistake `is_partition_root` guards one level up. `is_partition_root` only sees
/// depth-1 roots, so a deeper stock dir slips past it. Refuse those; a module's
/// real content still comes from its own directory entries, which recurse and
/// inject their leaves individually.
///
/// The mounted-set is read once and cached: `plan_tree` is recursive and each
/// `nomount` run is a fresh short-lived process, so a snapshot is correct for it.
fn inject_would_mask_dir(target: &Path) -> bool {
    // Only the DIRECTORY test belongs here. `is_dir()` follows symlinks, which is
    // the case this exists for: a module file or link resolving onto a stock
    // directory would be served as one directory rule and hide every stock entry
    // under it -- the masking that bootlooped zygote.
    //
    // A live MOUNT on the target is deliberately NOT refused here any more. It is
    // not a masking hazard (a bind over a file masks nothing), and refusing it at
    // plan time had two silent costs: `unmount_before_serving` -- whose whole job
    // is "unmount, then serve", and which since today returns false and skips
    // loudly when it cannot -- became unreachable for injects; and because
    // `collect_plan()` now runs BEFORE `bind::teardown_all()`, a mid-session
    // re-apply saw the previous pass's own binds still live and dropped every one
    // of those targets from the plan, leaving neither a bind nor an injection.
    target.is_dir()
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

pub(crate) fn module_enabled(dir: &Path) -> bool {
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
/// Separating "what we would do" from "doing it" is what lets `nomount check --plan`
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
/// Expand a "replace this directory" marker into rules the engine actually has.
///
/// `.replace` and `trusted.overlay.opaque=y` both mean the same thing: the
/// module's copy of a directory IS the directory, stock contents included. That
/// is overlayfs vocabulary, inherited from when this project magic-mounted, and
/// the hookless engine has no primitive for it. What it was translated into --
/// one whiteout on the PARENT, plus injects for the module's files inside it --
/// cannot work: the whiteout d_drops the directory, so every path beneath it
/// stops resolving and the injects underneath serve nothing. Measured on an OP15:
/// a `.replace` on `/system_ext/etc/perfetto-configs` shipping a byte-identical
/// copy of the stock file left `ls` reporting "No such file or directory", with
/// both the whiteout and the inject sitting in `nm list` looking healthy.
///
/// The engine does have the two primitives needed to express it exactly: a
/// whiteout hides ONE path, and an inject serves ONE path. So instead of hiding
/// the parent, hide each stock entry the module does not ship, and let the normal
/// walk inject the ones it does. Where the module ships a directory of its own,
/// recurse, so a partially-shipped subtree keeps the stock entries it does not
/// replace hidden rather than merged -- `.replace` means replace, not merge.
///
/// Whiteouts land on leaves and on whole unshipped subdirectories, never on the
/// parent being replaced, so nothing d_drops a path this module still serves.
fn expand_replacement(
    module: &str,
    stock_dir: &Path,
    module_dir: &Path,
    marker: &Path,
    depth: u32,
    out: &mut Vec<PlanEntry>,
) {
    // A stock tree deep enough to hit this is not a module layout; stop rather
    // than walk something pathological (or a symlink loop we failed to spot).
    if depth > 16 {
        eprintln!(
            "nomount: {module}: giving up expanding {} past depth 16",
            stock_dir.display()
        );
        return;
    }
    let stock_entries = match fs::read_dir(stock_dir) {
        Ok(e) => e,
        // No stock directory to replace: the module's content is simply served,
        // and the engine materialises the parent as a virtual dir on its own.
        Err(_) => return,
    };
    let mut entries: Vec<_> = stock_entries.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name();
        let stock_child = stock_dir.join(&name);
        let module_child = module_dir.join(&name);

        // lstat, not stat: a stock symlink the module does not ship must be
        // hidden as the link it is, never followed to whatever it points at.
        let shipped = fs::symlink_metadata(&module_child).ok();
        let stock_is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);

        match shipped {
            // Shipped as a directory over a stock directory: recurse, so the
            // stock entries the module does not replace inside it still go.
            Some(m) if m.is_dir() && stock_is_dir => {
                expand_replacement(module, &stock_child, &module_child, marker, depth + 1, out);
            }
            // Shipped at all, otherwise: the module's own file wins here and the
            // ordinary walk emits its inject. Nothing to hide.
            Some(_) => {}
            // Not shipped: this is what "replace" is for.
            None => {
                if can_whiteout(&stock_child).is_err() {
                    continue;
                }
                out.push(PlanEntry {
                    module: module.to_string(),
                    target: stock_child,
                    // Provenance for `plan`/`doctor`: the marker that asked for this,
                    // which is the `.replace` file or the opaque directory itself.
                    source: marker.to_path_buf(),
                    kind: PlanKind::Whiteout,
                });
            }
        }
    }
}

/// One target claimed by more than one module: the winner, and who it beat.
pub(crate) struct Collision {
    pub target: PathBuf,
    pub winner: String,
    pub losers: Vec<String>,
}

/// Collapse entries claiming the same target, keeping the LAST.
///
/// The plan is sorted, so "last" is the last module name alphabetically, which
/// is the documented precedence. This used to be left to `nm.add` overwriting
/// the earlier rule, and that only works for SOME targets. Measured on an OP15,
/// engine v26, with two sources of different content:
///
///     /system/etc/x.txt      (real ROM dir)  add A, add B -> serves B  ok
///     /system/etc/nmt/x.txt  (virtual dir)   add A, add B -> serves A  WRONG
///
/// A directory the engine materialised itself keeps serving whichever source
/// got there first; the rule table takes the second either way. A contested
/// target is very often inside such a directory, because two modules shipping
/// the same new path both cause it to be synthesised -- which is exactly how
/// this was found.
///
/// When it goes wrong the table and the filesystem disagree, `selfcheck`
/// reports consistency=ok throughout (its canary compares root's view against
/// an unprivileged uid's, never the served bytes against the rule's source),
/// and neither `vfs refresh` nor `reload` heals it -- reload reconciles against
/// the table, which is already correct, so it computes no delta at all. Only
/// del+add re-points, which is what `absorb::add_repointing` does for the same
/// reason.
///
/// Applying each target exactly once sidesteps the whole thing and makes the
/// documented precedence true instead of aspirational. The collisions are
/// returned rather than swallowed so the caller can say what it dropped.
pub(crate) fn dedupe_by_target(plan: Vec<PlanEntry>) -> (Vec<PlanEntry>, Vec<Collision>) {
    let mut last: HashMap<PathBuf, usize> = HashMap::new();
    for (i, e) in plan.iter().enumerate() {
        last.insert(e.target.clone(), i);
    }
    if last.len() == plan.len() {
        return (plan, Vec::new());
    }
    let mut losers: HashMap<PathBuf, Vec<String>> = HashMap::new();
    for (i, e) in plan.iter().enumerate() {
        if last.get(&e.target) != Some(&i) {
            losers.entry(e.target.clone()).or_default().push(e.module.clone());
        }
    }
    let mut collisions: Vec<Collision> = Vec::new();
    let mut kept = Vec::with_capacity(last.len());
    for (i, e) in plan.into_iter().enumerate() {
        if last.get(&e.target) != Some(&i) {
            continue;
        }
        if let Some(mut l) = losers.remove(&e.target) {
            // Only a contest between DIFFERENT modules is worth reporting. One
            // module can reach the same target twice on its own -- shipping both
            // `vendor/etc/x` and `system/vendor/etc/x`, which the SAR alias folds
            // together -- and printing "claimed by 2, serving M, skipping M"
            // describes a conflict that does not exist. doctor already dedupes
            // module names for its own collision check, so reporting it here made
            // the two disagree.
            l.retain(|m| m != &e.module);
            l.sort_unstable();
            l.dedup();
            if !l.is_empty() {
                collisions.push(Collision {
                    target: e.target.clone(),
                    winner: e.module.clone(),
                    losers: l,
                });
            }
        }
        kept.push(e);
    }
    collisions.sort_by(|a, b| a.target.cmp(&b.target));
    (kept, collisions)
}

fn plan_tree(module: &str, module_root: &Path, dir: &Path, out: &mut Vec<PlanEntry>) {
    // Sorted, not raw readdir order. Two modules may claim the same target (doctor
    // reports it as "target claimed twice"), and the LAST plan entry wins -- which
    // `dedupe_by_target` then enforces by applying only that one, because the
    // engine does not re-point an inode when a second rule lands on its target.
    // readdir order is the filesystem's, so the winner could differ between two
    // boots of an unchanged device. Sorting makes the precedence stable and
    // explainable (last name alphabetically wins) instead of incidental.
    let mut entries: Vec<_> = match fs::read_dir(dir) {
        Ok(e) => e.flatten().collect(),
        Err(_) => return,
    };
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
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
            // directory underneath. We read the other two markers and were blind to
            // this one, so such a module installed cleanly and hid nothing: an empty
            // opaque dir has no files, so plan_tree recursed into it and emitted
            // nothing at all.
            //
            // This used to name PlayIntegrityFork as the module taking this branch
            // on KernelSU/APatch. Not on the device this is developed against: the
            // installed PIF ships no system tree at all (classes.dex, pif.prop and
            // boot scripts only) and the plan plans zero entries for it. Across all
            // 16 modules on that OP15 there are no `.replace` markers and no opaque
            // dirs — the plan reports 0 whiteouts, which is the engine confirming
            // it. So treat this branch as supported-but-unexercised here rather than
            // as the common path, and do not assume any particular module needs it.
            // Expanded into per-entry whiteouts rather than one on this directory:
            // see expand_replacement. my_* rides along safely now -- what it
            // emits are leaf deletions, which the engine serves on my_* like
            // anywhere else, not the parent whiteout that made this unsafe.
            //
            // Gated on `can_whiteout`, the shared predicate, rather than on a local
            // partition-root test: what an expansion emits are whiteouts, so the
            // question is whether this directory is one we may hide entries under at
            // all -- which also rules out a non-ROM root the old test let through.
            if is_opaque_dir(&source) && can_whiteout(&target).is_ok() {
                expand_replacement(module, &target, &source, &source, 0, out);
            }
            plan_tree(module, module_root, &source, out);
        } else if name == ".replace" {
            // Whiteout the parent dir (module wants to replace, not merge, it).
            // Never whiteout a bare partition root: masking a whole partition bootloops
            // (forkSystemServer SIGABRT), exactly as an inject on a root does below.
            if let Some(parent) = target.parent() {
                // Never touch a bare partition root: replacing a whole partition
                // is not something a module can mean, and masking one bootloops.
                // `can_whiteout` is that test plus the non-ROM roots, and it is the
                // same predicate the expansion applies to each entry it emits.
                if can_whiteout(parent).is_err() {
                    continue;
                }
                // Expand instead of whiteouting `parent` itself -- a whiteout there
                // d_drops the directory and the module's own injects underneath it
                // stop resolving. See expand_replacement.
                if let Some(module_dir) = source.parent() {
                    expand_replacement(module, parent, module_dir, &source, 0, out);
                }
            }
        } else if is_char_dev(&ft) {
            // A 0:0 char device is Magisk's whiteout marker: a pure deletion, with
            // no module content behind it. `can_whiteout` is the whole guard -- and
            // deliberately NOT `serve_mode`, see its doc: it permits my_*, where the
            // engine d_drops a dentry as readily as anywhere else, which is what
            // `nomount whiteout add` has always done there.
            if can_whiteout(&target).is_err() {
                continue;
            }
            out.push(PlanEntry {
                module: module.to_string(),
                target,
                source,
                kind: PlanKind::Whiteout,
            });
        } else {
            // Every servable entry goes through the ONE predicate (M-S10). The plan
            // used to re-derive a weaker subset of it here -- `is_partition_root` +
            // `is_my_partition`, with `NON_PARTITION_ROOTS` enforced only at module-root
            // discovery -- which is how the plan and absorb drifted apart once already:
            // absorb refused targets this file happily injected. A refusal is now
            // skipped WITH its reason, because a module whose content silently vanishes
            // is the failure mode this project keeps re-fixing.
            match serve_mode(&target) {
                Serve::Refuse(why) => {
                    // The common one is a module's layout-convergence symlink
                    // (`system/product -> ../product`), which resolves to a bare
                    // partition root: injecting it would redirect the whole partition.
                    // The real content still comes from the module's own top-level
                    // partition dir, and real `system/<partition>` DIRECTORIES are
                    // unaffected -- they take the is_dir() branch above and recurse.
                    eprintln!("nomount: {module}: skipping {} — {why}", target.display());
                }
                Serve::Bind => {
                    // my_* is served by a real bind: hookless there trips zygote's FD
                    // allowlist. Whether the experimental NM_MY_HOOKLESS override is on
                    // is `serve_mode`'s business now, not this walk's.
                    //
                    // Always served. This used to be skipped when a text heuristic decided
                    // the module's boot scripts "looked like" they mounted my_* themselves,
                    // which silently dropped the module's ENTIRE my_* content on a grep over
                    // shell source -- unpredictable, and invisible when it misfired. If a
                    // module does bind its own path, that real mount simply takes precedence.
                    out.push(PlanEntry {
                        module: module.to_string(),
                        target,
                        source,
                        kind: PlanKind::Bind,
                    });
                }
                // H16, kept in the inject arm where it belongs (a bind d_drops
                // nothing): resolves to a live stock directory, or a mountpoint, one
                // or more levels below a partition root -- injecting a file there masks
                // the whole directory. See `inject_would_mask_dir`; this is the depth-2+
                // case a partition-root test cannot see (e.g. a module file named
                // `overlay`).
                Serve::Inject if inject_would_mask_dir(&target) => {
                    eprintln!(
                        "nomount: {module}: skipping {} — it resolves to a live directory/mountpoint; \
                         injecting a file there would mask the whole directory (a module may only \
                         inject over a file)",
                        target.display()
                    );
                }
                Serve::Inject => out.push(PlanEntry {
                    module: module.to_string(),
                    target,
                    source,
                    kind: PlanKind::Inject,
                }),
            }
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
/// Returns whether it is now safe to serve `target` — i.e. nothing is mounted on
/// it any more. The caller must NOT serve when this is false: injecting over a
/// live mount strands it in mountinfo forever (the old fn returned `()` and the
/// caller served regardless, which is exactly that leak).
fn unmount_before_serving(targets: &std::collections::HashSet<PathBuf>, target: &Path) -> bool {
    if !targets.contains(target) {
        return true; // nothing was mounted here; serving is safe
    }
    if crate::absorb::umount_detach(target) {
        eprintln!("nomount: unmounted {} before serving it", target.display());
    }
    // Authoritative: umount2 reports EINVAL both for a stranded peer under shared
    // propagation (fine) and a still-live mount (not fine). `still_mounted` asks
    // mountinfo, which distinguishes them.
    let gone = !crate::absorb::still_mounted(target);
    if !gone {
        eprintln!(
            "nomount: {} is still mounted and will not unmount; serving it anyway would strand \
             that mount in mountinfo, so it is left unserved",
            target.display()
        );
    }
    gone
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

/// Warn (only) when a whiteout will leave a measurable hole. It is always APPLIED
/// -- declining would silently neuter a debloat module -- so this returns nothing.
/// It used to return `bool` (always `true`), and every caller wrote
/// `if !whiteout_allowed(...) { continue; }`, a dead branch that read as a real gate.
fn warn_whiteout_hole(target: &Path, module: &str) {
    if whiteout_leaves_hole(target) {
        eprintln!(
            "nomount: applying whiteout {} from {module}: its parent is multi-block erofs (or \
             the engine predates v13), so the size and link count still count the hidden entry \
             and cannot be recomputed. Applied because declining it would make {module} a \
             no-op; see `nomount check --plan`.",
            target.display()
        );
    }
}

/// `Err` when the module tree could not be ENUMERATED, which is not the same as
/// "there are no modules". `run_mount` calls this, then `nm clear()`, then applies
/// the result -- so an empty-on-error plan wiped every rule and printed
/// `0 modules | 0 rules, ... 0 failed` with no error and exit 0. `run_reload` was
/// worse: it pruned every live rule and reported `-N rules` as if intended.
pub(crate) fn collect_plan() -> Result<(Vec<PlanEntry>, u32)> {
    let blocklist = load_blocklist();
    let mut plan = Vec::new();
    let mut skipped = 0u32;
    // Sorted for the same reason plan_tree sorts: a contested target must resolve
    // to the same module on every boot.
    let dirs = fs::read_dir(MODULES_DIR)
        .with_context(|| format!("cannot enumerate {MODULES_DIR} -- refusing to treat that as \"no modules installed\", which would clear every rule"))?;
    let mut dirs: Vec<_> = dirs.flatten().collect();
    dirs.sort_by_key(|e| e.file_name());
    for entry in dirs {
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
            let mut entries: Vec<_> = entries.flatten().collect();
            entries.sort_by_key(|e| e.file_name());
            for e in entries {
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
    Ok((plan, skipped))
}

/// Print the resolved plan without applying it: target, kind, source, module.
///
/// Restored after being cut as "zero callers". That was true inside this repo
/// and false outside it -- the NMT test harness parses this output to lint a
/// STAGED module before it is ever applied, which nothing else can do: `nm list`
/// shows live rules, and `check --plan` reports findings, not the resolution.
pub fn run_plan() -> Result<()> {
    let (plan, skipped) = collect_plan()?;
    // Same collapse run_mount applies, so `plan` describes what will actually be
    // served. Without it the output listed both halves of a contested target
    // while only one was ever applied.
    let (plan, _) = dedupe_by_target(plan);
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

/// The live leaf rules the reconcile diffs against, keyed by (target, UID):
/// injects and whiteouts. Engine-managed virtual dirs are dropped -- no rule
/// created them, so the prune pass has nothing to say about one.
///
/// The line reading is [`crate::nm::parse_list`], shared with `doctor` and
/// `absorb`; this only reshapes its rows. The three used to parse the same text
/// independently and had already disagreed on where to split a line, which is how
/// a source containing ` -> ` matched here and not there.
///
/// Keeping the UID in the key is load-bearing: collapsing it meant a per-UID rule
/// and a global one for the same target shared a key, and `nm del <target>`
/// (always uid 0) could never remove the per-UID one -- so it re-counted as a
/// failure on every reload, forever.
fn parse_live_rules(list: &str) -> HashMap<(PathBuf, u32), LiveRule> {
    crate::nm::parse_list(list)
        .into_iter()
        .filter_map(|r| {
            let kind = match r.kind {
                crate::nm::LiveKind::Inject => LiveRule::Inject(r.source?),
                crate::nm::LiveKind::Whiteout => LiveRule::Whiteout,
                crate::nm::LiveKind::VirtualDir => return None,
            };
            Some(((r.target, r.uid), kind))
        })
        .collect()
}

/// May the reconcile drop this live rule?
///
/// Only when the module plan does not want it AND neither durable list claims it.
/// `wanted` is the plan's answer; the two sets are the rules the plan structurally
/// cannot describe -- a stock path hidden by `nomount whiteout add`, and a rule
/// `absorb` created from another module's bind.
fn prunable(
    target: &Path,
    uid: u32,
    wanted: bool,
    durable_whiteouts: &HashSet<PathBuf>,
    absorbed: &HashSet<PathBuf>,
) -> bool {
    // Only the GLOBAL (uid 0) rules are the module plan's to prune. A per-UID rule
    // comes from the hide path, no module plan describes it, and `nm del` -- which
    // always addresses uid 0 -- cannot remove it anyway. Without this gate the
    // prune pass reached every per-UID rule, failed to delete it, and re-counted
    // it as a failure on every single reload, forever.
    uid == 0 && !wanted && !durable_whiteouts.contains(target) && !absorbed.contains(target)
}

/// `nomount reload`: gap-free hot load/unload. Diffs the desired plan against the
/// live rule set and applies ONLY the delta -- no `clear`, so injections never
/// drop. Install a module then reload => just its files go live; remove a module
/// then reload => just its files go away. Also reconciles my_* binds.
pub fn run_reload() -> Result<()> {
    let _pass = pass_lock(); // serialise against a concurrent mount/absorb (M-S9)
    let nm = Nm::new();
    nm.version()
        .context("hookless NoMount engine not responding -- is the CONFIG_NOMOUNT kernel loaded?")?;

    let (plan, skipped) = collect_plan()?;

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
    // NOT unwrap_or_default(). These two sets are the only thing standing between
    // the prune loop below and every durable whiteout / absorbed rule on the
    // device: collapsing an I/O error to an empty set deletes all of them and
    // counts them into `removed`, so `reload` prints `-37 rules ... (gap-free)`
    // while the on-disk lists still say "applied" and nothing comes back until a
    // reboot. That is the regression the `reload_never_prunes_durable_or_absorbed_rules`
    // test pins, reached through the error path the test does not exercise.
    let durable_whiteouts: HashSet<PathBuf> = crate::whiteout::read()
        .context("cannot read the durable whiteout list -- refusing to reload, because an empty list here would PRUNE every whiteout")?
        .into_iter()
        .map(PathBuf::from)
        .collect();
    let mut absorbed = crate::absorb::read_absorbed_targets()
        .context("cannot read the absorbed-rule record -- refusing to reload, because an empty record here would PRUNE every absorbed rule")?;
    // The ROM-tmpfs takeovers are absorb's rules too (M-S8): whiteouts on paths no
    // module plan names, so the prune below would drop them and the emptied
    // directory would fill back in on the first reload after a takeover.
    absorbed.extend(crate::absorb::absorbed_tmpfs_targets());

    let (mut added, mut changed, mut removed, mut failed) = (0u32, 0u32, 0u32, 0u32);
    // Add new rules, and re-apply a live rule whose SOURCE or KIND changed (not
    // just presence): a target moving between modules or flipping inject<->whiteout
    // must update, or the stale rule would be frozen until a full mount.
    let mounted = crate::absorb::mounted_targets().context(
        "cannot read /proc/self/mountinfo -- refusing to serve, because assuming \"nothing is mounted\" injects over live mounts and strands each one in mountinfo until reboot",
    )?;
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
        // Unmount BEFORE dropping the stale rule: if the target will not unmount we
        // must skip it entirely (serving would strand the mount), and skipping
        // after a del would have left it with no rule at all.
        if !unmount_before_serving(&mounted, &e.target) {
            failed += 1;
            continue;
        }
        let existed = live.contains_key(&((*t).to_path_buf(), 0));
        if existed {
            let _ = nm.del(&e.target); // drop the stale rule before re-adding
        }
        let r = match e.kind {
            PlanKind::Inject => nm.add(&e.target, &e.source),
            PlanKind::Whiteout => {
                warn_whiteout_hole(&e.target, &e.module);
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
        // Same gate `whiteout::apply` uses. Without it a hand-edited entry that
        // apply() refuses (a partition root, a /data path) would still be pushed
        // to the engine from here -- the two paths must agree on what is legal.
        if crate::whiteout::validate(&w.to_string_lossy()).is_err() {
            eprintln!("nomount: skipping invalid whiteout entry {}", w.display());
            failed += 1;
            continue;
        }
        // Converge on the same two observables `whiteout list` reports: whether
        // the engine holds the rule, and whether the target still stats. A rule
        // that is live while its path remains readable is applied and NOT
        // serving -- what that command prints as "applied, but still visible".
        // The presence-only check this loop used to open with skipped precisely
        // that state, so a whiteout that had stopped hiding stayed stopped until
        // the next boot or a manual `whiteout apply`. Re-issuing is idempotent,
        // so the missing and the inert case take the same path.
        //
        // Honest scope: a durable whiteout was twice seen inert on an OP15 with
        // reloads and a reboot in flight, but three attempts to reproduce it from
        // `reload` alone did not, so the trigger is NOT established. This is
        // convergence on the saved list, not a fix for a known cause. Cost is one
        // stat per durable entry.
        let live_rule = live.contains_key(&(w.clone(), 0));
        if live_rule && !w.exists() {
            continue;
        }
        match nm.whiteout(w) {
            // Only a genuinely absent whiteout is a new rule; re-arming an inert
            // one must not inflate the `+N` the caller reads as "rules added".
            Ok(()) => {
                if !live_rule {
                    added += 1;
                }
            }
            Err(_) => failed += 1,
        }
    }

    // Remove live rules no longer desired (skip any that are now bind targets,
    // and anything durable/absorbed that the module plan cannot describe).
    for (t, uid) in live.keys() {
        let wanted = desired_hookless.contains_key(t.as_path())
            || desired_bind_src.contains_key(t.as_path());
        if !prunable(t, *uid, wanted, &durable_whiteouts, &absorbed) {
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
            // Only count what actually came down: a bind that refused to umount is
            // still live AND still recorded, and reporting it as removed is how a
            // surviving mount became invisible to every later pass.
            if crate::bind::umount_one(t) {
                bind_removed += 1;
            } else {
                failed += 1;
            }
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
                // AlreadyMounted made no new bind, so it must not inflate the count.
                Ok(crate::bind::BindOutcome::Bound) => bind_added += 1,
                Ok(crate::bind::BindOutcome::AlreadyMounted) => {}
                Err(_) => failed += 1,
            }
        }
    }

    // PM has already parsed every ROM APK by the time a reload runs, so dropping
    // its cache entry here only takes effect at the next scan.
    let pm = crate::pmcache::sync(&served_apks(&plan, &crate::absorb::absorbed_pairs()));
    crate::pmcache::add_pending(&pm);

    println!(
        "nomount reload: +{added} ~{changed} -{removed} rules, +{bind_added} -{bind_removed} binds, \
         {failed} failed, {skipped} blocklisted (gap-free)"
    );
    if !pm.is_empty() {
        let shown: Vec<String> =
            pm.iter().take(3).map(|p| p.display().to_string()).collect();
        println!(
            "nomount: {} system APK(s) changed -- REBOOT REQUIRED: {}{}",
            pm.len(),
            shown.join(", "),
            if pm.len() > 3 { ", ..." } else { "" }
        );
        println!(
            "         PackageManager parsed the old bytes; its cache is dropped but only \
             re-read at the next scan. Apps over these APKs can force-close until then."
        );
    }
    Ok(())
}

/// Metamodule entry point (`nomount mount`): rebuild rules from the current set
/// of enabled modules and mount RRO overlays. The Suite deliberately does NOT
/// touch root/su: su is provided independently by the kernel's sucompat,
/// mountlessly. Keeping su out of the Suite means a Suite bug can never break
/// root, and there is no su mount for a scanner to flag.
pub fn run_mount() -> Result<()> {
    let _pass = pass_lock(); // serialise against a concurrent reload/absorb (M-S9)
    let nm = Nm::new();
    nm.version()
        .context("hookless NoMount engine not responding -- is the CONFIG_NOMOUNT kernel loaded?")?;

    // Build the plan BEFORE clearing the engine (M-S9): collect_plan only reads the
    // module tree, and enumerating it after `clear()` would, on any failure between
    // the two, leave the engine empty with nothing to re-serve.
    let (plan, skipped) = collect_plan()?;

    // Exactly one rule per target. See dedupe_by_target: applying both halves of
    // a contested target leaves the table naming one module and the filesystem
    // serving the other, which no later refresh or reload can reconcile.
    let (plan, collisions) = dedupe_by_target(plan);
    for c in &collisions {
        eprintln!(
            "nomount: {} claimed by {} -- serving {}, skipping {}",
            c.target.display(),
            c.losers.len() + 1,
            c.winner,
            c.losers.join(", ")
        );
    }

    // Measure the ROM's directory shape and tell the engine, BEFORE any rule
    // exists: a synthesized dir inherits its parent's superblock, which on an
    // overlay-backed path is overlayfs and says nothing about the layer whose
    // shape its stock siblings show. Userspace can just read a directory and
    // check, so it does; a failure to prove it leaves the engine as it was.
    //
    // Which means: only CALL the knob when the shape is proven. Passing `false`
    // for "unproven" is not the same statement -- it asserts not-packed, and
    // `fits_erofs_shape` answers false for any sampled directory >= 4096 bytes or
    // reached through an overlay mount, so a genuine erofs ROM whose sampled roots
    // all happen to be large would have turned the knob OFF and disabled the
    // size/nlink recompute `whiteout::measurable_hole` depends on.
    if crate::dirshape::rom_dirs_are_dirent_packed() {
        if let Err(e) = nm.set_dir_shape(true) {
            eprintln!("nomount: could not set the directory-shape knob: {e:#}");
        }
    }

    // READ THE MOUNT TABLE BEFORE CLEARING.
    //
    // This used to sit 58 lines below `clear()`, and it is fallible: on a failed
    // read of /proc/self/mountinfo the `?` returned -- with the engine already
    // emptied, hidden UIDs re-applied and binds torn down. Every injection on the
    // device was gone, and nothing re-served them until a later successful pass.
    //
    // It is the same hazard the comment above `collect_plan` records ("an
    // empty-on-error plan wiped every rule"), reached through a different
    // fallible call. `mounted_targets()` reads no module state and depends on
    // nothing this pass does, so it belongs on the same side of `clear()` as the
    // plan: everything that can refuse the pass runs while the engine is still
    // serving.
    let mounted = crate::absorb::mounted_targets().context(
        "cannot read /proc/self/mountinfo -- refusing to serve, because assuming \"nothing is mounted\" injects over live mounts and strands each one in mountinfo until reboot",
    )?;

    // Start clean so uninstalled/updated modules don't leave stale rules, and tear
    // down any my_* binds from the previous pass so removed modules don't leak one.
    // NOT `let _ =`. `nm.version()` already succeeded, so the binary is there --
    // a failure here is the engine refusing, and the contract of this call is
    // "start clean so uninstalled/updated modules do not leave stale rules". A
    // silent failure keeps every rule belonging to a module the user just removed
    // and then reports the whole pass as a clean rebuild.
    nm.clear()
        .context("could not clear the engine before rebuilding -- rules from uninstalled or updated modules would survive the pass")?;
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
    if !crate::bind::teardown_all() {
        // Not fatal -- the pass below still rebuilds the rules -- but a surviving
        // bind is a mount this Suite can no longer account for, so it must be said
        // rather than swallowed.
        eprintln!(
            "nomount: at least one my_* bind from the previous pass is still mounted; it \
             stays recorded in binds.list and the next pass will retry it"
        );
    }
    // `clear` dropped every absorbed rule, but NOT the record of them: the pass
    // below rebuilds those rules from it, so truncating the file here would throw
    // away the only thing that can. Read it first either way -- an earlier version
    // cleared the file and then read an empty list, and silently did nothing.
    // `read_` not `absorbed_pairs()`: the latter is unwrap_or_default, and the
    // write-back below would then TRUNCATE the record to a bare header on any
    // read error -- destroying, permanently, the only thing that can re-serve a
    // patched-APK rule. (`fs::write` truncates before writing, and metamount.sh
    // SIGKILLs this pass at 60s, so a half-written record is reachable.) A
    // missing file is Ok(empty) and still normal. run_reload already treats this
    // read as fatal for the same reason; there it costs one pass, here it is the
    // file.
    let (recorded, record_readable) = match crate::absorb::read_absorbed_pairs() {
        Ok(v) => (v, true),
        Err(e) => {
            eprintln!(
                "nomount: could not read the absorbed-rule record ({e}) -- re-serving \
                 nothing from it this pass and LEAVING THE FILE ALONE, because rewriting \
                 it from an empty read would lose every patched-APK rule for good"
            );
            (Vec::new(), false)
        }
    };
    // Only when we actually read it. Always the tab-separated pairs format (empty
    // is fine — it just rewrites the header). The legacy bare-target writer is
    // gone; see H18.
    if record_readable {
        crate::absorb::set_absorbed_pairs(&recorded);
    }
    // Re-serve them here, before zygote starts and PackageManager scans, so a
    // patched-APK module never has to mount at all: no bind, so no process maps
    // one, so nothing carries the "(deleted)" marking a later takeover leaves
    // behind. Verified end to end on OP15 -- all audit checks pass with the app
    // patched, running, and zero mounts.
    //
    // This looked like a timing bug at first: YouTube came up with a null
    // Resources (GraphicsEnvironment.queryAngleChoice -> handleBindApplication
    // NPE) and a retry took the system down. The cause was the SELinux label on
    // the copy being served -- everything under /data/adb is adb_data_file, which
    // an app cannot read. absorb::label_apk_readable fixes that; the timing was
    // never the problem.
    if !recorded.is_empty() {
        let n = crate::absorb::reapply_absorbed_pairs(&nm, &recorded);
        if n > 0 {
            println!("nomount: re-served {n} absorbed APK rule(s) from the record");
        }
    }

    // plan/skipped were collected before `clear()` above.
    let mut served: HashSet<&str> = HashSet::new();
    let mut binds = 0u32;
    let mut st = Stats {
        applied: 0,
        failed: 0,
        whiteouts: 0,
    };
    // What was actually APPLIED, not what was planned. pmcache::sync records the
    // source identity of everything it is handed as "PM has now parsed these
    // bytes". Handing it the plan meant a rule that FAILED to apply was recorded
    // as served, so on the next boot -- when it applies -- identity(source) is
    // unchanged, the entry is not stale, the cache is never dropped, and
    // PackageManager keeps serving its parse of the STOCK apk. That is the
    // "Theme.AppCompat" force-close this module documents, made permanent:
    // nothing will ever mark that APK changed again.
    let mut applied_apks: Vec<(PathBuf, PathBuf)> = Vec::new();
    // `mounted` was read before `clear()` -- see the note there.
    for e in &plan {
        served.insert(e.module.as_str());
        if !unmount_before_serving(&mounted, &e.target) {
            st.failed += 1;
            continue;
        }
        match e.kind {
            PlanKind::Whiteout => {
                warn_whiteout_hole(&e.target, &e.module);
                match nm.whiteout(&e.target) {
                    Ok(()) => st.whiteouts += 1,
                    Err(_) => st.failed += 1,
                }
            }
            PlanKind::Inject if !source_resolves(e) => st.failed += 1,
            PlanKind::Inject => match nm.add(&e.target, &e.source) {
                Ok(()) => {
                    st.applied += 1;
                    applied_apks.push((e.target.clone(), e.source.clone()));
                }
                Err(_) => st.failed += 1,
            },
            PlanKind::Bind => match crate::bind::apply(&e.source, &e.target) {
                Ok(crate::bind::BindOutcome::Bound) => {
                    binds += 1;
                    applied_apks.push((e.target.clone(), e.source.clone()));
                }
                Ok(crate::bind::BindOutcome::AlreadyMounted) => {
                    applied_apks.push((e.target.clone(), e.source.clone()));
                }
                Err(_) => st.failed += 1,
            },
        }
    }
    // Re-apply the ROM-tmpfs takeovers, AFTER the module plan for the same reason
    // metamount.sh runs `whiteout apply` after this pass: a whiteout d_drops the
    // dentry it names, so it has to land once the injections underneath are in.
    // `clear` above dropped these along with everything else, and the module that
    // mounted the tmpfs does not re-mount it until the next boot -- so without
    // this, a mid-session Re-apply put the stock directory back. absorb confirms
    // or expires each entry when it next runs (M-S8).
    let tmpfs_hidden = crate::absorb::reapply_tmpfs_whiteouts(&nm);

    // PM scans after this pass, so an entry dropped here is rebuilt with the
    // bytes we serve and nothing is left pending.
    let pm = crate::pmcache::sync(&served_apks_applied(&applied_apks, &recorded));
    crate::pmcache::clear_pending();

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
    if tmpfs_hidden > 0 {
        println!(
            "nomount: re-applied {tmpfs_hidden} ROM directory hide(s) taken over from a module tmpfs"
        );
    }
    // A failure count buried in the summary line is not a report. The pass exits
    // 0 (12 bad rules out of 260 must not fail the boot and trip the bootloop
    // guard), and metamount.sh only logged non-zero exits -- so a partial
    // injection ended the boot on a green tick with NOTHING in boot.log. Same
    // false green the timeout path was fixed for, reached by exiting cleanly.
    // metamount.sh greps for this marker.
    if st.failed > 0 {
        println!(
            "nomount: WARNING {} rule(s) failed to apply — the injection set is INCOMPLETE",
            st.failed
        );
    }
    if !pm.is_empty() {
        println!("nomount: re-parsed {} changed system APK(s) (package cache)", pm.len());
    }
    Ok(())
}

/// Every ROM APK a rule serves, as (target, source), from the module plan plus
/// the absorbed record. Binds count: a my_* APK is bind-served (hookless there
/// bootloops zygote) and a bind swaps the bytes PM parsed just as an inject
/// does. Only whiteouts are excluded -- removing a file leaves PM nothing to
/// have cached under that path.
fn served_apks(plan: &[PlanEntry], absorbed: &[(PathBuf, PathBuf)]) -> Vec<(PathBuf, PathBuf)> {
    plan.iter()
        .filter(|e| matches!(e.kind, PlanKind::Inject | PlanKind::Bind))
        .map(|e| (e.target.clone(), e.source.clone()))
        .chain(absorbed.iter().cloned())
        .filter(|(t, _)| crate::pmcache::is_rom_apk(t))
        .collect()
}

/// Same filter, but over pairs that were actually applied rather than planned.
/// Recording a FAILED rule as served is what makes a stale PackageManager parse
/// permanent -- see the note at the apply loop.
fn served_apks_applied(
    applied: &[(PathBuf, PathBuf)],
    absorbed: &[(PathBuf, PathBuf)],
) -> Vec<(PathBuf, PathBuf)> {
    applied
        .iter()
        .cloned()
        .chain(absorbed.iter().cloned())
        .filter(|(t, _)| crate::pmcache::is_rom_apk(t))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(module: &str, target: &str, source: &str) -> PlanEntry {
        PlanEntry {
            module: module.to_string(),
            target: PathBuf::from(target),
            source: PathBuf::from(source),
            kind: PlanKind::Inject,
        }
    }

    /// Two modules claiming one target must produce exactly one applied rule.
    ///
    /// Applying both is what left the rule table naming one module while the
    /// filesystem served the other: `nm add` over a live target updates the
    /// table but does not re-point the materialised inode.
    #[test]
    fn dedupe_keeps_the_last_claim() {
        let plan = vec![
            entry("a_mod", "/system/etc/x", "/data/adb/modules/a_mod/system/etc/x"),
            entry("b_mod", "/system/etc/x", "/data/adb/modules/b_mod/system/etc/x"),
            entry("c_mod", "/system/etc/y", "/data/adb/modules/c_mod/system/etc/y"),
        ];
        let (kept, collisions) = dedupe_by_target(plan);
        assert_eq!(kept.len(), 2, "one rule per target");
        let x = kept.iter().find(|e| e.target == Path::new("/system/etc/x")).unwrap();
        assert_eq!(x.module, "b_mod", "last plan entry wins, as documented");
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].winner, "b_mod");
        assert_eq!(collisions[0].losers, vec!["a_mod".to_string()]);
    }

    /// An uncontested plan must pass through untouched -- no reordering, no
    /// allocation of a collision list, nothing for the caller to report.
    #[test]
    fn dedupe_is_a_noop_without_collisions() {
        let plan = vec![
            entry("a", "/system/etc/one", "/data/adb/modules/a/system/etc/one"),
            entry("b", "/system/etc/two", "/data/adb/modules/b/system/etc/two"),
        ];
        let (kept, collisions) = dedupe_by_target(plan);
        assert_eq!(kept.len(), 2);
        assert!(collisions.is_empty());
        assert_eq!(kept[0].module, "a");
        assert_eq!(kept[1].module, "b");
    }

    /// `/product/product/...` is the installer nesting `system/product` inside an
    /// existing `product/`. Serving it puts content at a directory the ROM does
    /// not have, which helps nobody and creates an existence oracle.
    #[test]
    fn serve_mode_refuses_repeated_partition_name() {
        assert!(matches!(
            serve_mode(Path::new("/product/product/etc/nmt/x.txt")),
            Serve::Refuse(_)
        ));
        assert!(matches!(
            serve_mode(Path::new("/system/system/etc/x")),
            Serve::Refuse(_)
        ));
        // A directory that merely SHARES a name with a partition one level down
        // is fine -- only the repeat at depth 1 is the installer's mistake.
        assert_eq!(serve_mode(Path::new("/product/etc/product/x")), Serve::Inject);
        assert_eq!(serve_mode(Path::new("/system/etc/system/x")), Serve::Inject);
    }

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
        // `/d` is debugfs. It only ever reached the plan because discovery follows
        // symlinks and nothing downstream re-checked the root (M-S10).
        assert!(matches!(serve_mode(Path::new("/d/tracing/x")), Serve::Refuse(_)));
        assert!(can_whiteout(Path::new("/d/tracing/x")).is_err());
    }

    /// `.replace` must hide the stock entries the module does NOT ship, and leave
    /// the ones it does to the ordinary inject walk. The old translation put a
    /// single whiteout on the parent, which d_dropped the directory and took the
    /// module's own content down with it.
    ///
    /// Built on a real tree because that is what the function reads. The base has
    /// to be somewhere `can_whiteout` accepts, so /tmp is out -- "tmp" is in
    /// NON_PARTITION_ROOTS -- and $HOME is used instead.
    #[test]
    fn replace_expands_to_the_unshipped_entries_only() {
        let Some(base) = test_base("replace-expand") else { return };
        let stock = base.join("stock");
        let module = base.join("module");

        // stock: a.xml, b.xml, sub/{c.xml,d.xml}, extra/
        fs::create_dir_all(stock.join("sub")).unwrap();
        fs::create_dir_all(stock.join("extra")).unwrap();
        fs::write(stock.join("a.xml"), b"stock").unwrap();
        fs::write(stock.join("b.xml"), b"stock").unwrap();
        fs::write(stock.join("sub/c.xml"), b"stock").unwrap();
        fs::write(stock.join("sub/d.xml"), b"stock").unwrap();

        // module ships: a.xml, and sub/ containing only d.xml
        fs::create_dir_all(module.join("sub")).unwrap();
        fs::write(module.join("a.xml"), b"mine").unwrap();
        fs::write(module.join("sub/d.xml"), b"mine").unwrap();

        let mut out = Vec::new();
        expand_replacement("m", &stock, &module, &module.join(".replace"), 0, &mut out);
        let mut got: Vec<String> =
            out.iter().map(|e| e.target.strip_prefix(&stock).unwrap().display().to_string()).collect();
        got.sort();

        // b.xml unshipped -> hidden. extra/ unshipped -> hidden whole, not descended.
        // sub/ is shipped as a dir -> recursed: c.xml hidden, d.xml left alone.
        assert_eq!(got, vec!["b.xml".to_string(), "extra".to_string(), "sub/c.xml".to_string()]);
        assert!(out.iter().all(|e| e.kind == PlanKind::Whiteout));
        // The parent itself is never whiteouted -- that was the whole bug.
        assert!(out.iter().all(|e| e.target != stock));

        let _ = fs::remove_dir_all(&base);
    }

    /// A stock directory the module replaces with a FILE of the same name is not
    /// recursed into: the module's file is served there and the ordinary walk
    /// emits its inject, so there is nothing left to hide.
    #[test]
    fn replace_does_not_descend_where_the_module_ships_a_file() {
        let Some(base) = test_base("replace-file-over-dir") else { return };
        let stock = base.join("stock");
        let module = base.join("module");
        fs::create_dir_all(stock.join("thing")).unwrap();
        fs::write(stock.join("thing/inner.xml"), b"stock").unwrap();
        fs::create_dir_all(&module).unwrap();
        fs::write(module.join("thing"), b"mine").unwrap();

        let mut out = Vec::new();
        expand_replacement("m", &stock, &module, &module.join(".replace"), 0, &mut out);
        assert!(out.is_empty(), "expected no whiteouts, got {} entries", out.len());

        let _ = fs::remove_dir_all(&base);
    }

    /// No stock directory to replace: the module's content is served on its own
    /// and the engine materialises the parent. Nothing to hide, and no panic.
    #[test]
    fn replace_on_a_directory_the_rom_does_not_have_is_a_no_op() {
        let Some(base) = test_base("replace-absent") else { return };
        let module = base.join("module");
        fs::create_dir_all(&module).unwrap();
        fs::write(module.join("mine.xml"), b"mine").unwrap();

        let mut out = Vec::new();
        expand_replacement("m", &base.join("no-such-stock"), &module, &module.join(".replace"), 0, &mut out);
        assert!(out.is_empty());

        let _ = fs::remove_dir_all(&base);
    }

    /// A tree deeper than the guard stops instead of walking forever.
    #[test]
    fn replace_expansion_stops_at_the_depth_guard() {
        let Some(base) = test_base("replace-depth") else { return };
        let stock = base.join("stock");
        let mut d = stock.clone();
        let module = base.join("module");
        let mut m = module.clone();
        for _ in 0..20 {
            d = d.join("x");
            m = m.join("x");
        }
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("deep.xml"), b"stock").unwrap();
        fs::create_dir_all(&m).unwrap();

        let mut out = Vec::new();
        expand_replacement("m", &stock, &module, &module.join(".replace"), 0, &mut out);
        // It stopped rather than reaching the leaf 20 levels down.
        assert!(out.iter().all(|e| !e.target.ends_with("deep.xml")));

        let _ = fs::remove_dir_all(&base);
    }

    /// Somewhere `can_whiteout` accepts (not /tmp, whose root is non-partition).
    /// Returns None -- test skips -- if this machine has no usable home.
    fn test_base(tag: &str) -> Option<PathBuf> {
        let home = std::env::var("HOME").ok()?;
        let base = PathBuf::from(home).join(format!(".nomount-test-{tag}"));
        if can_whiteout(&base.join("probe")).is_err() {
            eprintln!("skipping: {} is not a whiteoutable base", base.display());
            return None;
        }
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).ok()?;
        Some(base)
    }

    /// A whiteout is a d_drop, not a serve, so it is allowed wherever the path
    /// itself is ours to touch -- `my_*` included. Proven on an OP15: the CLI
    /// hides `/my_stock/app/OplusOperationManual` live (43 app dirs -> 42, restored
    /// on remove), while a module shipping the identical 0:0 char device was
    /// dropped from the plan without a word.
    #[test]
    fn whiteout_allowed_on_my_partitions() {
        assert!(can_whiteout(Path::new("/my_stock/app/OplusOperationManual")).is_ok());
        assert!(can_whiteout(Path::new("/my_product/app/Foo")).is_ok());
        assert!(can_whiteout(Path::new("/product/app/AIMemory")).is_ok());
        assert!(can_whiteout(Path::new("/system/priv-app/Foo")).is_ok());
    }

    /// The refusals that DO carry over from `serve_mode`: a bare partition root
    /// masks every stock entry under it (zygote SIGABRT at forkSystemServer), and
    /// a non-ROM root was never ours to touch.
    #[test]
    fn whiteout_refuses_partition_roots_and_non_rom() {
        assert!(can_whiteout(Path::new("/my_stock")).is_err());
        assert!(can_whiteout(Path::new("/product")).is_err());
        assert!(can_whiteout(Path::new("/system")).is_err());
        assert!(can_whiteout(Path::new("/data/adb/modules/x")).is_err());
        assert!(can_whiteout(Path::new("/apex/com.android.art/x")).is_err());
        assert!(can_whiteout(Path::new("/")).is_err());
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
        assert!(!prunable(Path::new("/system/etc/tell.conf"), 0, false, &durable, &absorbed));
        assert!(!prunable(Path::new("/system/etc/absorbed.xml"), 0, false, &durable, &absorbed));
        // Wanted by the plan -> never pruned either.
        assert!(!prunable(Path::new("/system/app/Foo.apk"), 0, true, &none, &none));
        // Claimed by nobody -> this is the stale rule prune exists for.
        assert!(prunable(Path::new("/system/app/Gone.apk"), 0, false, &durable, &absorbed));
    }

    /// A per-UID rule is not the module plan's to prune, and `nm del` (always uid 0)
    /// could not remove it anyway -- the attempt just re-counted as a failure on
    /// every reload, forever.
    #[test]
    fn reload_never_prunes_per_uid_rules() {
        let none = HashSet::new();
        let t = Path::new("/system/app/Gone.apk");
        // Same target, same "nobody wants it": global gets pruned, per-UID does not.
        assert!(prunable(t, 0, false, &none, &none));
        assert!(!prunable(t, 10471, false, &none, &none));
        assert!(!prunable(t, 1000, false, &none, &none));
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
