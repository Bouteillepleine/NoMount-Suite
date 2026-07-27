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

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::nm::Nm;

const MODULES_DIR: &str = "/data/adb/modules";

// Modules that do their own mounting/redirection (or ship their own su, like a
// kernelnosu module) — injecting their files double-handles the same targets, and
// for a su binary would break root. Extend at runtime via the blocklist file.
const BUILTIN_BLOCKLIST: &[&str] = &["kernelnosu", "scene_swap_controller", "AAaTempSpoof"];
const BLOCKLIST_FILE: &str = "/data/adb/nomount/blocklist";

// On System-as-Root devices these live under /vendor, /product, etc. Canonicalize
// so rules target the real inode instead of the /system/<x> symlink alias.
const SAR_ALIAS_PARTITIONS: &[&str] = &[
    "system/vendor",
    "system/product",
    "system/system_ext",
    "system/odm",
];

// Top-level module roots that exist on-device but must NEVER be injected into
// (writable, virtual, or ramdisk mounts). Any OTHER top-level module dir whose
// "/<name>" is a real directory is treated as a partition to inject — so partition
// discovery is dynamic (product/, my_*/, vendor/, whatever THIS device ships) with
// no hardcoded per-OEM list. Module-metadata dirs (META-INF/, webroot/, common/…)
// are excluded for free: their "/<name>" doesn't exist on the device.
const NON_PARTITION_ROOTS: &[&str] = &[
    "data", "mnt", "dev", "proc", "sys", "cache", "metadata", "config",
    "storage", "sdcard", "apex", "tmp", "debug_ramdisk", "linkerconfig",
    "postinstall", "second_stage_resources", "bin", "sbin",
];

/// Resolve a module-relative path ("system/app/Foo.apk") to its absolute target
/// ("/system/app/Foo.apk", or "/vendor/..." for SAR aliases).
fn resolve_target_path(relative: &Path) -> Option<PathBuf> {
    let s = relative.to_str()?;
    if s.is_empty() {
        return None;
    }
    for alias in SAR_ALIAS_PARTITIONS {
        let canonical = &alias["system/".len()..];
        if s == *alias {
            return Some(PathBuf::from(format!("/{canonical}")));
        }
        if let Some(rest) = s.strip_prefix(alias).and_then(|r| r.strip_prefix('/')) {
            return Some(PathBuf::from(format!("/{canonical}/{rest}")));
        }
    }
    Some(PathBuf::from(format!("/{s}")))
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

/// Recursively route a module subtree rooted at `dir`.
/// `.replace`/char-device markers become whiteouts; every other file — including
/// RRO overlay APKs — gets a hookless redirect. Symlinks are treated as files
/// (file_type does not follow). RRO overlay dirs are NOT special-cased: their APKs
/// are hookless-injected into e.g. `/product/overlay`, and OverlayManagerService +
/// idmap2 pick them up at the system_server scan (which runs after this
/// post-fs-data pass). So RRO works with no overlayfs mount — zero mounts total.
fn inject_tree(nm: &Nm, module_root: &Path, dir: &Path, st: &mut Stats) {
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
            inject_tree(nm, module_root, &source, st);
        } else if name == ".replace" {
            // Whiteout the parent dir (module wants to replace, not merge, it).
            if let Some(parent) = target.parent() {
                match nm.whiteout(parent) {
                    Ok(()) => st.whiteouts += 1,
                    Err(_) => st.failed += 1,
                }
            }
        } else if ft.is_char_device() {
            // A 0:0 char device is Magisk's whiteout marker.
            match nm.whiteout(&target) {
                Ok(()) => st.whiteouts += 1,
                Err(_) => st.failed += 1,
            }
        } else if is_partition_root(&target) {
            // A non-directory entry resolving to a bare partition root — a module's
            // layout-convergence symlink (e.g. `system/product -> ../product`). Injecting it
            // would redirect the entire partition; skip it. The real content still comes from
            // the module's own top-level partition dir. Real `system/<partition>` DIRECTORIES
            // are unaffected: they take the is_dir() branch above and recurse as before.
            continue;
        } else {
            match nm.add(&target, &source) {
                Ok(()) => st.applied += 1,
                Err(_) => st.failed += 1,
            }
        }
    }
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

    // Start clean so uninstalled/updated modules don't leave stale rules.
    let _ = nm.clear();

    let blocklist = load_blocklist();
    let mut modules = 0u32;
    let mut skipped = 0u32;
    let mut st = Stats {
        applied: 0,
        failed: 0,
        whiteouts: 0,
    };
    if let Ok(dirs) = fs::read_dir(MODULES_DIR) {
        for entry in dirs.flatten() {
            let mdir = entry.path();
            if !mdir.is_dir() || !module_enabled(&mdir) {
                continue;
            }
            if mdir
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|id| blocklist.contains(id))
            {
                skipped += 1;
                continue;
            }
            // "system/" is the classic layout; auto_mount modules (e.g. OxygenCustomizer)
            // ship content directly under module-root partition dirs. Process every
            // top-level dir that maps to a real on-device partition — dynamically, so any
            // OEM's partitions are handled. resolve_target_path maps "<root>/…" -> "/<root>/…"
            // (and applies the SAR aliases for "system/vendor" etc.).
            let mut had_content = false;
            if let Ok(entries) = fs::read_dir(&mdir) {
                for e in entries.flatten() {
                    if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        continue;
                    }
                    let name = e.file_name();
                    let Some(name) = name.to_str() else {
                        continue;
                    };
                    // Skip non-injectable roots, and OnePlus/Oppo `my_*` feature partitions.
                    // `my_*` is deliberate: those paths are NOT in zygote's FD allowlist
                    // (`FileDescriptorInfo::CreateFromFd`), so anything zygote preloads from
                    // there — an RRO overlay APK in particular — aborts the first
                    // `forkSystemServer` with "Not allowlisted" and bootloops. Modules that
                    // need `my_*` content handle it themselves (e.g. OxygenCustomizer's
                    // post-fs-data.sh binds); NoMount serves the /product, /system, … trees.
                    if NON_PARTITION_ROOTS.contains(&name) || name.starts_with("my_") {
                        continue;
                    }
                    // A partition iff "/<name>" is a real directory on this device;
                    // module-metadata dirs (META-INF/, webroot/, …) fail this and are skipped.
                    if !Path::new(&format!("/{name}")).is_dir() {
                        continue;
                    }
                    had_content = true;
                    inject_tree(&nm, &mdir, &e.path(), &mut st);
                }
            }
            if had_content {
                modules += 1;
            }
        }
    }

    println!(
        "nomount(suite): {modules} modules | {} rules, {} whiteouts, {} failed, {skipped} skipped \
         | mountless (RRO via hookless)",
        st.applied, st.whiteouts, st.failed
    );
    Ok(())
}
