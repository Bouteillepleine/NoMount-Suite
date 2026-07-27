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

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::nm::Nm;
use crate::overlay;

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
/// RRO overlay dirs are collected in `overlays` (target -> source) for real
/// mounting; `.replace`/char-device markers become whiteouts; other files get a
/// hookless redirect. Symlinks are treated as files (file_type does not follow).
fn inject_tree(
    nm: &Nm,
    module_root: &Path,
    dir: &Path,
    st: &mut Stats,
    overlays: &mut Vec<(PathBuf, PathBuf)>,
) {
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
            // Only RRO overlay dirs go to the real overlay engine. NB: routing a
            // whole live overlayfs partition subdir (e.g. /product/priv-app) here
            // to fix the new-subtree-over-overlayfs ECHILD gap was tried in v2.2.2
            // and BOOTLOOPS OP15 — remounting overlayfs over the stock priv-app at
            // early boot breaks PMS. The real fix belongs in the kernel engine
            // (nomount.c: synthetic dir ops over overlay parents), not here.
            // `overlay::should_route` remains available but is deliberately unused.
            if overlay::is_overlay_target(&target) {
                overlays.push((target, source));
                continue;
            }
            inject_tree(nm, module_root, &source, st, overlays);
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
    let mut overlays: Vec<(PathBuf, PathBuf)> = Vec::new();

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
            let sysroot = mdir.join("system");
            if !sysroot.is_dir() {
                continue;
            }
            modules += 1;
            inject_tree(&nm, &mdir, &sysroot, &mut st, &mut overlays);
        }
    }

    // Real-mount RRO overlay dirs (grouped by target; several modules may
    // contribute APKs to the same partition overlay dir).
    let mut by_target: BTreeMap<PathBuf, Vec<PathBuf>> = BTreeMap::new();
    for (target, source) in overlays {
        by_target.entry(target).or_default().push(source);
    }
    let (ov_ok, ov_fail) = overlay::setup(&by_target);

    println!(
        "nomount(suite): {modules} modules | {} rules, {} whiteouts, {} failed, {skipped} skipped \
         | {ov_ok} RRO overlays ({ov_fail} failed)",
        st.applied, st.whiteouts, st.failed
    );
    Ok(())
}
