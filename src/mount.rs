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
            let sysroot = mdir.join("system");
            if !sysroot.is_dir() {
                continue;
            }
            modules += 1;
            inject_tree(&nm, &mdir, &sysroot, &mut st);
        }
    }

    println!(
        "nomount(suite): {modules} modules | {} rules, {} whiteouts, {} failed, {skipped} skipped \
         | mountless (RRO via hookless)",
        st.applied, st.whiteouts, st.failed
    );
    Ok(())
}
