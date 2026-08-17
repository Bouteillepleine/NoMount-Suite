//! Decide whether this device's ROM directories describe their own contents.
//!
//! erofs stores a directory as packed 12-byte dirents followed by unpadded
//! names, so a single-block directory reports exactly
//! `st_size == 12*(entries incl "." and "..") + total name bytes`. f2fs and ext4
//! report block multiples that encode nothing about the entry set, and an
//! overlayfs mountpoint reports a value unrelated to either.
//!
//! The kernel cannot work this out for itself where it matters most. A
//! synthesized directory inherits its PARENT's superblock, and on an
//! overlay-backed ROM path that is overlayfs — whose magic says nothing about
//! the layer whose shape the stock siblings actually show. `d_real()` cannot
//! answer either: it resolves regular files, and a merged directory has no
//! single real dentry. Two in-kernel attempts to infer it produced silent
//! no-ops, which is exactly the failure mode this module exists to avoid.
//!
//! So measure it here, where a directory listing is one `read_dir` away, and
//! tell the engine the answer. Proof, not inference: we only claim the shape
//! when a REAL directory's reported size matches the formula for its own
//! contents. When nothing proves it, the knob stays unset and the engine keeps
//! its previous behaviour.

use std::fs;
use std::path::Path;

/// `12*(n+2) + sum(namelen) + 3` — the `+2`/`+3` are `.` and `..`, which the
/// listing does not return but the on-disk directory always contains.
fn erofs_model(dir: &Path) -> Option<u64> {
    let mut n: u64 = 0;
    let mut names: u64 = 0;
    for e in fs::read_dir(dir).ok()? {
        let e = e.ok()?;
        n += 1;
        names += e.file_name().as_encoded_bytes().len() as u64;
    }
    if n == 0 {
        return None; // nothing to distinguish a shape from
    }
    Some(12 * (n + 2) + names + 3)
}

/// True when `dir`'s own reported size equals the erofs formula for its
/// contents. Only meaningful under one block: past 4096 bytes erofs pads each
/// block by an amount that depends on where the names fall, so a mismatch there
/// proves nothing either way.
fn fits_erofs_shape(dir: &Path) -> bool {
    let Ok(md) = fs::metadata(dir) else { return false };
    let size = md.len();
    if size == 0 || size >= 4096 {
        return false;
    }
    erofs_model(dir) == Some(size)
}

/// Walk the ROM looking for proof. Returns true as soon as a real directory
/// demonstrates the shape.
///
/// Deliberately samples the CHILDREN of each root rather than the roots
/// themselves: an overlay mountpoint (`/product/priv-app`) reports its own
/// meaningless size — 27 bytes for 35 entries on OP15 — while the merged
/// subdirectories beneath it report their lower layer's size verbatim, which is
/// the value our synthesized siblings have to blend in with.
pub fn rom_dirs_are_dirent_packed() -> bool {
    const ROOTS: &[&str] = &[
        "/system/app", "/system/priv-app", "/system/etc", "/product/app",
        "/product/priv-app", "/product/etc", "/vendor/etc", "/system_ext/app",
    ];
    let mut checked = 0usize;
    for root in ROOTS {
        let root = Path::new(root);
        if !root.is_dir() {
            continue;
        }
        if fits_erofs_shape(root) {
            return true;
        }
        // Children of an overlay mountpoint are the informative case.
        let Ok(rd) = fs::read_dir(root) else { continue };
        for e in rd.flatten().take(12) {
            let p = e.path();
            if p.is_dir() && fits_erofs_shape(&p) {
                return true;
            }
            checked += 1;
            if checked > 60 {
                break;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The formula, pinned against directories measured on OP15 erofs. If this
    /// ever changes, every claim built on it is void.
    #[test]
    fn model_matches_measured_erofs_directories() {
        // (entries, total name bytes, observed st_size)
        for (n, names, size) in [
            (17u64, 186u64, 417u64),   // /product/etc
            (15, 236, 443),            // /system/app
            (2, 13, 64),               // /product/priv-app/AICore
            (1, 19, 58),               // /product/priv-app/AndroidAutoStub
            (3, 16, 79),               // /product/priv-app/AIUnit
        ] {
            assert_eq!(12 * (n + 2) + names + 3, size, "n={n} names={names}");
        }
    }
}
