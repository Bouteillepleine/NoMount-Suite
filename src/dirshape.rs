//! Decide whether this device's ROM directories describe their own contents

use std::fs;
use std::path::Path;

/// erofs's `statfs` magic
pub(crate) const EROFS_MAGIC: i64 = 0xE0F5_E1E2;

/// `statfs(2)`'s `f_type` for `p`, or `None` if it would not statfs
pub(crate) fn fs_magic(p: &Path) -> Option<i64> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(p.as_os_str().as_bytes()).ok()?;
    let mut sf: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut sf) } != 0 {
        return None;
    }
    Some(sf.f_type as i64)
}

/// `12*(n+2) + sum(namelen) + 3` - the `+2`/`+3` are `.` and `..`, which the listing does
pub(crate) fn erofs_model(dir: &Path) -> Option<u64> {
    let mut n: u64 = 0;
    let mut names: u64 = 0;
    for e in fs::read_dir(dir).ok()? {
        let Ok(e) = e else { continue };
        n += 1;
        names += e.file_name().as_encoded_bytes().len() as u64;
    }
    if n == 0 {
        return None;
    }
    Some(12 * (n + 2) + names + 3)
}

fn fits_erofs_shape(dir: &Path) -> bool {
    let Ok(md) = fs::metadata(dir) else { return false };
    let size = md.len();
    if size == 0 || size >= 4096 {
        return false;
    }
    erofs_model(dir) == Some(size)
}

/// Walk the ROM looking for proof
pub fn rom_dirs_are_dirent_packed() -> bool {
    const ROOTS: &[&str] = &[
        "/system/app", "/system/priv-app", "/system/etc", "/product/app",
        "/product/priv-app", "/product/etc", "/vendor/etc", "/system_ext/app",
    ];
    for root in ROOTS {
        let root = Path::new(root);
        if !root.is_dir() {
            continue;
        }
        if fits_erofs_shape(root) {
            return true;
        }
        let Ok(rd) = fs::read_dir(root) else { continue };
        for e in rd.flatten().take(12) {
            let p = e.path();
            if p.is_dir() && fits_erofs_shape(&p) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {

    #[test]
    fn model_matches_measured_erofs_directories() {
        for (n, names, size) in [
            (17u64, 186u64, 417u64),
            (15, 236, 443),
            (2, 13, 64),
            (1, 19, 58),
            (3, 16, 79),
        ] {
            assert_eq!(12 * (n + 2) + names + 3, size, "n={n} names={names}");
        }
    }
}
