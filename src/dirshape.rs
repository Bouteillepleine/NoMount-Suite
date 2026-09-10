
use std::fs;
use std::path::Path;

fn erofs_model(dir: &Path) -> Option<u64> {
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
