//! PackageManager's on-disk parse cache

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const CACHE_DIR: &str = "/data/system/package_cache";
const STATE: &str = "/data/adb/nomount/apkstate.list";
const PENDING: &str = "/data/adb/nomount/pm-reboot.list";

const ROM_ROOTS: &[&str] = &[
    "/system/", "/system_ext/", "/product/", "/vendor/", "/odm/", "/my_product/", "/my_region/",
    "/my_stock/", "/my_company/", "/my_carrier/", "/my_engineering/", "/my_heytap/", "/my_preload/",
];

/// ROM partition names, for anything that needs "is this path on the ROM" rather than
pub const ROM_PARTITIONS: &[&str] = &[
    "system", "system_ext", "product", "vendor", "odm",
    "my_product", "my_region", "my_stock", "my_company", "my_carrier", "my_engineering",
    "my_heytap", "my_preload", "my_bigball", "my_manifest", "my_reserve",
];

const PM_SCAN_DIRS: &[&str] = &["app", "priv-app", "overlay", "app-ext", "priv-app-ext"];

/// Any file inside a directory pm scans, i.e
pub fn is_pm_published(target: &Path) -> bool {
    let s = target.to_string_lossy();
    if !ROM_ROOTS.iter().any(|r| s.starts_with(r)) {
        return false;
    }
    target
        .components()
        .nth(2)
        .and_then(|c| c.as_os_str().to_str())
        .is_some_and(|d| PM_SCAN_DIRS.contains(&d))
}

/// A ROM APK PM parses at scan time
pub fn is_rom_apk(target: &Path) -> bool {
    target.extension().is_some_and(|e| e == "apk") && is_pm_published(target)
}

fn cache_keys(target: &Path) -> Vec<String> {
    let mut keys = Vec::new();
    if let Some(file) = target.file_name() {
        keys.push(format!("{}-", file.to_string_lossy()));
    }
    let Some(dir) = target.parent() else { return keys };
    let apks = fs::read_dir(dir).ok().map(|rd| {
        rd.filter_map(Result::ok)
            .filter(|e| e.path().extension().is_some_and(|x| x == "apk"))
            .count()
    });
    if apks == Some(1) {
        if let Some(name) = dir.file_name() {
            keys.push(format!("{}-", name.to_string_lossy()));
        }
    }
    keys
}

fn cache_files() -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for d in fs::read_dir(CACHE_DIR)? {
        let Ok(d) = d else { continue };
        let Ok(entries) = fs::read_dir(d.path()) else { continue };
        out.extend(entries.filter_map(|e| e.ok()).map(|e| e.path()));
    }
    Ok(out)
}

fn drop_entry(target: &Path, cache: &[PathBuf]) -> (usize, usize) {
    let keys = cache_keys(target);
    if keys.is_empty() {
        return (0, 0);
    }
    let (mut matched, mut removed) = (0usize, 0usize);
    for p in cache {
        let Some(name) = p.file_name().map(|n| n.to_string_lossy().into_owned()) else { continue };
        if !keys.iter().any(|k| name.starts_with(k.as_str())) {
            continue;
        }
        matched += 1;
        if fs::remove_file(p).is_ok() {
            removed += 1;
        }
    }
    (matched, removed)
}

fn read_state() -> Option<HashMap<PathBuf, String>> {
    let txt = match fs::read_to_string(STATE) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(_) => return None,
    };
    Some(
        txt.lines()
            .filter_map(|l| {
                let (t, id) = l.split_once('\t')?;
                Some((PathBuf::from(t), id.to_string()))
            })
            .collect(),
    )
}

fn identity(source: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(source).ok()?;
    Some(format!("{}\t{}", m.mtime(), m.size()))
}

/// Invalidate PM's cached parse for every ROM APK whose served bytes changed since the
pub fn sync(served: &[(PathBuf, PathBuf)]) -> Vec<PathBuf> {
    let (previous, seeding) = match read_state() {
        Some(p) => (p, !Path::new(STATE).exists()),
        None => {
            eprintln!(
                "nomount: pmcache: {STATE} exists but could not be read - adopting what is \
                 served now instead of treating every injected APK as changed"
            );
            (HashMap::new(), true)
        }
    };
    let cache = match cache_files() {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            eprintln!(
                "nomount: pmcache: {CACHE_DIR} could not be read ({e}) - not recording what is \
                 served, so the next pass re-checks instead of adopting a parse it could not \
                 invalidate"
            );
            return Vec::new();
        }
    };

    let mut changed = Vec::new();
    let mut lines = Vec::new();

    for (target, source) in served.iter().filter(|(t, _)| is_rom_apk(t)) {
        let Some(id) = identity(source) else { continue };
        let stale = previous.get(target).map(String::as_str) != Some(id.as_str());
        let (matched, removed) =
            if !seeding && stale { drop_entry(target, &cache) } else { (0, 0) };
        if removed > 0 {
            changed.push(target.clone());
        }
        if matched > removed {
            eprintln!(
                "nomount: pmcache: {} cached parse(s) for {} would not delete - PM keeps \
                 serving its parse of the previous APK; retrying next pass",
                matched - removed,
                target.display()
            );
            if let Some(old) = previous.get(target) {
                lines.push(format!("{}\t{}", target.display(), old));
            }
            continue;
        }
        lines.push(format!("{}\t{}", target.display(), id));
    }

    let live: Vec<&PathBuf> = served.iter().map(|(t, _)| t).collect();
    for target in previous.keys().filter(|t| !live.contains(t)) {
        if seeding {
            continue;
        }
        let (matched, removed) = drop_entry(target, &cache);
        if removed > 0 {
            changed.push(target.clone());
        }
        if matched > removed {
            if let Some(old) = previous.get(target) {
                lines.push(format!("{}\t{}", target.display(), old));
            }
        }
    }

    if let Err(e) = crate::statefile::write_atomic(STATE, lines.join("\n")) {
        eprintln!("nomount: pmcache: could not write {STATE} ({e:#}) - the next pass will \
                   re-invalidate every served APK");
    }
    changed
}

/// Record APKs invalidated while pm was already running: their parse is only rebuilt at
pub fn add_pending(targets: &[PathBuf]) {
    if targets.is_empty() {
        return;
    }
    let Ok(mut all) = pending_result() else {
        eprintln!(
            "nomount: pmcache: {PENDING} could not be read - not rewriting it, so the {} APK(s) \
             recorded now are not added and the existing list is kept",
            targets.len()
        );
        return;
    };
    for t in targets {
        if !all.contains(t) {
            all.push(t.clone());
        }
    }
    let body: Vec<String> = all.iter().map(|t| t.display().to_string()).collect();
    if let Err(e) = crate::statefile::write_atomic(PENDING, body.join("\n")) {
        eprintln!(
            "nomount: pmcache: could not write {PENDING} ({e:#}) - {} APK(s) need a reboot and \
             nothing now records it",
            all.len()
        );
    }
}

fn pending_result() -> std::io::Result<Vec<PathBuf>> {
    match fs::read_to_string(PENDING) {
        Ok(t) => Ok(t.lines().filter(|l| !l.is_empty()).map(PathBuf::from).collect()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// The accumulated reboot-required set, best effort
pub fn pending() -> Vec<PathBuf> {
    pending_result().unwrap_or_else(|e| {
        eprintln!(
            "nomount: pmcache: {PENDING} exists but could not be read ({e}) - the \
             reboot-required list may be incomplete"
        );
        Vec::new()
    })
}

/// Called from the boot pass: PM re-parses this boot, so anything recorded by an earlier
pub fn clear_pending() {
    let _ = fs::remove_file(PENDING);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn my_partition_apks_are_tracked() {
        assert!(is_rom_apk(Path::new("/my_product/app/Foo/Foo.apk")));
        assert!(is_rom_apk(Path::new("/my_stock/priv-app/Bar/Bar.apk")));
    }

    #[test]
    fn rom_partitions_cover_every_pm_scan_root() {
        for r in ROM_ROOTS {
            let name = r.trim_matches('/');
            assert!(
                ROM_PARTITIONS.contains(&name),
                "{name} is a pm scan root but not a known ROM partition"
            );
        }
        for extra in ["my_bigball", "my_manifest", "my_reserve"] {
            assert!(ROM_PARTITIONS.contains(&extra));
        }
    }

    #[test]
    fn only_rom_apks_are_pm_parsed() {
        assert!(is_rom_apk(Path::new("/product/priv-app/Contacts/Contacts.apk")));
        assert!(is_rom_apk(Path::new("/system/app/Foo/Foo.apk")));
        assert!(!is_rom_apk(Path::new("/data/app/~~x==/com.foo-1/base.apk")));
        assert!(!is_rom_apk(Path::new("/product/etc/config.xml")));
        assert!(!is_rom_apk(Path::new("/data/adb/nomount/apks/youtube-patched.apk")));
    }

    #[test]
    fn files_outside_a_pm_scan_dir_stay_hidden() {
        for p in [
            "/product/etc/foo.apk",
            "/product/media/x.apk",
            "/system/framework/bar.apk",
            "/vendor/lib/baz.apk",
            "/my_product/etc/extension/q.apk",
        ] {
            assert!(!is_pm_published(Path::new(p)), "{p} must not be public");
        }
        for p in [
            "/product/overlay/OxygenCustomizerComponentNB8.apk",
            "/product/priv-app/Mms/Mms.apk",
            "/product/priv-app/Mms/lib/arm64/libjni.so",
            "/system_ext/app/Foo/Foo.apk",
            "/system_ext/app/Foo/lib/arm64/libfoo.so",
            "/my_stock/priv-app/Bar/Bar.apk",
        ] {
            assert!(is_pm_published(Path::new(p)), "{p} should be public");
        }
        assert!(is_rom_apk(Path::new("/product/priv-app/Mms/Mms.apk")));
        assert!(!is_rom_apk(Path::new("/product/priv-app/Mms/lib/arm64/libjni.so")));
    }

    #[test]
    fn the_kernel_carries_the_same_pm_scan_lists() {
        let src = std::fs::read_to_string("hookless/src/nomount.c").expect(
            "hookless/src/nomount.c must be readable -- the engine lives in this repository \
             precisely so this invariant can be checked; if it has moved out again, this test \
             is the thing that has to move with it",
        );
        let fun = src
            .split_once("fn_marker_nm_vpath_in_pm_scandir")
            .map(|(_, r)| r)
            .or_else(|| src.split_once("static bool nm_vpath_in_pm_scandir").map(|(_, r)| r))
            .expect("nm_vpath_in_pm_scandir() not found - was it renamed?");
        let body = &fun[..fun.find("\n}").expect("unterminated function")];

        let table = |name: &str| -> Vec<String> {
            let at = body
                .find(&format!("*const {name}[] = {{"))
                .unwrap_or_else(|| panic!("the kernel's `{name}` table is gone or renamed"));
            let rest = &body[at..];
            let end = rest.find("};").expect("unterminated table");
            let mut out = Vec::new();
            let mut it = rest[..end].split('"');
            let _ = it.next();
            while let Some(word) = it.next() {
                out.push(word.to_string());
                if it.next().is_none() {
                    break;
                }
            }
            out.sort();
            out
        };

        let mut ours: Vec<String> = ROM_ROOTS
            .iter()
            .map(|r| r.trim_matches('/').to_string())
            .collect();
        ours.sort();
        assert_eq!(
            table("roots"),
            ours,
            "ROM_ROOTS and the kernel's roots[] have diverged -- a rule on a partition only \
             userspace knows about is granted --public here and stripped of it by the engine"
        );

        let mut dirs: Vec<String> = PM_SCAN_DIRS.iter().map(|d| d.to_string()).collect();
        dirs.sort();
        assert_eq!(
            table("dirs"),
            dirs,
            "PM_SCAN_DIRS and the kernel's dirs[] have diverged - same failure, one level down"
        );
    }

    #[test]
    fn cache_keys_cover_file_and_dedicated_dir() {
        let dir = std::env::temp_dir().join("nm-pmcache-test/priv-app/Contacts");
        fs::create_dir_all(&dir).unwrap();
        let apk = dir.join("Contacts.apk");
        fs::write(&apk, b"x").unwrap();
        let keys = cache_keys(&apk);
        assert!(keys.contains(&"Contacts.apk-".to_string()));
        assert!(keys.contains(&"Contacts-".to_string()), "own dir contributes its name");
        assert!(!"ContactsProvider-16-1".starts_with("Contacts-"));

        let shared = std::env::temp_dir().join("nm-pmcache-test/overlay");
        fs::create_dir_all(&shared).unwrap();
        fs::write(shared.join("A.apk"), b"x").unwrap();
        fs::write(shared.join("B.apk"), b"x").unwrap();
        assert_eq!(cache_keys(&shared.join("A.apk")), vec!["A.apk-".to_string()]);
        let _ = fs::remove_dir_all(std::env::temp_dir().join("nm-pmcache-test"));
    }
}
