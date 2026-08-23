//! PackageManager's on-disk parse cache.
//!
//! `/data/system/package_cache/<hash>/<Leaf>-<sdk>-<hash>` holds PM's serialized
//! parse of one APK, keyed on the APK's containing directory name -- `Contacts`
//! for `/product/priv-app/Contacts/Contacts.apk`. Swapping a ROM APK under a
//! rule leaves that entry describing the bytes we no longer serve, and because
//! it lives on disk a reboot does not clear it: the app keeps launching against
//! a parse of the old APK. Measured on OP15 as a dialer that force-closed with
//! "You need to use a Theme.AppCompat theme" until the entry was deleted.
//!
//! Deleting the entry is safe -- PM re-parses the APK and writes a new one.
//! We only do it for an APK whose served bytes actually CHANGED, so an ordinary
//! boot re-parses nothing.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

const CACHE_DIR: &str = "/data/system/package_cache";
/// Last-served identity per ROM APK: target \t source \t mtime \t size.
const STATE: &str = "/data/adb/nomount/apkstate.list";
/// APKs invalidated after PM had already parsed them -- cured by a reboot.
const PENDING: &str = "/data/adb/nomount/pm-reboot.list";

/// ROM partitions whose APKs PM parses at scan time. A /data APK is PM's own
/// and is never served by a rule.
const ROM_ROOTS: &[&str] = &[
    "/system/", "/system_ext/", "/product/", "/vendor/", "/odm/", "/my_product/", "/my_region/",
    "/my_stock/", "/my_company/", "/my_carrier/", "/my_engineering/", "/my_heytap/", "/my_preload/",
];

pub fn is_rom_apk(target: &Path) -> bool {
    let s = target.to_string_lossy();
    target.extension().is_some_and(|e| e == "apk") && ROM_ROOTS.iter().any(|r| s.starts_with(r))
}

/// The cache-entry prefixes PM may use for this APK. PM names the entry after
/// the package's codePath leaf, which is the APK file for a monolithic install
/// in a shared directory (`OxygenCustomizerComponentCR1.apk-16-...` under
/// /product/overlay) and the directory for one that owns its own
/// (`Contacts-16-...` for /product/priv-app/Contacts/Contacts.apk). The dir form
/// is only offered when the directory holds this APK alone, so a shared one like
/// /product/overlay never contributes a bare `overlay-` that matches whatever
/// happens to sort under it. The trailing dash keeps `Contacts-` off
/// `ContactsProvider-16-...`.
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

/// Drop every cached parse for `target`. Returns how many entries were removed.
fn drop_entry(target: &Path) -> usize {
    let keys = cache_keys(target);
    if keys.is_empty() {
        return 0;
    }
    let Ok(dirs) = fs::read_dir(CACHE_DIR) else { return 0 };
    let mut n = 0;
    for d in dirs.filter_map(Result::ok) {
        let Ok(entries) = fs::read_dir(d.path()) else { continue };
        for e in entries.filter_map(Result::ok) {
            let name = e.file_name().to_string_lossy().into_owned();
            if keys.iter().any(|k| name.starts_with(k.as_str())) && fs::remove_file(e.path()).is_ok()
            {
                n += 1;
            }
        }
    }
    n
}

/// What we last served for a target, as recorded by [`sync`].
fn read_state() -> HashMap<PathBuf, String> {
    let Ok(txt) = fs::read_to_string(STATE) else { return HashMap::new() };
    txt.lines()
        .filter_map(|l| {
            let (t, id) = l.split_once('\t')?;
            Some((PathBuf::from(t), id.to_string()))
        })
        .collect()
}

/// mtime+size of the file actually being served. Absent source -> None, which
/// never matches a recorded identity and so re-invalidates once it returns.
fn identity(source: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let m = fs::metadata(source).ok()?;
    Some(format!("{}\t{}", m.mtime(), m.size()))
}

/// Invalidate PM's cached parse for every ROM APK whose served bytes changed
/// since the last pass, and record what is served now. Returns the targets that
/// were invalidated.
pub fn sync(served: &[(PathBuf, PathBuf)]) -> Vec<PathBuf> {
    // No state yet (first run after an upgrade): adopt what is served instead of
    // calling every APK changed and dropping the whole cache for nothing.
    let seeding = !Path::new(STATE).exists();
    let previous = read_state();
    let mut changed = Vec::new();
    let mut lines = Vec::new();

    for (target, source) in served.iter().filter(|(t, _)| is_rom_apk(t)) {
        let Some(id) = identity(source) else { continue };
        let stale = previous.get(target).map(String::as_str) != Some(id.as_str());
        if !seeding && stale && drop_entry(target) > 0 {
            changed.push(target.clone());
        }
        lines.push(format!("{}\t{}", target.display(), id));
    }

    // A target that had a rule and no longer does is back to its stock bytes,
    // so PM's parse of the injected APK is just as stale.
    let live: Vec<&PathBuf> = served.iter().map(|(t, _)| t).collect();
    for target in previous.keys().filter(|t| !live.contains(t)) {
        if !seeding && drop_entry(target) > 0 {
            changed.push(target.clone());
        }
    }

    let _ = fs::write(STATE, lines.join("\n"));
    changed
}

/// Record APKs invalidated while PM was already running: their parse is only
/// rebuilt at the next scan, so the swap is not fully applied until a reboot.
/// Accumulates -- the state is only resolved by the reboot, so a later no-op
/// reload must not report the earlier swap as applied.
pub fn add_pending(targets: &[PathBuf]) {
    if targets.is_empty() {
        return;
    }
    let mut all = pending();
    for t in targets {
        if !all.contains(t) {
            all.push(t.clone());
        }
    }
    let body: Vec<String> = all.iter().map(|t| t.display().to_string()).collect();
    let _ = fs::write(PENDING, body.join("\n"));
}

pub fn pending() -> Vec<PathBuf> {
    fs::read_to_string(PENDING)
        .map(|t| t.lines().filter(|l| !l.is_empty()).map(PathBuf::from).collect())
        .unwrap_or_default()
}

/// Called from the boot pass: PM re-parses this boot, so anything recorded by
/// an earlier session is resolved.
pub fn clear_pending() {
    let _ = fs::remove_file(PENDING);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A my_* APK is bind-served, and a bind swaps the parsed bytes too -- it
    /// must be tracked like any other ROM APK.
    #[test]
    fn my_partition_apks_are_tracked() {
        assert!(is_rom_apk(Path::new("/my_product/app/Foo/Foo.apk")));
        assert!(is_rom_apk(Path::new("/my_stock/priv-app/Bar/Bar.apk")));
    }

    #[test]
    fn only_rom_apks_are_pm_parsed() {
        assert!(is_rom_apk(Path::new("/product/priv-app/Contacts/Contacts.apk")));
        assert!(is_rom_apk(Path::new("/system/app/Foo/Foo.apk")));
        // PM owns its own copies, and a non-APK has no cached parse.
        assert!(!is_rom_apk(Path::new("/data/app/~~x==/com.foo-1/base.apk")));
        assert!(!is_rom_apk(Path::new("/product/etc/config.xml")));
        assert!(!is_rom_apk(Path::new("/data/adb/nomount/apks/youtube-patched.apk")));
    }

    /// Both layouts PM uses, measured on OP15: `Contacts-16-...` for a dir it
    /// owns, `OxygenCustomizerComponentCR1.apk-16-...` for one of the 139 APKs
    /// sharing /product/overlay.
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

        // A shared directory offers only the file name: no bare `overlay-`.
        let shared = std::env::temp_dir().join("nm-pmcache-test/overlay");
        fs::create_dir_all(&shared).unwrap();
        fs::write(shared.join("A.apk"), b"x").unwrap();
        fs::write(shared.join("B.apk"), b"x").unwrap();
        assert_eq!(cache_keys(&shared.join("A.apk")), vec!["A.apk-".to_string()]);
        let _ = fs::remove_dir_all(std::env::temp_dir().join("nm-pmcache-test"));
    }
}
