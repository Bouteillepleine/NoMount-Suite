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
/// DELIBERATELY a fixed list, unlike `mount.rs`, which discovers partitions from
/// the device. This one is half of a contract with the kernel: `nm_vpath_in_pm_scandir()`
/// applies the same predicate to decide whether a SHADOWS_STOCK rule may keep
/// NM_FLAG_PUBLIC, and userspace is the source of truth for granting it.
/// `the_kernel_carries_the_same_pm_scan_lists` now asserts the two agree -- which
/// only became possible when the engine moved into this repository.
///
/// KNOWN, MEASURED GAP. Widening it is not a one-line change, so the shortfall is
/// recorded rather than quietly carried. On an OP11 (CPH2449, OOS15) the ROM has
/// six top-level directories this list does not name: `/my_bigball`,
/// `/my_manifest`, `/my_reserve`, `/special_preload`, `/odm_dlkm` and
/// `/bootstrap-apex`. Only `/my_bigball` is a PackageManager scan target at all --
/// it ships `app/`, `priv-app/` and `overlay/` -- and on that ROM all three are
/// EMPTY, so nothing is currently mis-served. A module that shipped an APK there
/// would get no `--public` and no cache invalidation.
///
/// Fixing it needs BOTH lists and a version gate, in that order:
///   * widening userspace alone is worse than the gap -- the engine strips the bit
///     from any shadowing rule on the new partition, so PM advertises the module's
///     APK while a blocked reader is served the stock bytes, which is the exact
///     inconsistency NM_FLAG_PUBLIC exists to remove;
///   * widening the kernel alone changes nothing, since userspace never grants it;
///   * widening both is only safe for a matched pair, and the Suite (a zip) and the
///     engine (in the kernel) are flashed separately. So it needs a NOMOUNT_VERSION
///     bump and an `engine >= N` gate here, exactly like the 15/17 opt-out gates in
///     doctor.rs -- otherwise a Suite update on an unflashed kernel lands in the
///     first bullet.
const ROM_ROOTS: &[&str] = &[
    "/system/", "/system_ext/", "/product/", "/vendor/", "/odm/", "/my_product/", "/my_region/",
    "/my_stock/", "/my_company/", "/my_carrier/", "/my_engineering/", "/my_heytap/", "/my_preload/",
];

/// The directory names PM actually scans for packages. A file anywhere else on a
/// ROM partition is just a file: PM never parses it, so it has no cache entry to
/// invalidate and -- far more importantly -- it is not advertised to any app.
///
/// This gate is load-bearing beyond the cache. `Nm::add` passes [`is_pm_published`]
/// as the `--public` flag, i.e. "exempt this rule from per-UID hiding", and the
/// only justification for that exemption is that the PackageManager already hands
/// the path to every app that asks (see the NM_FLAG_PUBLIC note in nomount.h). A
/// path-prefix test alone made every file under a ROM root public, so a module
/// shipping `/product/etc/foo.apk` or `/product/media/x.apk` -- which PM never
/// scans, never registers and never advertises -- was handed to the detector apps
/// on the hide list for no benefit at all. Narrow it to what PM really reads.
///
/// The kernel's PUBLIC-strip exemption is changed in lockstep to use this SAME
/// scan-dir predicate, so this list must stay identical to the kernel's; pmcache.rs
/// is the single source of truth for it.
const PM_SCAN_DIRS: &[&str] = &["app", "priv-app", "overlay", "app-ext", "priv-app-ext"];

/// Any file inside a directory PM scans, i.e. one PM registers a codePath for and
/// advertises to every app that asks. This is what grants `--public`.
///
/// Deliberately NOT limited to the `.apk`: PM publishes a package's whole
/// codePath, `nativeLibraryDir` included -- `com.android.mms` at
/// `/product/priv-app/Mms` advertises `legacyNativeLibraryDir=.../Mms/lib`, so the
/// `.so` files under `Mms/lib/arm64` are named to any app just as `Mms.apk` is.
/// Hiding them from a blocked uid while PM says they exist is the same
/// Trusteer-class inconsistency the APK case is (PM names the path, `open()`
/// answers ENOENT). So every file under `<partition>/<scan-dir>/<PkgDir>/…`,
/// including the synthesized `lib`/`lib/<abi>` subtree, is exempted.
pub fn is_pm_published(target: &Path) -> bool {
    let s = target.to_string_lossy();
    if !ROM_ROOTS.iter().any(|r| s.starts_with(r)) {
        return false;
    }
    // PM's layout is <partition>/<scan-dir>/… -- either a file directly
    // (/product/overlay/Foo.apk) or one directory of its own below it
    // (/product/priv-app/Contacts/Contacts.apk, .../Contacts/lib/arm64/*.so).
    // Match the component after the partition rather than searching the whole
    // path, so a stray directory called "app" deeper down does not qualify.
    target
        .components()
        .nth(2)
        .and_then(|c| c.as_os_str().to_str())
        .is_some_and(|d| PM_SCAN_DIRS.contains(&d))
}

/// A ROM APK PM parses at scan time. The cache-invalidation half of this module
/// keys on this: only an APK has a cached parse to drop. For the `--public`
/// decision use [`is_pm_published`], which covers the rest of the codePath too.
pub fn is_rom_apk(target: &Path) -> bool {
    target.extension().is_some_and(|e| e == "apk") && is_pm_published(target)
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

    let _ = crate::statefile::write_atomic(STATE, lines.join("\n"));
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
    let _ = crate::statefile::write_atomic(PENDING, body.join("\n"));
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

    /// A file on a ROM partition that PM does NOT scan must not be treated as one
    /// it does: `is_pm_published` is what grants `--public`, i.e. exemption from
    /// per-UID hiding, and the only thing that justifies the exemption is PM
    /// already advertising the path. A prefix-only test made all of these public.
    #[test]
    fn files_outside_a_pm_scan_dir_stay_hidden() {
        for p in [
            "/product/etc/foo.apk",
            "/product/media/x.apk",
            "/system/framework/bar.apk",
            "/vendor/lib/baz.apk",
            "/my_product/etc/extension/q.apk",
        ] {
            assert!(!is_pm_published(Path::new(p)), "{p} must NOT be public");
        }
        // ...while the directories PM really reads still qualify, in both layouts,
        // and for the WHOLE codePath -- the nativeLibraryDir .so files too, not
        // just the .apk (the H3 hole: PM advertises Mms/lib/arm64 as well).
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
        // is_rom_apk stays APK-only -- it drives cache invalidation, and only an
        // APK has a cached parse to drop.
        assert!(is_rom_apk(Path::new("/product/priv-app/Mms/Mms.apk")));
        assert!(!is_rom_apk(Path::new("/product/priv-app/Mms/lib/arm64/libjni.so")));
    }

    /// Both layouts PM uses, measured on OP15: `Contacts-16-...` for a dir it
    /// owns, `OxygenCustomizerComponentCR1.apk-16-...` for one of the 139 APKs
    /// sharing /product/overlay.
    /// The kernel carries the SAME two lists, and CI is now able to say so.
    ///
    /// `nm_vpath_in_pm_scandir()` in hookless/src/nomount.c repeats this test so a
    /// mislabelling client cannot keep NM_FLAG_PUBLIC on a rule that shadows a
    /// stock file PM never advertised. Its own comment calls pmcache.rs the source
    /// of truth and says the kernel copy "must be at least as strict as
    /// userspace" -- an invariant that, until the engine moved into this
    /// repository, no test could reach: the two lists were hand-maintained in two
    /// languages in two repos, and the only thing keeping them in step was
    /// somebody remembering.
    ///
    /// Divergence is silent and asymmetric, which is why it is worth a test:
    ///   * widen USERSPACE alone and a replaced APK on the new partition is
    ///     granted --public here and stripped of it there, so a blocked app is
    ///     served the stock bytes for a path PM advertises the module's version
    ///     of -- the inconsistency the flag exists to remove, reintroduced;
    ///   * widen the KERNEL alone and nothing happens at all, because userspace
    ///     never grants the bit for those paths.
    ///
    /// Compared as sets: the order is not semantic, and the kernel spells the
    /// partitions without the surrounding slashes this file uses.
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
            .expect("nm_vpath_in_pm_scandir() not found -- was it renamed?");
        let body = &fun[..fun.find("\n}").expect("unterminated function")];

        // Pull the quoted words out of one `static const char *const <name>[] = {...}`.
        let table = |name: &str| -> Vec<String> {
            let at = body
                .find(&format!("*const {name}[] = {{"))
                .unwrap_or_else(|| panic!("the kernel's `{name}` table is gone or renamed"));
            let rest = &body[at..];
            let end = rest.find("};").expect("unterminated table");
            let mut out = Vec::new();
            let mut it = rest[..end].split('"');
            let _ = it.next(); // before the first quote
            while let Some(word) = it.next() {
                out.push(word.to_string());
                if it.next().is_none() {
                    break; // the gap between this string and the next
                }
            }
            out.sort();
            out
        };

        // The kernel stores bare segments; this file stores "/<part>/".
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
            "PM_SCAN_DIRS and the kernel's dirs[] have diverged -- same failure, one level down"
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

        // A shared directory offers only the file name: no bare `overlay-`.
        let shared = std::env::temp_dir().join("nm-pmcache-test/overlay");
        fs::create_dir_all(&shared).unwrap();
        fs::write(shared.join("A.apk"), b"x").unwrap();
        fs::write(shared.join("B.apk"), b"x").unwrap();
        assert_eq!(cache_keys(&shared.join("A.apk")), vec!["A.apk-".to_string()]);
        let _ = fs::remove_dir_all(std::env::temp_dir().join("nm-pmcache-test"));
    }
}
