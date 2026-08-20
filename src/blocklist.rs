//! Persistent, package-name-aware UID block list.
//!
//! The kernel's per-UID hiding (`nm block <uid>`) is **runtime-only**: the idr
//! that backs it lives in kernel memory and is empty after every reboot (and is
//! destroyed again by `nm clear`). It also speaks raw UIDs, which nobody
//! remembers — `10487` tells you nothing, whereas `me.garfieldhan.holmes` does.
//!
//! This module closes both gaps without touching the kernel:
//!   * a plain-text file (`/data/adb/nomount/uidhide`) is the source of truth,
//!     one entry per line — a package name (preferred, durable) or a bare UID;
//!   * package names are resolved to their live appid via the canonical
//!     `/data/system/packages.list` (root-readable, no `pm` fork);
//!   * every successful resolve is mirrored into `uidhide.cache`, so the mount
//!     pass can re-block at post-fs-data — before a single app has started —
//!     instead of waiting for `packages.list` to be meaningful at boot_completed;
//!   * `apply` re-blocks every resolved appid and is invoked from the mount pass
//!     and again from `service.sh`, so a hidden detector stays hidden across
//!     reboots *and* across a mid-session `nomount mount`.
//!
//! Matching is on the **appid** (`uid % 100000`), exactly like the kernel: one
//! entry covers the app in every user, work profile and clone.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

/// Source of truth for the persistent hide list.
pub const BLOCKLIST_PATH: &str = "/data/adb/nomount/uidhide";

/// Where this list used to live — the same file `mount.rs` reads as the list of
/// *module ids to skip injecting*. One file, two schemas: hiding an app also
/// inserted it into the module-skip set, every module-skip entry showed up in the
/// WebUI as a "hidden app", and its ✕ button deleted a line whose real job was to
/// keep a self-mounting module from being injected. Split, with a one-time
/// migration that only moves entries which are not the id of an installed module.
const LEGACY_PATH: &str = "/data/adb/nomount/blocklist";

/// Resolved appids, mirrored from the last successful resolve. Lets the mount
/// pass re-block at post-fs-data without depending on `packages.list`.
const CACHE_PATH: &str = "/data/adb/nomount/uidhide.cache";

/// Feature settings that must be re-asserted after every reboot / `nm clear`.
const CONF_PATH: &str = "/data/adb/nomount/uidhide.conf";

/// Android's canonical package→UID map. Column 0 is the package name, column 1
/// the app UID. Root-readable; avoids forking `pm` (slow, and unavailable early
/// in boot when the mount pass runs).
const PACKAGES_LIST: &str = "/data/system/packages.list";

const MODULES_DIR: &str = "/data/adb/modules";

/// Android packs (user, appid) into a uid. The kernel stores and matches the
/// appid, so the CLI must normalise the same way or the two disagree about a
/// clone/work-profile UID — which made `uid unblock 1010471` report success while
/// the kernel went on hiding appid 10471.
pub const PER_USER_RANGE: u32 = 100_000;

/// Below this is the platform (root, system_server, shell, radio…). Blocking one
/// of these hides injections from Android itself; `2000` additionally breaks the
/// health canary, which probes as shell.
pub const FIRST_APP_APPID: u32 = 10_000;

/// Normalise a raw UID to the appid the kernel matches on.
pub fn appid(uid: u32) -> u32 {
    uid % PER_USER_RANGE
}

/// What an entry resolved to, for display in `uid list`.
pub enum Resolved {
    /// Package (or bare UID) resolved to this live appid.
    Uid(u32),
    /// A package name that isn't in `packages.list` right now (not installed, or
    /// disabled for the current user). Kept in the list so it re-arms if the app
    /// returns; simply skipped by `apply`.
    NotInstalled,
}

/// Resolve a hide-list target to an appid.
///
/// A purely numeric target is taken verbatim (already a UID) and normalised.
/// Anything else is a package name, looked up in `packages.list`.
/// A hide-list entry that is not a single package or UID but a glob over package
/// names. Detectors are the reason this exists: Duck ships as `*.duckdetector`,
/// Holmes under `me.garfieldhan.*`, Chunqiu with the string buried mid-name — all
/// under package names that change between builds, so an exact list cannot hold
/// them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// `com.foo.*`
    Prefix(String),
    /// `*.duckdetector`
    Suffix(String),
    /// `*chunqiu*`
    Contains(String),
}

/// Shortest literal a glob may carry. `*a*` would match most of the device and a
/// bare `*` all of it; hiding injections from every installed app is never what
/// someone meant to type, so it is rejected rather than silently applied.
pub const MIN_PATTERN_LITERAL: usize = 4;

impl Pattern {
    /// Parse a glob. `None` = not a glob (no `*`), so the caller treats it as an
    /// exact package name. `Some(Err)` = a glob that is too broad to honour.
    pub fn parse(entry: &str) -> Option<Result<Pattern>> {
        let e = entry.trim();
        if !e.contains('*') {
            return None;
        }
        let stripped = e.trim_start_matches('*').trim_end_matches('*');
        if stripped.contains('*') {
            return Some(Err(anyhow::anyhow!(
                "{e:?}: `*` is only allowed at the start and/or end"
            )));
        }
        if stripped.len() < MIN_PATTERN_LITERAL {
            return Some(Err(anyhow::anyhow!(
                "{e:?}: needs at least {MIN_PATTERN_LITERAL} literal characters \
                 (a broader glob would hide injections from most of the device)"
            )));
        }
        let lit = stripped.to_string();
        Some(Ok(match (e.starts_with('*'), e.ends_with('*')) {
            (true, true) => Pattern::Contains(lit),
            (true, false) => Pattern::Suffix(lit),
            (false, true) => Pattern::Prefix(lit),
            // No leading or trailing `*`, yet `contains('*')` held: impossible.
            (false, false) => unreachable!("glob with no anchor"),
        }))
    }

    pub fn matches(&self, pkg: &str) -> bool {
        match self {
            Pattern::Prefix(p) => pkg.starts_with(p.as_str()),
            Pattern::Suffix(p) => pkg.ends_with(p.as_str()),
            Pattern::Contains(p) => pkg.contains(p.as_str()),
        }
    }
}

/// Every installed package and its appid, from `packages.list`. One read serves a
/// whole apply pass; globs are matched against this rather than forking `pm`.
///
/// `None` means the map could not be read (not root, or too early in boot) — which
/// is NOT the same as "nothing is installed". The caller must not treat it as
/// evidence that an app went away: `uid_for_package` answers `Ok(None)` for both
/// cases, so acting on that alone would un-hide every hidden app the first time a
/// read failed. An empty parse counts as unreadable for the same reason; a real
/// device always has packages.
pub fn installed_packages() -> Option<Vec<(String, u32)>> {
    installed_from(&fs::read_to_string(PACKAGES_LIST).ok()?)
}

/// Pure half of [`installed_packages`]: `None` when the body yields no packages,
/// which on a real device means the read was bad rather than the device empty.
fn installed_from(list: &str) -> Option<Vec<(String, u32)>> {
    let parsed = parse_installed(list);
    if parsed.is_empty() { None } else { Some(parsed) }
}

/// Pure: `packages.list` body -> (package, appid).
fn parse_installed(list: &str) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    for line in list.lines() {
        let mut cols = line.split(' ');
        let (Some(pkg), Some(uid)) = (cols.next(), cols.next()) else { continue };
        if pkg.is_empty() {
            continue;
        }
        if let Ok(u) = uid.parse::<u32>() {
            out.push((pkg.to_string(), appid(u)));
        }
    }
    out
}

/// Resolve an exact entry against an already-loaded package map. Same answer as
/// [`resolve`], without re-reading `packages.list` — which the apply pass did once
/// per entry, so a ~50-entry preset re-read the whole file ~50 times at boot.
pub fn resolve_in(target: &str, installed: &[(String, u32)]) -> Result<Resolved> {
    let t = target.trim();
    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
        let uid: u32 = t.parse().context("UID out of range")?;
        return Ok(Resolved::Uid(appid(uid)));
    }
    match installed.iter().find(|(pkg, _)| pkg == t) {
        Some((_, uid)) => Ok(Resolved::Uid(*uid)),
        None => Ok(Resolved::NotInstalled),
    }
}

/// Expand one hide-list entry into the concrete `(package, appid)` pairs it covers.
/// An exact entry yields at most one; a glob yields every installed match. `installed`
/// is passed in so a whole pass shares a single `packages.list` read.
pub fn expand(entry: &str, installed: &[(String, u32)]) -> Result<Vec<(String, u32)>> {
    let e = entry.trim();
    if let Some(pat) = Pattern::parse(e) {
        let pat = pat?;
        return Ok(installed
            .iter()
            .filter(|(pkg, _)| pat.matches(pkg))
            .cloned()
            .collect());
    }
    match resolve(e)? {
        Resolved::Uid(uid) => Ok(vec![(e.to_string(), uid)]),
        Resolved::NotInstalled => Ok(Vec::new()),
    }
}

/// True if the entry is a glob (well-formed or not) rather than a package/UID.
pub fn is_pattern(entry: &str) -> bool {
    entry.contains('*')
}

pub fn resolve(target: &str) -> Result<Resolved> {
    let t = target.trim();
    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
        let uid: u32 = t.parse().context("UID out of range")?;
        return Ok(Resolved::Uid(appid(uid)));
    }
    match uid_for_package(t)? {
        Some(uid) => Ok(Resolved::Uid(appid(uid))),
        None => Ok(Resolved::NotInstalled),
    }
}

/// Resolve preferring the cache, for the early-boot pass. `packages.list` is
/// readable at post-fs-data, but the cache is both cheaper and correct even if it
/// is not yet in its final state; `apply` reconciles against the live map later.
pub fn resolve_early(target: &str, cache: &BTreeMap<String, u32>) -> Result<Resolved> {
    if let Some(uid) = cache.get(target.trim()) {
        return Ok(Resolved::Uid(*uid));
    }
    resolve(target)
}

/// Reverse of `uid_for_package`: the first package owning `uid`, for labelling a
/// UID the kernel is hiding that isn't in the hide-list file. `None` = no match
/// (system/shared UID, or `packages.list` unreadable).
pub fn package_for_uid(uid: u32) -> Option<String> {
    parse_package_for_uid(&fs::read_to_string(PACKAGES_LIST).ok()?, uid)
}

/// Pure: first package owning `uid` in a `packages.list` body (col0=pkg, col1=uid).
fn parse_package_for_uid(list: &str, uid: u32) -> Option<String> {
    for line in list.lines() {
        let mut cols = line.split(' ');
        let pkg = cols.next()?;
        if cols.next().and_then(|c| c.parse::<u32>().ok()).map(appid) == Some(appid(uid)) {
            return Some(pkg.to_string());
        }
    }
    None
}

/// Look up a package's UID in `packages.list`. `Ok(None)` = not present.
fn uid_for_package(pkg: &str) -> Result<Option<u32>> {
    let list = match fs::read_to_string(PACKAGES_LIST) {
        Ok(s) => s,
        // Missing/unreadable (e.g. not root, or very early boot) is not fatal to
        // a *resolution* — the caller decides whether that's an error.
        Err(_) => return Ok(None),
    };
    Ok(parse_uid_for_package(&list, pkg))
}

/// Pure: the UID for `pkg` in a `packages.list` body.
fn parse_uid_for_package(list: &str, pkg: &str) -> Option<u32> {
    for line in list.lines() {
        let mut cols = line.split(' ');
        if cols.next() == Some(pkg) {
            if let Some(uid) = cols.next().and_then(|c| c.parse::<u32>().ok()) {
                return Some(uid);
            }
        }
    }
    None
}

/// One-time split of the shared `blocklist` file, run while the new file is
/// absent. An entry that names a directory under `/data/adb/modules` is a module
/// id for the mount pass to skip; everything else is a hide-list entry and is
/// COPIED here.
///
/// Copied, not moved: this runs unattended at post-fs-data, and the two mistakes
/// are not the same size. A leftover package name in `blocklist` is inert — that
/// file is only ever consulted as "is this the id of a module I am about to
/// inject?", so a name no module has changes nothing. Removing an entry that IS a
/// module id, on the other hand, means the next mount pass injects a module that
/// was deliberately excluded, which is how a self-mounting module or a shipped su
/// binary breaks the boot. So if `is_dir()` were ever wrong (an unreadable modules
/// dir, say), the failure lands on the harmless side.
///
/// The dangerous half of the old shared file is fixed regardless: the hidden-apps
/// list, and its delete button, now read and write `uidhide` only.
fn migrate_legacy() {
    if Path::new(BLOCKLIST_PATH).exists() {
        return;
    }
    let Ok(raw) = fs::read_to_string(LEGACY_PATH) else { return };
    let entries = parse_blocklist(&raw);
    if entries.is_empty() {
        return;
    }
    let apps: Vec<String> = entries
        .into_iter()
        .filter(|e| !Path::new(MODULES_DIR).join(e).is_dir())
        .collect();
    // Written even when empty: the file's existence is what marks the migration
    // done, so an all-module-ids legacy file is not re-scanned on every read.
    let _ = write_lines(BLOCKLIST_PATH, &apps);
}

/// Read the persistent hide list: trimmed, comment- and blank-stripped, order
/// preserved, deduplicated. Absent file = empty list (not an error).
pub fn read() -> Result<Vec<String>> {
    migrate_legacy();
    let raw = match fs::read_to_string(BLOCKLIST_PATH) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context("read hide list"),
    };
    Ok(parse_blocklist(&raw))
}

/// Pure: trimmed, comment/blank-stripped, order-preserved, deduplicated.
fn parse_blocklist(raw: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in raw.lines() {
        let e = line.trim();
        if e.is_empty() || e.starts_with('#') {
            continue;
        }
        if !out.iter().any(|x| x == e) {
            out.push(e.to_string());
        }
    }
    out
}

fn write_lines(path: &str, entries: &[String]) -> Result<()> {
    if let Some(dir) = Path::new(path).parent() {
        fs::create_dir_all(dir).ok();
    }
    let mut body = String::new();
    for e in entries {
        body.push_str(e);
        body.push('\n');
    }
    fs::write(path, body).with_context(|| format!("write {path}"))
}

/// Persist the list (LF-terminated, one entry per line).
fn write(entries: &[String]) -> Result<()> {
    write_lines(BLOCKLIST_PATH, entries)
}

/// Add many entries in one read-modify-write. Returns how many were new. A preset
/// is ~50 entries, and `add` per entry rewrote the whole file each time.
pub fn add_many(entries: &[String]) -> Result<usize> {
    let mut list = read()?;
    let mut added = 0;
    for e in entries {
        let e = e.trim();
        if e.is_empty() || list.iter().any(|x| x == e) {
            continue;
        }
        list.push(e.to_string());
        added += 1;
    }
    if added > 0 {
        write(&list)?;
    }
    Ok(added)
}

/// Replace the whole resolved-appid mirror in one write.
pub fn cache_replace(map: &BTreeMap<String, u32>) {
    cache_write(map);
}

/// Add an entry (no-op if already present). Returns true if it was newly added.
pub fn add(entry: &str) -> Result<bool> {
    let e = entry.trim().to_string();
    let mut list = read()?;
    if list.contains(&e) {
        return Ok(false);
    }
    list.push(e);
    write(&list)?;
    Ok(true)
}

/// Remove an entry (no-op if absent). Returns true if something was removed.
pub fn remove(entry: &str) -> Result<bool> {
    let e = entry.trim();
    let mut list = read()?;
    let before = list.len();
    list.retain(|x| x != e);
    if list.len() == before {
        return Ok(false);
    }
    write(&list)?;
    cache_forget(e);
    Ok(true)
}

// ---- resolved-appid cache -------------------------------------------------

/// Read the `entry<TAB>appid` mirror. Absent/garbled = empty (never an error:
/// the cache is an optimisation, `packages.list` is the truth).
pub fn cache_read() -> BTreeMap<String, u32> {
    let mut map = BTreeMap::new();
    let Ok(raw) = fs::read_to_string(CACHE_PATH) else { return map };
    for line in raw.lines() {
        if let Some((k, v)) = line.split_once('\t') {
            if let Ok(uid) = v.trim().parse::<u32>() {
                map.insert(k.trim().to_string(), appid(uid));
            }
        }
    }
    map
}

fn cache_write(map: &BTreeMap<String, u32>) {
    if let Some(dir) = Path::new(CACHE_PATH).parent() {
        fs::create_dir_all(dir).ok();
    }
    let mut body = String::new();
    for (k, v) in map {
        body.push_str(k);
        body.push('\t');
        body.push_str(&v.to_string());
        body.push('\n');
    }
    let _ = fs::write(CACHE_PATH, body);
}

/// Record `entry -> appid` for the next early-boot pass.
pub fn cache_put(entry: &str, uid: u32) {
    let mut map = cache_read();
    if map.insert(entry.trim().to_string(), appid(uid)) != Some(appid(uid)) {
        cache_write(&map);
    }
}

/// Drop an entry from the mirror (unhidden, or its package went away).
pub fn cache_forget(entry: &str) {
    let mut map = cache_read();
    if map.remove(entry.trim()).is_some() {
        cache_write(&map);
    }
}

// ---- feature settings -----------------------------------------------------

/// Which isolated-process pools the kernel hides from: 1 = app-zygote pool,
/// 2 = platform isolated pool, 3 = both (the default), 0 = neither.
pub const DEFAULT_HIDE_ISOLATED: u32 = 3;

/// Read the persisted isolated-pool policy (default when unset/garbled).
pub fn hide_isolated() -> u32 {
    let Ok(raw) = fs::read_to_string(CONF_PATH) else { return DEFAULT_HIDE_ISOLATED };
    for line in raw.lines() {
        if let Some(v) = line.trim().strip_prefix("hide_isolated=") {
            if let Ok(n) = v.trim().parse::<u32>() {
                if n <= 3 {
                    return n;
                }
            }
        }
    }
    DEFAULT_HIDE_ISOLATED
}

/// Persist the isolated-pool policy so `apply` can re-assert it after a reboot
/// or a `nm clear` (the kernel knob is runtime state like the block set itself).
pub fn set_hide_isolated(mode: u32) -> Result<()> {
    if let Some(dir) = Path::new(CONF_PATH).parent() {
        fs::create_dir_all(dir).ok();
    }
    fs::write(
        CONF_PATH,
        format!("# NoMount per-UID hiding settings\nhide_isolated={mode}\n"),
    )
    .context("write uidhide.conf")
}

#[cfg(test)]
mod tests {
    use super::*;

    // Two representative packages.list lines (col0=pkg, col1=uid, rest ignored).
    const LIST: &str = "com.foo 10123 0 /data/user/0/com.foo default none 0 34 1 @null\n\
me.garfieldhan.holmes 10471 0 /data/user/0/me.garfieldhan.holmes default 3003 0 35 1 @null\n";

    #[test]
    fn uid_for_known_and_unknown_package() {
        assert_eq!(parse_uid_for_package(LIST, "com.foo"), Some(10123));
        assert_eq!(parse_uid_for_package(LIST, "me.garfieldhan.holmes"), Some(10471));
        assert_eq!(parse_uid_for_package(LIST, "com.absent"), None);
    }

    #[test]
    fn package_for_known_and_unknown_uid() {
        assert_eq!(parse_package_for_uid(LIST, 10471).as_deref(), Some("me.garfieldhan.holmes"));
        assert_eq!(parse_package_for_uid(LIST, 10123).as_deref(), Some("com.foo"));
        assert_eq!(parse_package_for_uid(LIST, 99999), None);
    }

    #[test]
    fn package_for_uid_matches_a_clone_of_the_same_app() {
        // uid 1010471 is holmes in user 10 — same appid, same entry.
        assert_eq!(parse_package_for_uid(LIST, 1_010_471).as_deref(), Some("me.garfieldhan.holmes"));
    }

    #[test]
    fn resolve_numeric_target_is_uid_without_io() {
        match resolve(" 10123 ").unwrap() {
            Resolved::Uid(u) => assert_eq!(u, 10123),
            _ => panic!("numeric target should resolve to a UID"),
        }
    }

    #[test]
    fn resolve_normalises_a_clone_uid_to_its_appid() {
        // What the kernel stores for uid 1010471 is appid 10471; the CLI must agree
        // or `uid unblock 1010471` reports success while the app stays hidden.
        match resolve("1010471").unwrap() {
            Resolved::Uid(u) => assert_eq!(u, 10471),
            _ => panic!("numeric target should resolve to a UID"),
        }
    }

    #[test]
    fn appid_normalisation() {
        assert_eq!(appid(10471), 10471);
        assert_eq!(appid(1_010_471), 10471);
        assert_eq!(appid(99_020), 99_020);
        assert_eq!(appid(2000), 2000);
    }

    #[test]
    fn blocklist_trims_dedups_and_skips_comments_blanks() {
        let raw = "# a comment\n\ncom.foo\n  com.bar  \ncom.foo\n\n# trailing\n";
        assert_eq!(parse_blocklist(raw), vec!["com.foo".to_string(), "com.bar".to_string()]);
    }

    #[test]
    fn empty_or_comment_only_blocklist_is_empty() {
        assert!(parse_blocklist("").is_empty());
        assert!(parse_blocklist("# only\n\n   \n").is_empty());
    }

    // ---- globs ------------------------------------------------------------

    fn pat(s: &str) -> Pattern {
        Pattern::parse(s).expect("is a glob").expect("is well formed")
    }

    #[test]
    fn plain_names_and_uids_are_not_globs() {
        assert!(Pattern::parse("com.example.app").is_none());
        assert!(Pattern::parse("10487").is_none());
        assert!(!is_pattern("com.example.app"));
        assert!(is_pattern("*.duckdetector"));
    }

    #[test]
    fn each_anchor_form_matches_only_where_it_should() {
        assert!(matches!(pat("me.garfieldhan.*"), Pattern::Prefix(_)));
        assert!(matches!(pat("*.duckdetector"), Pattern::Suffix(_)));
        assert!(matches!(pat("*chunqiu*"), Pattern::Contains(_)));

        assert!(pat("me.garfieldhan.*").matches("me.garfieldhan.holmes"));
        assert!(!pat("me.garfieldhan.*").matches("com.me.garfieldhan.x"));

        assert!(pat("*.duckdetector").matches("com.whatever.duckdetector"));
        assert!(!pat("*.duckdetector").matches("com.duckdetector.app"));

        assert!(pat("*chunqiu*").matches("io.chunqiu.detector"));
        assert!(!pat("*chunqiu*").matches("com.google.android.gms"));
    }

    /// The guard that stops a typo hiding injections from the whole device.
    #[test]
    fn globs_that_are_too_broad_are_refused() {
        for bad in ["*", "**", "*a*", "*ab*", "*abc*", "a*"] {
            let parsed = Pattern::parse(bad).expect("is a glob");
            assert!(parsed.is_err(), "{bad} should have been refused");
        }
        assert!(Pattern::parse("*abcd*").expect("is a glob").is_ok());
    }

    #[test]
    fn a_star_in_the_middle_is_refused_rather_than_half_honoured() {
        let parsed = Pattern::parse("com.*.detector").expect("is a glob");
        assert!(parsed.is_err());
    }

    #[test]
    fn expand_returns_every_installed_match_for_a_glob() {
        let installed = vec![
            ("me.garfieldhan.holmes".to_string(), 10001u32),
            ("com.acme.duckdetector".to_string(), 10002),
            ("com.google.android.gms".to_string(), 10003),
        ];
        let hits = expand("*.duckdetector", &installed).unwrap();
        assert_eq!(hits, vec![("com.acme.duckdetector".to_string(), 10002)]);

        let hits = expand("me.garfieldhan.*", &installed).unwrap();
        assert_eq!(hits.len(), 1);

        // A glob matching nothing installed is empty, not an error.
        assert!(expand("*.nosuchthing", &installed).unwrap().is_empty());
        // A malformed glob is an error, so a pass reports it instead of hiding all.
        assert!(expand("*", &installed).is_err());
    }

    /// The gate that stops a bad read being read as "every app was uninstalled".
    /// Acting on that would un-hide everything and wipe the mirror in one pass.
    #[test]
    fn resolve_in_agrees_with_resolve_without_touching_the_disk() {
        let installed = vec![("com.a".to_string(), 10123u32), ("com.b".to_string(), 10456)];
        assert!(matches!(resolve_in("com.a", &installed).unwrap(), Resolved::Uid(10123)));
        // A bare UID never needs the map, and is normalised to its appid.
        assert!(matches!(resolve_in("1010456", &installed).unwrap(), Resolved::Uid(10456)));
        assert!(matches!(resolve_in("com.gone", &installed).unwrap(), Resolved::NotInstalled));
        assert!(resolve_in("99999999999", &installed).is_err());
    }

    #[test]
    fn an_unusable_package_map_is_none_not_an_empty_device() {
        assert!(installed_from("").is_none());
        assert!(installed_from("\n\n").is_none());
        assert!(installed_from("garbage-with-no-columns").is_none());
        assert!(installed_from("com.a 10123 0 /data/user/0/com.a default none 0\n").is_some());
    }

    #[test]
    fn parse_installed_reads_packages_list_columns_and_normalises_appid() {
        let body = "com.a 10123 0 /data/user/0/com.a default:targetSdk=34 none 0\n\
                    com.b 1010456 1 /data/user/0/com.b default 3003 0\n\
                    garbage\n";
        let got = parse_installed(body);
        assert_eq!(got, vec![("com.a".to_string(), 10123), ("com.b".to_string(), 10456)]);
    }
}
