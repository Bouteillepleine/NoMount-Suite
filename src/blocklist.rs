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
}
