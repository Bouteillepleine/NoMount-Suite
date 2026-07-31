//! Persistent, package-name-aware UID block list.
//!
//! The kernel's per-UID hiding (`nm block <uid>`) is **runtime-only**: the idr
//! that backs it lives in kernel memory and is empty after every reboot. It also
//! speaks raw UIDs, which nobody remembers — `10487` tells you nothing, whereas
//! `me.garfieldhan.holmes` does.
//!
//! This module closes both gaps without touching the kernel:
//!   * a plain-text file (`/data/adb/nomount/blocklist`) is the source of truth,
//!     one entry per line — a package name (preferred, durable) or a bare UID;
//!   * package names are resolved to their live UID via the canonical
//!     `/data/system/packages.list` (root-readable, no `pm` fork);
//!   * `apply` re-blocks every resolved UID and is invoked from `service.sh` once
//!     `packages.list` is populated, so a hidden detector stays hidden across boots.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

/// Source of truth for the persistent block list. Lives beside the guard state
/// under `/data/adb/nomount`, which the module creates in `customize.sh`.
pub const BLOCKLIST_PATH: &str = "/data/adb/nomount/blocklist";

/// Android's canonical package→UID map. Column 0 is the package name, column 1
/// the app UID. Root-readable; avoids forking `pm` (slow, and unavailable early
/// in boot when `service.sh` runs).
const PACKAGES_LIST: &str = "/data/system/packages.list";

/// What an entry resolved to, for display in `uid list`.
pub enum Resolved {
    /// Package (or bare UID) resolved to this live app UID.
    Uid(u32),
    /// A package name that isn't in `packages.list` right now (not installed, or
    /// disabled for the current user). Kept in the list so it re-arms if the app
    /// returns; simply skipped by `apply`.
    NotInstalled,
}

/// Resolve a block-list target to a UID.
///
/// A purely numeric target is taken verbatim (already a UID). Anything else is a
/// package name, looked up in `packages.list`.
pub fn resolve(target: &str) -> Result<Resolved> {
    let t = target.trim();
    if !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(Resolved::Uid(t.parse().context("UID out of range")?));
    }
    match uid_for_package(t)? {
        Some(uid) => Ok(Resolved::Uid(uid)),
        None => Ok(Resolved::NotInstalled),
    }
}

/// Reverse of `uid_for_package`: the first package owning `uid`, for labelling a
/// UID the kernel is hiding that isn't in the block-list file. `None` = no match
/// (system/shared UID, or `packages.list` unreadable).
pub fn package_for_uid(uid: u32) -> Option<String> {
    parse_package_for_uid(&fs::read_to_string(PACKAGES_LIST).ok()?, uid)
}

/// Pure: first package owning `uid` in a `packages.list` body (col0=pkg, col1=uid).
fn parse_package_for_uid(list: &str, uid: u32) -> Option<String> {
    for line in list.lines() {
        let mut cols = line.split(' ');
        let pkg = cols.next()?;
        if cols.next().and_then(|c| c.parse::<u32>().ok()) == Some(uid) {
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

/// Read the persistent block list: trimmed, comment- and blank-stripped, order
/// preserved, deduplicated. Absent file = empty list (not an error).
pub fn read() -> Result<Vec<String>> {
    let raw = match fs::read_to_string(BLOCKLIST_PATH) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context("read blocklist"),
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

/// Persist the list (LF-terminated, one entry per line).
fn write(entries: &[String]) -> Result<()> {
    if let Some(dir) = Path::new(BLOCKLIST_PATH).parent() {
        fs::create_dir_all(dir).ok();
    }
    let mut body = String::new();
    for e in entries {
        body.push_str(e);
        body.push('\n');
    }
    fs::write(BLOCKLIST_PATH, body).context("write blocklist")
}

/// Add an entry (no-op if already present). Returns true if it was newly added.
pub fn add(entry: &str) -> Result<bool> {
    let e = entry.trim().to_string();
    let mut list = read()?;
    if list.iter().any(|x| *x == e) {
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
    Ok(true)
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
    fn resolve_numeric_target_is_uid_without_io() {
        match resolve(" 10123 ").unwrap() {
            Resolved::Uid(u) => assert_eq!(u, 10123),
            _ => panic!("numeric target should resolve to a UID"),
        }
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
