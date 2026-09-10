
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

pub const BLOCKLIST_PATH: &str = "/data/adb/nomount/uidhide";

const LEGACY_PATH: &str = "/data/adb/nomount/blocklist";

const CACHE_PATH: &str = "/data/adb/nomount/uidhide.cache";

const CONF_PATH: &str = "/data/adb/nomount/uidhide.conf";

const PACKAGES_LIST: &str = "/data/system/packages.list";

const MODULES_DIR: &str = "/data/adb/modules";

pub const PER_USER_RANGE: u32 = 100_000;

pub const FIRST_APP_APPID: u32 = 10_000;

pub fn appid(uid: u32) -> u32 {
    uid % PER_USER_RANGE
}

pub fn redact_hide_list() -> bool {
    std::env::var_os("NM_REDACT_HIDE_LIST").is_some()
}

pub enum Resolved {
    Uid(u32),
    NotInstalled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    Prefix(String),
    Suffix(String),
    Contains(String),
}

pub const MIN_PATTERN_LITERAL: usize = 4;

impl Pattern {
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

pub fn installed_packages() -> Option<Vec<(String, u32)>> {
    installed_from(&fs::read_to_string(PACKAGES_LIST).ok()?)
}

fn installed_from(list: &str) -> Option<Vec<(String, u32)>> {
    let parsed = parse_installed(list);
    if parsed.is_empty() { None } else { Some(parsed) }
}

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
    match resolve_in(e, installed)? {
        Resolved::Uid(uid) => Ok(vec![(e.to_string(), uid)]),
        Resolved::NotInstalled => Ok(Vec::new()),
    }
}

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

pub fn resolve_early(target: &str, cache: &BTreeMap<String, u32>) -> Result<Resolved> {
    if let Some(uid) = cache.get(target.trim()) {
        return Ok(Resolved::Uid(*uid));
    }
    resolve(target)
}

pub fn package_for_uid(uid: u32) -> Option<String> {
    parse_package_for_uid(&fs::read_to_string(PACKAGES_LIST).ok()?, uid)
}

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

fn uid_for_package(pkg: &str) -> Result<Option<u32>> {
    let list = match fs::read_to_string(PACKAGES_LIST) {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };
    Ok(parse_uid_for_package(&list, pkg))
}

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
    let _ = write_lines(BLOCKLIST_PATH, &apps);
}

pub fn read() -> Result<Vec<String>> {
    migrate_legacy();
    let raw = match fs::read_to_string(BLOCKLIST_PATH) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).context("read hide list"),
    };
    Ok(parse_blocklist(&raw))
}

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
    let mut body = String::new();
    for e in entries {
        body.push_str(e);
        body.push('\n');
    }
    crate::statefile::write_atomic(path, body).with_context(|| format!("write {path}"))
}

fn write(entries: &[String]) -> Result<()> {
    write_lines(BLOCKLIST_PATH, entries)
}

fn check_entry(e: &str) -> Result<()> {
    if e.is_empty() || e.starts_with('#') || e.contains(['\n', '\r', '\t']) {
        anyhow::bail!(
            "{e:?} cannot be a hide-list entry (blank, a comment, or carrying a newline or tab) \
 - it would be dropped again on the next read"
        );
    }
    Ok(())
}

pub fn add_many(entries: &[String]) -> Result<usize> {
    let _pass = crate::mount::pass_lock();
    let mut list = read()?;
    let mut added = 0;
    for e in entries {
        let e = e.trim();
        check_entry(e)?;
        if list.iter().any(|x| x == e) {
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

pub fn cache_replace(map: &BTreeMap<String, u32>) {
    cache_write(map);
}

pub fn add(entry: &str) -> Result<bool> {
    let _pass = crate::mount::pass_lock();
    let e = entry.trim().to_string();
    check_entry(&e)?;
    let mut list = read()?;
    if list.contains(&e) {
        return Ok(false);
    }
    list.push(e);
    write(&list)?;
    Ok(true)
}

pub fn remove(entry: &str) -> Result<bool> {
    let _pass = crate::mount::pass_lock();
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
    let mut body = String::new();
    for (k, v) in map {
        body.push_str(k);
        body.push('\t');
        body.push_str(&v.to_string());
        body.push('\n');
    }
    let _ = crate::statefile::write_atomic(CACHE_PATH, body);
}

pub fn cache_put(entry: &str, uid: u32) {
    let mut map = cache_read();
    if map.insert(entry.trim().to_string(), appid(uid)) != Some(appid(uid)) {
        cache_write(&map);
    }
}

pub fn cache_forget(entry: &str) {
    let mut map = cache_read();
    if map.remove(entry.trim()).is_some() {
        cache_write(&map);
    }
}

pub const DEFAULT_HIDE_ISOLATED: u32 = 3;

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

pub fn set_hide_isolated(mode: u32) -> Result<()> {
    crate::statefile::write_atomic(
        CONF_PATH,
        format!("# NoMount per-UID hiding settings\nhide_isolated={mode}\n"),
    )
    .context("write uidhide.conf")
}

#[cfg(test)]
mod tests {
    use super::*;

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

        assert!(expand("*.nosuchthing", &installed).unwrap().is_empty());
        assert!(expand("*", &installed).is_err());
    }

    #[test]
    fn resolve_in_agrees_with_resolve_without_touching_the_disk() {
        let installed = vec![("com.a".to_string(), 10123u32), ("com.b".to_string(), 10456)];
        assert!(matches!(resolve_in("com.a", &installed).unwrap(), Resolved::Uid(10123)));
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
