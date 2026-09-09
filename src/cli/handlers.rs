use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context, Result};

use super::{UidAction, VfsAction};
use crate::blocklist::{self, appid, Resolved};
use crate::nm::Nm;

/// What `uid unblock` actually did, in words
fn unblock_message(target: &str, uid: Option<u32>, existed: bool, unhid: bool) -> String {
    match (uid, existed, unhid) {
        (Some(uid), true, true) => format!("ok: {target} (uid {uid}) unhidden"),
        (Some(_), true, false) => {
            format!("ok: {target} removed from the hide list - it was not being hidden")
        }
        (Some(uid), false, true) => format!(
            "ok: {target} (uid {uid}) unhidden - it was not in the hide list, so nothing was saved"
        ),
        (Some(_), false, false) => {
            format!("ok: {target} was not hidden, and was not in the hide list")
        }
        (None, true, true) => format!(
            "ok: {target} removed from the hide list, and its last known uid unhidden - it is \
             not installed now"
        ),
        (None, true, false) => format!("ok: {target} removed from the hide list (not installed)"),
        (None, false, true) => {
            format!("ok: {target} unhidden - not installed, and it was not in the hide list")
        }
        (None, false, false) => {
            format!("ok: {target} is not installed, and was not in the hide list")
        }
    }
}

/// Serialise a verb's kernel mutation against the mount pass
fn pass_guard() -> Option<crate::mount::PassLock> {
    crate::mount::pass_lock()
}

pub fn handle_vfs(action: VfsAction) -> Result<()> {
    let nm = Nm::new();
    match action {
        VfsAction::Add { virtual_path, real_path } => {
            let virt = Path::new(&virtual_path);
            let real = Path::new(&real_path);
            if crate::mount::is_partition_root(virt) {
                anyhow::bail!(
                    "refusing {}: a rule on a bare partition root masks every stock entry \
                     under it, which aborts forkSystemServer. Name a file inside it.",
                    virt.display()
                );
            }
            for (side, p) in [("target", virt), ("source", real)] {
                if let Err(why) = crate::mount::path_is_representable(p) {
                    anyhow::bail!("refusing {} {}: {why}", side, p.display());
                }
            }
            if real.is_dir() {
                anyhow::bail!(
                    concat!(
                        "{} is a directory.
",
                        "A directory rule hides every stock entry under its target, and its
",
                        "children report the source filesystem's block counts, which a single
",
                        "stat separates from stock. Add the files individually instead."
                    ),
                    real.display()
                );
            }
            nm.add(Path::new(&virtual_path), real)?;
            println!("ok");
        }
        VfsAction::Del { virtual_path } => {
            nm.del(Path::new(&virtual_path))?;
            println!("ok");
        }
        VfsAction::Whiteout { path } => {
            crate::whiteout::validate(&path)?;
            let p = Path::new(&path);
            if let Err(why) = crate::mount::path_is_representable(p) {
                anyhow::bail!("refusing {}: {why}", p.display());
            }
            nm.whiteout(p)?;
            println!("ok");
        }
        VfsAction::Clear => {
            let _pass = pass_guard();
            nm.clear()?;
            let re = reapply_blocklist(&nm, false);
            if re.hidden > 0 || re.failed > 0 {
                println!("ok (re-hid {} app(s){})", re.hidden, re.fail_note());
            } else {
                println!("ok");
            }
            if re.failed > 0 {
                bail!(
                    "{} hide-list entr(ies) could not be re-applied after the clear - those apps are not hidden",
                    re.failed
                );
            }
        }
        VfsAction::List => {
            let list = nm.list()?;
            if !list.trim().is_empty() {
                print!("{list}");
            }
        }
    }
    Ok(())
}

/// Outcome of one re-apply pass
pub struct ApplyReport {
    pub hidden: u32,
    pub skipped: u32,
    pub failed: u32,
    pub retired: u32,
    /// Entries that named an app this device does not have installed
    pub not_installed: u32,
}

impl ApplyReport {
    pub fn fail_note(&self) -> String {
        if self.failed > 0 { format!(", {} failed", self.failed) } else { String::new() }
    }
}

/// Re-assert the persistent hide list (and the isolated-pool policy) against the kernel
pub fn reapply_blocklist(nm: &Nm, early: bool) -> ApplyReport {
    let mut rep = ApplyReport { hidden: 0, skipped: 0, failed: 0, retired: 0, not_installed: 0 };

    let mode = blocklist::hide_isolated();
    if nm.set_hide_isolated(mode).is_err() && mode != blocklist::DEFAULT_HIDE_ISOLATED {
        rep.failed += 1;
    }

    let cache = blocklist::cache_read();
    let entries = match blocklist::read() {
        Ok(e) => e,
        Err(_) => {
            rep.failed += 1;
            return rep;
        }
    };
    if entries.is_empty() && cache.is_empty() {
        return rep;
    }
    let mut live = nm.uid_list_live().unwrap_or_default();

    let installed = if early { None } else { blocklist::installed_packages() };
    let can_retire = !early && installed.is_some();
    let installed = installed.unwrap_or_default();
    if !early && !can_retire {
        rep.failed += 1;
    }
    let mut desired: BTreeMap<String, u32> = BTreeMap::new();

    for e in &entries {
        if blocklist::is_pattern(e) {
            if early {
                continue;
            }
            match blocklist::expand(e, &installed) {
                Ok(hits) => {
                    if hits.is_empty() {
                        rep.skipped += 1;
                    }
                    for (pkg, uid) in hits {
                        if uid < blocklist::FIRST_APP_APPID {
                            eprintln!(
                                "nomount: {e} matches {pkg} (appid {uid}, below the app range) - \
                                 not hiding from it; add it explicitly with `uid block --force`"
                            );
                            rep.skipped += 1;
                            continue;
                        }
                        desired.insert(pkg, uid);
                    }
                }
                Err(err) => {
                    eprintln!("nomount: skipping hide-list glob {e:?}: {err:#}");
                    rep.skipped += 1;
                }
            }
            continue;
        }

        let resolved = if early {
            blocklist::resolve_early(e, &cache)
        } else {
            blocklist::resolve_in(e, &installed)
        };
        match resolved {
            Ok(Resolved::Uid(uid)) => {
                desired.insert(e.clone(), uid);
            }
            Ok(Resolved::NotInstalled) => rep.not_installed += 1,
            Err(err) => {
                eprintln!("nomount: skipping hide-list entry {e:?}: {err:#}");
                rep.skipped += 1;
            }
        }
    }

    if early {
        for (pkg, uid) in &cache {
            desired.entry(pkg.clone()).or_insert(*uid);
        }
    }

    for (key, uid) in &desired {
        let uid = *uid;
        if can_retire {
            if let Some(old) = cache.get(key) {
                if *old != uid && !desired.values().any(|v| *v == *old) {
                    if nm.uid_unblock(*old).is_ok() {
                        live.retain(|u| appid(*u) != *old);
                        rep.retired += 1;
                    } else {
                        rep.failed += 1;
                    }
                }
            }
        }
        if live.iter().any(|u| appid(*u) == uid) {
            rep.hidden += 1;
        } else if nm.uid_block(uid).is_ok() {
            live.push(uid);
            rep.hidden += 1;
        } else if nm
            .uid_list_live()
            .map(|v| v.iter().any(|u| appid(*u) == uid))
            .unwrap_or(false)
        {
            rep.hidden += 1;
        } else {
            rep.failed += 1;
        }
    }

    if can_retire {
        for (key, old) in &cache {
            if desired.contains_key(key) {
                continue;
            }
            if desired.values().any(|v| *v == *old) {
                continue;
            }
            if nm.uid_unblock(*old).is_ok() {
                live.retain(|u| appid(*u) != *old);
                rep.retired += 1;
            } else {
                rep.failed += 1;
            }
        }
        blocklist::cache_replace(&desired);
    }

    rep
}

/// `both | appzygote | platform | off` <-> the kernel's pool bitmask
fn parse_isolated_mode(s: &str) -> Option<u32> {
    match s.trim().to_ascii_lowercase().as_str() {
        "both" | "all" | "3" => Some(3),
        "appzygote" | "app_zygote" | "1" => Some(1),
        "platform" | "isolated" | "2" => Some(2),
        "off" | "none" | "0" => Some(0),
        _ => None,
    }
}

/// Which `uid list` row speaks for each appid: the first exact row if there is one, else
fn list_winners(rows: &[(Option<u32>, bool)]) -> BTreeMap<u32, usize> {
    let mut winner: BTreeMap<u32, usize> = BTreeMap::new();
    for (i, (appid, glob)) in rows.iter().enumerate() {
        let Some(a) = *appid else { continue };
        match winner.get(&a) {
            None => {
                winner.insert(a, i);
            }
            Some(&w) if rows[w].1 && !*glob => {
                winner.insert(a, i);
            }
            _ => {}
        }
    }
    winner
}

fn isolated_mode_name(mode: u32) -> &'static str {
    match mode {
        0 => "off - neither pool is hidden from",
        1 => "appzygote - app-zygote pool (90000-98999) only",
        2 => "platform - platform isolated pool (99000-99999) only",
        _ => "both - every isolated process (default)",
    }
}

pub fn handle_uid(action: UidAction) -> Result<()> {
    let nm = Nm::new();
    match action {
        UidAction::Block { target, force } => {
            let t = target.trim();
            if t.is_empty() {
                bail!("nothing to hide: give a package name, a uid, or a glob");
            }
            if target.contains(['\n', '\r', '\t']) || t.starts_with('#') {
                bail!(
                    "{target:?} cannot be stored: a newline, a tab and a leading '#' are the \
                     hide list's own syntax, so the entry would not survive being written and \
                     read back"
                );
            }
            if blocklist::is_pattern(&target) {
                if let Some(parsed) = blocklist::Pattern::parse(&target) {
                    parsed?;
                }
                let installed = blocklist::installed_packages().unwrap_or_default();
                let hits = blocklist::expand(&target, &installed)?;
                if let Some((pkg, uid)) = hits.iter().find(|(_, u)| *u < blocklist::FIRST_APP_APPID)
                {
                    bail!(
                        "{target} matches {pkg} (appid {uid}), below the app range - hiding from \
                         it would hide injections from Android itself. Narrow the glob, or hide \
                         that package explicitly with `uid block {pkg} --force`"
                    );
                }
                blocklist::add(&target)?;
                let _pass = pass_guard();
                let rep = reapply_blocklist(&nm, false);
                println!(
                    "ok: {target} saved - matches {} installed package(s), now hiding {}{}",
                    hits.len(),
                    rep.hidden,
                    rep.fail_note()
                );
                if rep.failed > 0 {
                    bail!("{} hide-list entr(ies) could not be applied", rep.failed);
                }
                return Ok(());
            }
            let resolved = blocklist::resolve(&target)?;
            if let Resolved::Uid(uid) = resolved {
                if uid < blocklist::FIRST_APP_APPID && !force {
                    bail!(
                        "{target} is appid {uid}, below the app range - hiding from it hides injections from Android itself (1000 = system_server: RRO and framework patches revert to stock; 2000 = shell: the health canary then reports a permanent inconsistency; 0 = root). Pass --force if that is really what you want."
                    );
                }
            }
            blocklist::add(&target)?;
            let _pass = pass_guard();
            match resolved {
                Resolved::Uid(uid) => {
                    blocklist::cache_put(&target, uid);
                    let already = nm.uid_list_live().unwrap_or_default().iter().any(|u| appid(*u) == appid(uid));
                    if already {
                        println!("ok: {target} (uid {uid}) already hidden - saved so it persists");
                    } else {
                        nm.uid_block(uid)?;
                        println!("ok: {target} (uid {uid}) hidden - persists across reboots");
                    }
                }
                Resolved::NotInstalled => {
                    println!("ok: {target} saved - not installed now, will apply when it is");
                }
            }
        }
        UidAction::Unblock { target } => {
            if blocklist::is_pattern(&target) {
                let existed = blocklist::remove(&target)?;
                let _pass = pass_guard();
                let rep = reapply_blocklist(&nm, false);
                if existed {
                    println!(
                        "ok: {target} removed - {} package(s) un-hidden, {} still hidden{}",
                        rep.retired,
                        rep.hidden,
                        rep.fail_note()
                    );
                } else {
                    println!("ok: {target} was not in the hide list");
                }
                if rep.failed > 0 {
                    bail!("{} hide-list entr(ies) could not be re-applied", rep.failed);
                }
                return Ok(());
            }
            let cached = blocklist::cache_read().get(target.trim()).copied();
            let existed = blocklist::remove(&target)?;
            let _pass = pass_guard();
            match blocklist::resolve(&target)? {
                Resolved::Uid(uid) => {
                    let live = nm.uid_list_live().with_context(|| {
                        format!(
                            "{target} was removed from the hide list, but the engine could not \
                             be asked which appids it is hiding - it may still be hidden"
                        )
                    })?;
                    let was_live = live.iter().any(|u| appid(*u) == appid(uid));
                    if was_live {
                        nm.uid_unblock(uid)?;
                    }
                    let mut retired_old = false;
                    if let Some(old) = cached {
                        if old != uid && live.iter().any(|u| appid(*u) == old) {
                            nm.uid_unblock(old).with_context(|| {
                                format!(
                                    "{target}: appid {old} is still hidden and nothing on disk \
                                     names it any more - re-add it with `nomount uid block \
                                     {target}` and retry, or clear the engine with \
                                     `nomount vfs clear`"
                                )
                            })?;
                            retired_old = true;
                        }
                    }
                    let unhid = was_live || retired_old;
                    println!("{}", unblock_message(&target, Some(uid), existed, unhid));
                }
                Resolved::NotInstalled => {
                    let mut unhid = false;
                    if let Some(old) = cached {
                        let live = nm.uid_list_live().with_context(|| {
                            format!(
                                "{target} was removed from the hide list, but the engine could \
                                 not be asked whether appid {old} is still hidden"
                            )
                        })?;
                        if live.iter().any(|u| appid(*u) == old) {
                            nm.uid_unblock(old).with_context(|| {
                                format!(
                                    "{target}: appid {old} is still hidden and nothing on disk \
                                     names it any more - re-add it with `nomount uid block \
                                     {target}` and retry, or clear the engine with \
                                     `nomount vfs clear`"
                                )
                            })?;
                            unhid = true;
                        }
                    }
                    println!("{}", unblock_message(&target, None, existed, unhid));
                }
            }
        }
        UidAction::List => {
            let persisted = blocklist::read()?;
            let live_res = nm.uid_list_live();
            let engine_unknown = live_res.is_err();
            let live = live_res.unwrap_or_default();
            let state_of = |uid: u32| -> &'static str {
                if engine_unknown {
                    "engine unreadable"
                } else if live.iter().any(|u| appid(*u) == appid(uid)) {
                    "live"
                } else {
                    "saved, not applied"
                }
            };
            struct Line {
                appid: Option<u32>,
                glob: bool,
                entry: String,
                name: String,
                text: String,
            }
            let mut lines: Vec<Line> = Vec::new();

            let installed_opt = blocklist::installed_packages();
            let installed = installed_opt.clone().unwrap_or_default();
            for e in &persisted {
                if blocklist::is_pattern(e) {
                    let mut note: Option<String> = None;
                    if installed_opt.is_none() {
                        note = Some(format!("{e}\tglob · package map unreadable"));
                    } else {
                        match blocklist::expand(e, &installed) {
                            Ok(hits) if hits.is_empty() => {
                                note = Some(format!("{e}\tglob · no match"));
                            }
                            Ok(hits) => {
                                for (pkg, uid) in hits {
                                    let text =
                                        format!("{pkg}\tvia {e} · uid {uid} · {}", state_of(uid));
                                    lines.push(Line {
                                        appid: Some(appid(uid)),
                                        glob: true,
                                        entry: e.clone(),
                                        name: pkg,
                                        text,
                                    });
                                }
                            }
                            Err(err) => note = Some(format!("{e}\tinvalid glob: {err:#}")),
                        }
                    }
                    if let Some(text) = note {
                        lines.push(Line {
                            appid: None,
                            glob: true,
                            entry: e.clone(),
                            name: e.clone(),
                            text,
                        });
                    }
                    continue;
                }
                let resolved = match blocklist::resolve(e) {
                    Ok(r) => r,
                    Err(err) => {
                        eprintln!("nomount: skipping blocklist entry {e:?}: {err:#}");
                        continue;
                    }
                };
                let (row_appid, text) = match resolved {
                    Resolved::Uid(uid) => {
                        (Some(appid(uid)), format!("{e}\tuid {uid} · {}", state_of(uid)))
                    }
                    Resolved::NotInstalled => (None, format!("{e}\tnot installed")),
                };
                lines.push(Line {
                    appid: row_appid,
                    glob: false,
                    entry: e.clone(),
                    name: e.clone(),
                    text,
                });
            }
            let winner =
                list_winners(&lines.iter().map(|l| (l.appid, l.glob)).collect::<Vec<_>>());
            for (i, l) in lines.iter().enumerate() {
                let Some(a) = l.appid else {
                    println!("{}", l.text);
                    continue;
                };
                if winner[&a] != i {
                    continue;
                }
                let mut also: Vec<&str> = Vec::new();
                for o in lines.iter().filter(|o| o.appid == Some(a)) {
                    let label = if o.entry != l.entry {
                        o.entry.as_str()
                    } else if o.name != l.name {
                        o.name.as_str()
                    } else {
                        continue;
                    };
                    if !also.contains(&label) {
                        also.push(label);
                    }
                }
                if also.is_empty() {
                    println!("{}", l.text);
                } else {
                    println!("{} · also covered by {}", l.text, also.join(", "));
                }
            }
            for uid in &live {
                if !winner.contains_key(&appid(*uid)) {
                    let name =
                        blocklist::package_for_uid(*uid).unwrap_or_else(|| format!("uid {uid}"));
                    println!("{name}\tuid {uid} · live, not saved");
                }
            }

            if persisted.is_empty() && live.is_empty() {
                if engine_unknown {
                    println!(
                        "hide list empty\tengine unreadable - cannot say what the kernel is hiding"
                    );
                } else {
                    println!("no blocked apps");
                }
            }
        }
        UidAction::Apply { early } => {
            let _pass = pass_guard();
            let rep = reapply_blocklist(&nm, early);
            println!(
                "hidden {}, not installed {}, skipped {}, retired {}, failed {}",
                rep.hidden, rep.not_installed, rep.skipped, rep.retired, rep.failed
            );
            if rep.failed > 0 {
                bail!("{} entr(ies) could not be applied", rep.failed);
            }
        }
        UidAction::Preset { name, dry_run, globs } => {
            let Some(name) = name else {
                println!("available presets:");
                for (n, desc) in crate::presets::ALL {
                    let count = crate::presets::entries(n).map(|e| e.len()).unwrap_or(0);
                    println!("  {n}\t{desc} ({count} entries)");
                }
                println!("\nadd with: nomount uid preset <name>");
                return Ok(());
            };
            let Some(mut entries) = crate::presets::entries(&name) else {
                bail!("unknown preset {name:?} - try `nomount uid preset` for the list");
            };
            if globs {
                entries.retain(|e| blocklist::is_pattern(e));
            }
            if dry_run {
                for e in &entries {
                    println!("{e}");
                }
                println!("\n{} entr(ies) - not added (--dry-run)", entries.len());
                return Ok(());
            }
            let added = blocklist::add_many(&entries)?;
            let _pass = pass_guard();
            let rep = reapply_blocklist(&nm, false);
            println!(
                "preset {name}: {added} new, {} already present · now hiding {}{}",
                entries.len() - added,
                rep.hidden,
                rep.fail_note()
            );
            if rep.failed > 0 {
                bail!("{} preset entr(ies) could not be applied", rep.failed);
            }
        }
        UidAction::Isolated { mode } => match mode {
            None => println!("{}", isolated_mode_name(blocklist::hide_isolated())),
            Some(m) => {
                let Some(v) = parse_isolated_mode(&m) else {
                    bail!("unknown mode '{m}' - use both | appzygote | platform | off");
                };
                let _pass = pass_guard();
                nm.set_hide_isolated(v).map_err(|e| {
                    e.context("engine did not accept the isolated-pool knob (kernel too old?)")
                })?;
                blocklist::set_hide_isolated(v)?;
                println!("ok: {}", isolated_mode_name(v));
            }
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolated_mode_words_and_numbers_both_parse() {
        assert_eq!(parse_isolated_mode("both"), Some(3));
        assert_eq!(parse_isolated_mode("APPZYGOTE"), Some(1));
        assert_eq!(parse_isolated_mode("platform"), Some(2));
        assert_eq!(parse_isolated_mode(" off "), Some(0));
        assert_eq!(parse_isolated_mode("2"), Some(2));
        assert_eq!(parse_isolated_mode("sometimes"), None);
    }

    /// One row per appid, and the exact entry is the one that speaks
    #[test]
    fn a_uid_list_row_is_per_appid_and_the_exact_entry_wins() {
        let rows = [(Some(10438), true), (Some(10438), false), (Some(10471), false)];
        let w = list_winners(&rows);
        assert_eq!(w.len(), 2, "one row per appid, not one per hide-list entry");
        assert_eq!(w[&10438], 1, "the exact entry speaks, so its ✕ changes something");
        assert_eq!(w[&10471], 2);

        assert_eq!(list_winners(&[(Some(1), false), (Some(1), true)])[&1], 0);
        assert_eq!(list_winners(&[(Some(1), true), (Some(1), true)])[&1], 0);
        assert!(list_winners(&[(None, true), (None, false)]).is_empty());
    }

    /// `uid unblock` must not report a removal it did not make
    #[test]
    fn unblock_reports_both_halves_of_what_it_did() {
        let listed_and_hiding = unblock_message("com.a", Some(10123), true, true);
        let listed_only = unblock_message("com.a", Some(10123), true, false);
        let hiding_only = unblock_message("com.a", Some(10123), false, true);
        let neither = unblock_message("com.a", Some(10123), false, false);

        assert!(listed_and_hiding.contains("unhidden"));
        assert!(
            !listed_only.contains("unhidden"),
            "nothing was unhidden here: {listed_only}"
        );
        assert!(listed_only.contains("removed"));
        assert!(
            hiding_only.contains("not in the hide list"),
            "an appid hidden but never listed must say so: {hiding_only}"
        );
        assert!(
            !neither.contains("removed") && !neither.contains("unhidden"),
            "unblocking something that was neither listed nor hidden must not \
             claim either: {neither}"
        );

        let gone_unlisted = unblock_message("com.a", None, false, false);
        assert!(
            !gone_unlisted.contains("removed") && !gone_unlisted.contains("unhidden"),
            "{gone_unlisted}"
        );
        assert!(unblock_message("com.a", None, true, false).contains("removed"));

        let all = [
            listed_and_hiding, listed_only, hiding_only, neither, gone_unlisted,
            unblock_message("com.a", None, true, false),
            unblock_message("com.a", None, true, true),
            unblock_message("com.a", None, false, true),
        ];
        let mut seen: Vec<&str> = all.iter().map(String::as_str).collect();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(before, seen.len(), "two states produce the same sentence");
    }
}
