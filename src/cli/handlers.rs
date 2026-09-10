use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Result};

use super::{UidAction, VfsAction};
use crate::blocklist::{self, appid, Resolved};
use crate::nm::Nm;

pub fn handle_vfs(action: VfsAction) -> Result<()> {
    let nm = Nm::new();
    match action {
        VfsAction::Add { virtual_path, real_path } => {
            let real = Path::new(&real_path);
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
            nm.whiteout(Path::new(&path))?;
            println!("ok");
        }
        VfsAction::Clear => {
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

pub struct ApplyReport {
    pub hidden: u32,
    pub skipped: u32,
    pub failed: u32,
    pub retired: u32,
}

impl ApplyReport {
    pub fn fail_note(&self) -> String {
        if self.failed > 0 { format!(", {} failed", self.failed) } else { String::new() }
    }
}

pub fn reapply_blocklist(nm: &Nm, early: bool) -> ApplyReport {
    let mut rep = ApplyReport { hidden: 0, skipped: 0, failed: 0, retired: 0 };

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
    if entries.is_empty() {
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
            Ok(Resolved::NotInstalled) => rep.skipped += 1,
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

fn parse_isolated_mode(s: &str) -> Option<u32> {
    match s.trim().to_ascii_lowercase().as_str() {
        "both" | "all" | "3" => Some(3),
        "appzygote" | "app_zygote" | "1" => Some(1),
        "platform" | "isolated" | "2" => Some(2),
        "off" | "none" | "0" => Some(0),
        _ => None,
    }
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
            blocklist::remove(&target)?;
            match blocklist::resolve(&target)? {
                Resolved::Uid(uid) => {
                    let live = nm.uid_list_live().unwrap_or_default();
                    if live.iter().any(|u| appid(*u) == appid(uid)) {
                        nm.uid_unblock(uid)?;
                    }
                    if let Some(old) = cached {
                        if old != uid && live.iter().any(|u| appid(*u) == old) {
                            let _ = nm.uid_unblock(old);
                        }
                    }
                    println!("ok: {target} (uid {uid}) unhidden");
                }
                Resolved::NotInstalled => {
                    if let Some(old) = cached {
                        if nm.uid_list_live().unwrap_or_default().iter().any(|u| appid(*u) == old) {
                            let _ = nm.uid_unblock(old);
                        }
                    }
                    println!("ok: {target} removed from list");
                }
            }
        }
        UidAction::List => {
            let persisted = blocklist::read()?;
            let live = nm.uid_list_live().unwrap_or_default();
            let mut covered: Vec<u32> = Vec::new();

            let installed_opt = blocklist::installed_packages();
            let installed = installed_opt.clone().unwrap_or_default();
            for e in &persisted {
                if blocklist::is_pattern(e) {
                    if installed_opt.is_none() {
                        println!("{e}\tglob · package map unreadable");
                        continue;
                    }
                    match blocklist::expand(e, &installed) {
                        Ok(hits) if hits.is_empty() => println!("{e}\tglob · no match"),
                        Ok(hits) => {
                            for (pkg, uid) in hits {
                                covered.push(uid);
                                let state = if live.iter().any(|u| appid(*u) == appid(uid)) {
                                    "live"
                                } else {
                                    "saved, not applied"
                                };
                                println!("{pkg}\tvia {e} · uid {uid} · {state}");
                            }
                        }
                        Err(err) => println!("{e}\tinvalid glob: {err:#}"),
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
                match resolved {
                    Resolved::Uid(uid) => {
                        covered.push(uid);
                        let state = if live.iter().any(|u| appid(*u) == appid(uid)) {
                            "live"
                        } else {
                            "saved, not applied"
                        };
                        println!("{e}\tuid {uid} · {state}");
                    }
                    Resolved::NotInstalled => println!("{e}\tnot installed"),
                }
            }
            for uid in &live {
                if !covered.iter().any(|c| appid(*c) == appid(*uid)) {
                    let name =
                        blocklist::package_for_uid(*uid).unwrap_or_else(|| format!("uid {uid}"));
                    println!("{name}\tuid {uid} · live, not saved");
                }
            }

            if persisted.is_empty() && live.is_empty() {
                println!("no blocked apps");
            }
        }
        UidAction::Apply { early } => {
            let rep = reapply_blocklist(&nm, early);
            println!(
                "hidden {}, skipped {}, retired {}, failed {}",
                rep.hidden, rep.skipped, rep.retired, rep.failed
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
}
