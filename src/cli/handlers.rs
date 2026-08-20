use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Result};

use super::{UidAction, VfsAction};
// Android packs (user_id, appid) into a uid, and the kernel's blocked set stores
// and returns the APPID -- so a raw-uid comparison misses for any work-profile or
// clone uid, reporting "not blocked" for one that is. The normalisation lives in
// blocklist.rs now, because the persisted file and the wire calls need it too.
use crate::blocklist::{self, appid, Resolved};
use crate::nm::Nm;

pub fn handle_vfs(action: VfsAction) -> Result<()> {
    let nm = Nm::new();
    match action {
        VfsAction::Add { virtual_path, real_path } => {
            nm.add(Path::new(&virtual_path), Path::new(&real_path))?;
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
            // CLEAR_ALL drops the kernel's hidden-UID set along with the rules, so
            // a bare clear silently unhides every app on the list. Put the hiding
            // back at once -- the rules are what is being cleared, not the hiding.
            let re = reapply_blocklist(&nm, false);
            if re.hidden > 0 || re.failed > 0 {
                println!("ok (re-hid {} app(s){})", re.hidden, re.fail_note());
            } else {
                println!("ok");
            }
        }
        VfsAction::List => {
            let list = nm.list()?;
            if list.trim().is_empty() {
                println!("no rules");
            } else {
                print!("{list}");
            }
        }
    }
    Ok(())
}

/// Outcome of one re-apply pass. `failed` is what makes this honest: the pass used
/// to discard every kernel error and still report "applied N", so an engine that
/// hid nothing at all (down, EPERM, missing `nm`) read exactly like a clean run --
/// on the one path whose whole job is to be trustworthy.
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

/// Re-assert the persistent hide list (and the isolated-pool policy) against the
/// kernel. Called from `uid apply`, from the mount pass after its `clear`, and
/// after a manual `vfs clear`.
///
/// `early` resolves from the cached appid mirror first, for the post-fs-data pass
/// where `packages.list` is not yet meaningful. The later, authoritative pass also
/// *reconciles*: appids are reused after an uninstall, so an entry that now
/// resolves elsewhere has its stale appid unblocked rather than left hiding
/// injections from whatever inherited it.
pub fn reapply_blocklist(nm: &Nm, early: bool) -> ApplyReport {
    let mut rep = ApplyReport { hidden: 0, skipped: 0, failed: 0, retired: 0 };

    // Knob state is as volatile as the blocked set; re-assert it every pass.
    let mode = blocklist::hide_isolated();
    if nm.set_hide_isolated(mode).is_err() && mode != blocklist::DEFAULT_HIDE_ISOLATED {
        // Only a non-default policy is worth reporting: on a kernel without the
        // knob, the default is what it already does.
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
    // One dump for the whole pass: this runs in the boot path, and asking the
    // kernel once per entry meant a fork+exec+netlink round trip per app.
    let mut live = nm.uid_list_live().unwrap_or_default();

    // Build the set this pass wants hidden, keyed by the *package* (or bare UID)
    // rather than by the list entry, because one glob covers many packages. The
    // cache is keyed the same way, so a glob's matches survive a reboot and are
    // re-blocked by the early pass, before `packages.list` is meaningful.
    // `None` = the package map could not be read. Un-hiding is destructive and
    // "not installed" is indistinguishable from "could not tell", so every retire
    // below is gated on having actually read it. Without this gate one unreadable
    // pass would un-hide every hidden app and wipe the mirror.
    let installed = if early { None } else { blocklist::installed_packages() };
    let can_retire = !early && installed.is_some();
    let installed = installed.unwrap_or_default();
    if !early && !can_retire {
        // Nothing can be resolved this pass; say so rather than reporting success.
        rep.failed += 1;
    }
    let mut desired: BTreeMap<String, u32> = BTreeMap::new();

    for e in &entries {
        if blocklist::is_pattern(e) {
            if early {
                // `packages.list` is not trustworthy yet. Every package this glob
                // matched last time is in the cache under its own name, and the
                // sweep below picks those up.
                continue;
            }
            match blocklist::expand(e, &installed) {
                Ok(hits) => {
                    if hits.is_empty() {
                        rep.skipped += 1;
                    }
                    for (pkg, uid) in hits {
                        // A glob is evaluated on every pass, so unlike an exact entry
                        // it can start matching a package that shares a platform UID
                        // (android.uid.system -> 1000) long after it was added, with
                        // no chance for the --force prompt `uid block` gives. Hiding
                        // from those hides injections from Android itself, so a glob
                        // never reaches below the app range.
                        if uid < blocklist::FIRST_APP_APPID {
                            eprintln!(
                                "nomount: {e} matches {pkg} (appid {uid}, below the app range) — \
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

        // Skip-and-continue on a malformed entry: one bad line (a hand-edited
        // out-of-range UID) must NOT abort the boot-time apply and leave every
        // later app un-hidden -- the exact failure this module exists to prevent.
        let resolved = if early {
            blocklist::resolve_early(e, &cache)
        } else {
            // Against the map already read for this pass, not a fresh read per entry.
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

    // Early pass: re-block whatever the last authoritative pass resolved, globs
    // included. Without this a glob would not take effect until boot completed.
    if early {
        for (pkg, uid) in &cache {
            desired.entry(pkg.clone()).or_insert(*uid);
        }
    }

    for (key, uid) in &desired {
        let uid = *uid;
        if can_retire {
            // Appids are reused after an uninstall, so an entry that now resolves
            // elsewhere has its stale appid unblocked rather than left hiding
            // injections from whatever inherited it.
            if let Some(old) = cache.get(key) {
                if *old != uid {
                    let _ = nm.uid_unblock(*old);
                    live.retain(|u| appid(*u) != *old);
                    rep.retired += 1;
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
            // The kernel answers EEXIST for a UID it already hides, which is
            // the end state we wanted -- only ask when the call failed, so a
            // stale snapshot of the live set cannot be reported as a failure.
            rep.hidden += 1;
        } else {
            rep.failed += 1;
        }
    }

    // Reconcile: anything the mirror still holds but this pass no longer wants is
    // stale -- package uninstalled, entry removed, or a glob stopped matching it.
    // Stop hiding from it, so deleting a glob actually un-hides its matches. Only
    // when the package map was readable: see `can_retire`.
    if can_retire {
        for (key, old) in &cache {
            if desired.contains_key(key) {
                continue;
            }
            let _ = nm.uid_unblock(*old);
            live.retain(|u| appid(*u) != *old);
            rep.retired += 1;
        }
        // One write for the whole pass. Per-entry `cache_put`/`cache_forget` each
        // re-read and rewrote the file, which a ~50-entry preset turned into ~50
        // rewrites in the boot path.
        blocklist::cache_replace(&desired);
    }

    rep
}

/// `both | appzygote | platform | off` <-> the kernel's pool bitmask.
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
        0 => "off — neither pool is hidden from",
        1 => "appzygote — app-zygote pool (90000-98999) only",
        2 => "platform — platform isolated pool (99000-99999) only",
        _ => "both — every isolated process (default)",
    }
}

pub fn handle_uid(action: UidAction) -> Result<()> {
    let nm = Nm::new();
    match action {
        // Block: persist the target, then block it live if it resolves right now.
        // A package that isn't installed yet is still recorded so `apply` picks it
        // up when it appears — the block "sticks" the moment the app exists.
        UidAction::Block { target, force } => {
            // A glob covers however many packages match now *and later*, so it is
            // validated, persisted, then applied through the normal pass.
            if blocklist::is_pattern(&target) {
                if let Some(parsed) = blocklist::Pattern::parse(&target) {
                    parsed?;
                }
                let installed = blocklist::installed_packages().unwrap_or_default();
                let hits = blocklist::expand(&target, &installed)?;
                // Refuse up front if it already matches a platform UID. The apply
                // pass skips those regardless (see the note there), so this is about
                // telling the user now rather than silently doing less than asked.
                if let Some((pkg, uid)) = hits.iter().find(|(_, u)| *u < blocklist::FIRST_APP_APPID)
                {
                    bail!(
                        "{target} matches {pkg} (appid {uid}), below the app range — hiding from \
                         it would hide injections from Android itself. Narrow the glob, or hide \
                         that package explicitly with `uid block {pkg} --force`"
                    );
                }
                blocklist::add(&target)?;
                let rep = reapply_blocklist(&nm, false);
                println!(
                    "ok: {target} saved — matches {} installed package(s), now hiding {}{}",
                    hits.len(),
                    rep.hidden,
                    rep.fail_note()
                );
                return Ok(());
            }
            // Resolve BEFORE persisting, so a refused target doesn't linger in the
            // file waiting for the next `apply` to enforce it anyway.
            let resolved = blocklist::resolve(&target)?;
            if let Resolved::Uid(uid) = resolved {
                if uid < blocklist::FIRST_APP_APPID && !force {
                    bail!(
                        "{target} is appid {uid}, below the app range — hiding from it hides                          injections from Android itself (1000 = system_server: RRO and framework                          patches revert to stock; 2000 = shell: the health canary then reports a                          permanent inconsistency; 0 = root). Pass --force if that is really what                          you want."
                    );
                }
            }
            blocklist::add(&target)?;
            match resolved {
                Resolved::Uid(uid) => {
                    blocklist::cache_put(&target, uid);
                    // Skip the block call if the kernel is already enforcing this
                    // UID — a second block returns EEXIST (non-zero), which would
                    // surface as a spurious failure on the drift→Save path even
                    // though the persist (the point of Save) succeeded.
                    let already = nm.uid_list_live().unwrap_or_default().iter().any(|u| appid(*u) == appid(uid));
                    if already {
                        println!("ok: {target} (uid {uid}) already hidden — saved so it persists");
                    } else {
                        nm.uid_block(uid)?;
                        println!("ok: {target} (uid {uid}) hidden — persists across reboots");
                    }
                }
                Resolved::NotInstalled => {
                    println!("ok: {target} saved — not installed now, will apply when it is");
                }
            }
        }
        // Unblock: drop from the persistent list AND unblock live if it's actually
        // blocked (unblocking a UID the kernel isn't hiding also returns non-zero).
        UidAction::Unblock { target } => {
            // Removing a glob leaves its matches hidden until something retires
            // them; the reconcile in `apply` is what does that, so run it.
            if blocklist::is_pattern(&target) {
                let existed = blocklist::remove(&target)?;
                let rep = reapply_blocklist(&nm, false);
                if existed {
                    println!(
                        "ok: {target} removed — {} package(s) un-hidden, {} still hidden{}",
                        rep.retired,
                        rep.hidden,
                        rep.fail_note()
                    );
                } else {
                    println!("ok: {target} was not in the hide list");
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
                    // The app may have been reinstalled under a different appid
                    // since it was hidden; retire the one actually in force too.
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
        // List: the persistent set cross-referenced against the kernel's LIVE set,
        // so drift is visible. Each line is `<name>\t<state>` for the WebUI:
        //   uid N · live               — saved AND the kernel is enforcing it
        //   uid N · saved, not applied — in the file but not live (reboot/apply pending)
        //   not installed              — saved package with no current UID
        //   uid N · live, not saved    — kernel is hiding it but it's NOT in the file
        //                                (won't survive a reboot)
        UidAction::List => {
            let persisted = blocklist::read()?;
            let live = nm.uid_list_live().unwrap_or_default();
            let mut covered: Vec<u32> = Vec::new();

            // Unreadable package map: globs cannot be expanded, and saying "no
            // match" would read as "nothing is hidden by this rule".
            let installed_opt = blocklist::installed_packages();
            let installed = installed_opt.clone().unwrap_or_default();
            for e in &persisted {
                // A glob stands for however many installed packages it matches;
                // print each one so the list shows what is actually hidden, not
                // just the rule that put it there.
                if blocklist::is_pattern(e) {
                    if installed_opt.is_none() {
                        println!("{e}\tglob · package map unreadable");
                        continue;
                    }
                    match blocklist::expand(e, &installed) {
                        Ok(hits) if hits.is_empty() => println!("{e}\tglob · no match"),
                        Ok(hits) => {
                            // Package first so a reader sees what is hidden; the glob
                            // follows as provenance, and is what removing it acts on.
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
            // Live-only: enforced by the kernel but absent from the file.
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
        // Apply: re-assert the whole list. The kernel's set is empty at boot and
        // after every `clear`, so the first pass genuinely hides each; re-runs are
        // idempotent.
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
        // Presets are ordinary hide-list entries — nothing about them is special
        // once added, so they can be removed one by one like anything else.
        UidAction::Preset { name, dry_run } => {
            let Some(name) = name else {
                println!("available presets:");
                for (n, desc) in crate::presets::ALL {
                    let count = crate::presets::entries(n).map(|e| e.len()).unwrap_or(0);
                    println!("  {n}\t{desc} ({count} entries)");
                }
                println!("\nadd with: nomount uid preset <name>");
                return Ok(());
            };
            let Some(entries) = crate::presets::entries(&name) else {
                bail!("unknown preset {name:?} — try `nomount uid preset` for the list");
            };
            if dry_run {
                for e in &entries {
                    println!("{e}");
                }
                println!("\n{} entr(ies) — not added (--dry-run)", entries.len());
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
        }
        UidAction::Isolated { mode } => match mode {
            None => println!("{}", isolated_mode_name(blocklist::hide_isolated())),
            Some(m) => {
                let Some(v) = parse_isolated_mode(&m) else {
                    bail!("unknown mode '{m}' — use both | appzygote | platform | off");
                };
                // Knob first, persist second. Persisting a policy the engine has
                // just refused leaves the file claiming a setting that is not in
                // force, and every later apply re-tries and re-reports the failure.
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
