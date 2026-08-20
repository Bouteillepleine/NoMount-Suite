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

    for e in entries {
        // Skip-and-continue on a malformed entry: one bad line (a hand-edited
        // out-of-range UID) must NOT abort the boot-time apply and leave every
        // later app un-hidden -- the exact failure this module exists to prevent.
        let resolved = if early {
            blocklist::resolve_early(&e, &cache)
        } else {
            blocklist::resolve(&e)
        };
        match resolved {
            Ok(Resolved::Uid(uid)) => {
                if !early {
                    if let Some(old) = cache.get(&e) {
                        if *old != uid {
                            let _ = nm.uid_unblock(*old);
                            live.retain(|u| appid(*u) != *old);
                            rep.retired += 1;
                        }
                    }
                    blocklist::cache_put(&e, uid);
                }
                // A UID the kernel already hides answers EEXIST -- the desired end
                // state, not a failure. Anything else is real.
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
            Ok(Resolved::NotInstalled) => {
                if !early {
                    // Gone (or not here yet): retire the mirror entry and stop
                    // hiding from whatever now owns that appid.
                    if let Some(old) = cache.get(&e) {
                        let _ = nm.uid_unblock(*old);
                        live.retain(|u| appid(*u) != *old);
                        blocklist::cache_forget(&e);
                        rep.retired += 1;
                    }
                }
                rep.skipped += 1;
            }
            Err(err) => {
                eprintln!("nomount: skipping hide-list entry {e:?}: {err:#}");
                rep.skipped += 1;
            }
        }
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

            for e in &persisted {
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
