use std::path::Path;

use anyhow::Result;

use super::{UidAction, VfsAction};
use crate::blocklist::{self, Resolved};
use crate::nm::Nm;

/// Android packs (user_id, appid) into a uid. The kernel's blocked set stores and
/// returns the APPID, so a raw-uid comparison misses for any work-profile or clone
/// uid (>= 100000) -- reporting "not blocked" for one that is.
const PER_USER_RANGE: u32 = 100_000;
fn appid(uid: u32) -> u32 { uid % PER_USER_RANGE }

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
            println!("ok");
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

pub fn handle_uid(action: UidAction) -> Result<()> {
    let nm = Nm::new();
    match action {
        // Block: persist the target, then block it live if it resolves right now.
        // A package that isn't installed yet is still recorded so `apply` picks it
        // up when it appears — the block "sticks" the moment the app exists.
        UidAction::Block { target } => {
            blocklist::add(&target)?;
            match blocklist::resolve(&target)? {
                Resolved::Uid(uid) => {
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
            blocklist::remove(&target)?;
            match blocklist::resolve(&target)? {
                Resolved::Uid(uid) => {
                    if nm.uid_list_live().unwrap_or_default().iter().any(|u| appid(*u) == appid(uid)) {
                        nm.uid_unblock(uid)?;
                    }
                    println!("ok: {target} (uid {uid}) unhidden");
                }
                Resolved::NotInstalled => {
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
        // Apply: re-assert a block for every installed entry; skip only the ones
        // that aren't installed right now. The kernel returns an error when a UID
        // is *already* blocked (EEXIST) — that's the desired end state, not a
        // failure, so a resolved app counts as applied regardless of that. Called
        // from service.sh once packages.list is populated; the boot idr is empty
        // so the first pass genuinely blocks each, and re-runs stay idempotent.
        UidAction::Apply => {
            let mut applied = 0u32;
            let mut skipped = 0u32;
            for e in blocklist::read()? {
                // Skip-and-continue on a malformed entry: one bad line (e.g. a hand-edited
                // out-of-range UID) must NOT abort the boot-time apply and leave every
                // later UID un-hidden -- the exact failure this module exists to prevent.
                match blocklist::resolve(&e) {
                    Ok(Resolved::Uid(uid)) => {
                        let _ = nm.uid_block(uid);
                        applied += 1;
                    }
                    Ok(Resolved::NotInstalled) => skipped += 1,
                    Err(err) => {
                        eprintln!("nomount: skipping blocklist entry {e:?}: {err:#}");
                        skipped += 1;
                    }
                }
            }
            println!("applied {applied}, skipped {skipped}");
        }
    }
    Ok(())
}
