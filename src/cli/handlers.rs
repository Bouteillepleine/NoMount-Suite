use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{bail, Context, Result};

use super::{UidAction, VfsAction};
// Android packs (user_id, appid) into a uid, and the kernel's blocked set stores
// and returns the APPID -- so a raw-uid comparison misses for any work-profile or
// clone uid, reporting "not blocked" for one that is. The normalisation lives in
// blocklist.rs now, because the persisted file and the wire calls need it too.
use crate::blocklist::{self, appid, Resolved};
use crate::nm::Nm;

/// What `uid unblock` actually did, in words.
///
/// Two facts, independently true or false, and the verb reported neither: the
/// entry was in the hide list (`existed`), and the kernel was hiding an appid
/// for it (`unhid`). The plain branch threw `blocklist::remove`'s answer away and
/// printed "removed from list" unconditionally — so `nomount uid unblock
/// com.nothing.here` reported success for a name that was never there, and the
/// WebUI's un-hide button, which paints its toast off errno alone, showed green.
/// The glob branch a few lines up has always said "was not in the hide list".
///
/// List membership is not the whole answer either: `uid list` documents a real
/// "live, not saved" state — the kernel hiding an appid that is not in the file —
/// and there the unblock does do something. Hence both flags.
///
/// `uid` is `None` when the package is not installed now.
fn unblock_message(target: &str, uid: Option<u32>, existed: bool, unhid: bool) -> String {
    match (uid, existed, unhid) {
        (Some(uid), true, true) => format!("ok: {target} (uid {uid}) unhidden"),
        (Some(_), true, false) => {
            format!("ok: {target} removed from the hide list — it was not being hidden")
        }
        (Some(uid), false, true) => format!(
            "ok: {target} (uid {uid}) unhidden — it was not in the hide list, so nothing was saved"
        ),
        (Some(_), false, false) => {
            format!("ok: {target} was not hidden, and was not in the hide list")
        }
        (None, true, true) => format!(
            "ok: {target} removed from the hide list, and its last known uid unhidden — it is \
             not installed now"
        ),
        (None, true, false) => format!("ok: {target} removed from the hide list (not installed)"),
        (None, false, true) => {
            format!("ok: {target} unhidden — not installed, and it was not in the hide list")
        }
        (None, false, false) => {
            format!("ok: {target} is not installed, and was not in the hide list")
        }
    }
}

pub fn handle_vfs(action: VfsAction) -> Result<()> {
    let nm = Nm::new();
    match action {
        VfsAction::Add { virtual_path, real_path } => {
            // A DIRECTORY source is the one rule shape the mount pass refuses to
            // build (`mount::inject_would_mask_dir`), for two separate reasons.
            // Masking is the documented one: serving a stock directory as a single
            // rule hides every stock entry under it, which is what bootlooped
            // zygote. The second was measured on a 6.1 device: a child served
            // through a directory rule inherits the SOURCE's raw block count, so a
            // 2 MB file on f2fs reports 2,002,944 bytes allocated where every stock
            // erofs file of that size reports ~15% of it. `st_blocks * 512 >= st_size`
            // then separates every child of that rule from every stock file in one
            // stat. Refuse it here too rather than let the CLI build by hand the
            // shape the mount pass will not.
            let virt = Path::new(&virtual_path);
            let real = Path::new(&real_path);
            // The VIRTUAL path was passed through unexamined, so this one verb
            // built by hand the two rule shapes every other entry point in the
            // product refuses:
            //
            //  * a bare partition root. `nomount vfs add /product <file>` masks
            //    every stock entry under /product; this project's own notes
            //    record the measured outcome -- the overlays vanished and zygote
            //    SIGABRT'ed. `mount::serve_mode`, `mount::can_whiteout` and
            //    `doctor`'s "partition-root target" finding all say no; the CLI
            //    said ok.
            //  * an unrepresentable path. A `\n` or a ` -> ` in either side
            //    forges a second line in `nm list`, which `nm::parse_list`
            //    returns as a real rule and `absorb` then acts on -- the
            //    forgery `mount::path_is_representable` exists to stop.
            //
            // Deliberately NOT the whole of `serve_mode`/`can_whiteout` here:
            // those refuse every non-ROM root, and `vfs add` is the low-level
            // verb, the one that can repoint a `/data/app` APK the way
            // `mount::add_repointing` does. Taking that away would remove the
            // reason the verb exists. The partition root is the shape that has
            // actually bricked a boot, and it is not a shape anyone means.
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
            // `vfs whiteout` and `whiteout add` issue the SAME engine command;
            // they differ only in whether the path is also written to
            // whiteouts.txt. So they get the same gate, rather than this one
            // having none: `whiteout::validate` refuses a relative path, `..`
            // (which the engine resolves with LOOKUP_FOLLOW), everything
            // `can_whiteout` refuses -- a bare partition root, a non-ROM root --
            // and re-checks the RESOLVED path, because `/system/vendor` is a
            // symlink to `/vendor` on every modern Android. Without it
            // `nomount vfs whiteout /product` was accepted.
            crate::whiteout::validate(&path)?;
            let p = Path::new(&path);
            // ...and the wire-format test `validate` does not make. A path
            // ending in ` (whiteout)`, or containing ` [UID:`, mis-parses into a
            // phantom rule no prune can ever delete.
            if let Err(why) = crate::mount::path_is_representable(p) {
                anyhow::bail!("refusing {}: {why}", p.display());
            }
            nm.whiteout(p)?;
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
            // A non-zero `failed` is embedded in the message but used to leave the
            // EXIT CODE at 0, and the WebUI gates on errno alone -- so
            // `nomount vfs clear` with the engine down toasted a green "Rules
            // cleared" while every hidden app had just been un-hidden (CLEAR_ALL
            // drops the hidden-UID set). `UidAction::Apply` already bails for the
            // same condition; the other verbs did not.
            if re.failed > 0 {
                bail!(
                    "{} hide-list entr(ies) could not be re-applied after the clear -- those apps are NOT hidden",
                    re.failed
                );
            }
        }
        VfsAction::List => {
            // NOTHING on an empty list, not a message. The WebUI reads this
            // through `nomount vfs list` and counts every non-blank line as a
            // rule, so the word "no rules" was itself counted: a device with
            // zero rules showed `Active rules 1`, `(other) 1`, and a rule row
            // named "no rules". Reported from an OP15 with five script-only
            // modules. An empty list is an empty stdout; the UI already has its
            // own empty state for it.
            let list = nm.list()?;
            if !list.trim().is_empty() {
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
    /// Entries that named an app this device does not have installed.
    ///
    /// Separate from `skipped` because it is not a problem and the other three
    /// kinds are. The `detectors` preset ships ~50 names on purpose; nobody has
    /// them all, so folding them into `skipped` logged "skipped 46" on every boot
    /// of a perfectly healthy device and trained the reader to ignore the number
    /// that also carries "a glob matched below the app range" and "malformed
    /// entry".
    pub not_installed: u32,
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
    let mut rep = ApplyReport { hidden: 0, skipped: 0, failed: 0, retired: 0, not_installed: 0 };

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
    // BOTH, not just `entries`. The whole retire/reconcile half of this function
    // lives below, and an empty hide list is exactly when it has the most to do:
    // removing the LAST entry -- and every `uid unblock <glob>`, which does no
    // unblock of its own and delegates entirely to the reconcile because the
    // mirror is keyed by package and `cache_forget("*duck*")` removes nothing --
    // returned here before `desired` was built. The kernel went on hiding every
    // matched appid, `uidhide.cache` went on naming them, every later `apply`
    // returned here too, and the command printed "0 package(s) un-hidden" and
    // exited 0. Nothing recovered it short of a reboot or `nm clear`.
    //
    // The rest of the function is already correct for an empty `entries`:
    // `desired` stays empty, the apply loop does nothing, the reconcile retires
    // everything the mirror still names, and `cache_replace` writes it empty.
    // It also makes the early-boot re-block loop below reachable again.
    if entries.is_empty() && cache.is_empty() {
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
            Ok(Resolved::NotInstalled) => rep.not_installed += 1,
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
            // injections from whatever inherited it. But a DIFFERENT still-desired
            // key (shared UID, a glob and an exact entry, a bare UID and a package)
            // may resolve to that same appid -- unblocking it then un-hides an app
            // this pass still wants hidden. Leave it blocked when anything desired
            // still maps to it.
            if let Some(old) = cache.get(key) {
                if *old != uid && !desired.values().any(|v| *v == *old) {
                    // Count the RESULT, not the attempt. `let _ =` + an
                    // unconditional `retired += 1` reported a retire the engine
                    // refused -- and `cache_replace` below then drops the mirror
                    // entry, so the appid stays in the kernel's hidden set with
                    // NOTHING on disk still naming it. Appids are reused after an
                    // uninstall, so the next app to get it is hidden by accident
                    // and no future pass can find it: the only cure is `nm clear`.
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
            // A different still-desired key may resolve to the same appid (shared
            // UID, glob + exact, bare UID + package). Retiring by key alone would
            // then unblock an app another entry still wants hidden -- print
            // "hidden N" while un-hiding one. Skip when anything desired maps here.
            if desired.values().any(|v| *v == *old) {
                continue;
            }
            // Same reasoning as the drift branch above: a refused unblock must not
            // be counted as a retire, because cache_replace() is about to delete
            // the only record that this appid is still hidden.
            if nm.uid_unblock(*old).is_ok() {
                live.retain(|u| appid(*u) != *old);
                rep.retired += 1;
            } else {
                rep.failed += 1;
            }
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
            // Can this string survive being written to `uidhide` and read back?
            // The file is `\n`-separated, `#`-commented and `trim()`-ed, and the
            // appid mirror beside it is `entry\tappid`, so its own syntax is the
            // whole answer:
            //   * a newline writes ONE entry and parses back as TWO, neither of
            //     which `uid unblock <what you typed>` can ever match again --
            //     the pair is stuck, editable only by hand;
            //   * a leading `#` is written, then dropped as a comment, so
            //     `uid block '#com.foo'` printed ok and hid nothing, forever;
            //   * a tab makes `cache_read`'s `split_once('\t')` yield a
            //     non-numeric appid, so the mirror entry is silently dropped and
            //     the early-boot pass never re-blocks it.
            // Same class as `mount::path_is_representable`, which gates
            // MODULE-supplied paths; this is the user-supplied one.
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
                // See the note in `VfsAction::Clear`: `failed` in the text but
                // exit 0 renders as a green toast in the WebUI.
                if rep.failed > 0 {
                    bail!("{} hide-list entr(ies) could not be applied", rep.failed);
                }
                return Ok(());
            }
            // Resolve BEFORE persisting, so a refused target doesn't linger in the
            // file waiting for the next `apply` to enforce it anyway.
            let resolved = blocklist::resolve(&target)?;
            if let Resolved::Uid(uid) = resolved {
                if uid < blocklist::FIRST_APP_APPID && !force {
                    bail!(
                        "{target} is appid {uid}, below the app range — hiding from it hides injections from Android itself (1000 = system_server: RRO and framework patches revert to stock; 2000 = shell: the health canary then reports a permanent inconsistency; 0 = root). Pass --force if that is really what you want."
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
                // See VfsAction::Clear: `failed` in the text but exit 0 renders as
                // a green toast in the WebUI, which reads errno and nothing else.
                // Here a failure means an app the user just un-hid is STILL hidden,
                // or one they kept hidden no longer is.
                if rep.failed > 0 {
                    bail!("{} hide-list entr(ies) could not be re-applied", rep.failed);
                }
                return Ok(());
            }
            let cached = blocklist::cache_read().get(target.trim()).copied();
            // Kept, not discarded: see `unblock_message` for what this branch
            // used to report and why both halves are needed.
            let existed = blocklist::remove(&target)?;
            // Both arms below take the RESULT of every engine call, and neither
            // reads "could not ask the engine" as "the kernel is hiding nobody".
            // That matters more here than anywhere else in the file, because
            // `blocklist::remove` above has ALREADY dropped the entry from
            // `uidhide` and, via `cache_forget`, from the appid mirror -- so a
            // refused or unasked un-hide leaves the appid in the kernel's hidden
            // set with nothing on disk still naming it. Appids are reused after
            // an uninstall, no later `apply` can find it, and the only cure is
            // `nm clear`. This is the failure `reapply_blocklist` documents at
            // length two hundred lines up; it was still live in both arms here,
            // behind a printed "ok:" and exit 0 that the WebUI toasts green.
            match blocklist::resolve(&target)? {
                Resolved::Uid(uid) => {
                    let live = nm.uid_list_live().with_context(|| {
                        format!(
                            "{target} was removed from the hide list, but the engine could not \
                             be asked which appids it is hiding — it may still be hidden"
                        )
                    })?;
                    let was_live = live.iter().any(|u| appid(*u) == appid(uid));
                    if was_live {
                        nm.uid_unblock(uid)?;
                    }
                    // The app may have been reinstalled under a different appid
                    // since it was hidden; retire the one actually in force too.
                    let mut retired_old = false;
                    if let Some(old) = cached {
                        if old != uid && live.iter().any(|u| appid(*u) == old) {
                            nm.uid_unblock(old).with_context(|| {
                                format!(
                                    "{target}: appid {old} is still hidden and nothing on disk \
                                     names it any more — re-add it with `nomount uid block \
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
                        // Only asked when there IS a stale appid to retire, so a
                        // plain "remove a name that is not installed" still works
                        // on a device whose engine is down.
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
                                     names it any more — re-add it with `nomount uid block \
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
        // List: the persistent set cross-referenced against the kernel's LIVE set,
        // so drift is visible. Each line is `<name>\t<state>` for the WebUI:
        //   uid N · live               — saved AND the kernel is enforcing it
        //   uid N · saved, not applied — in the file but not live (reboot/apply pending)
        //   not installed              — saved package with no current UID
        //   uid N · live, not saved    — kernel is hiding it but it's NOT in the file
        //                                (won't survive a reboot)
        //   uid N · engine unreadable  — saved, and the engine could not be asked
        //                                whether it is in force. Not "not applied".
        UidAction::List => {
            let persisted = blocklist::read()?;
            // Bound, not `unwrap_or_default()`. `uid_list_live` fails whenever
            // `nm` cannot be executed or the dump is refused or truncated, and
            // defaulting to an empty set turned all of that into "the kernel is
            // hiding nobody": every saved entry then rendered "saved, not
            // applied", which the WebUI classes `pending` and STILL counts as
            // active. That card's own comment states the rule this broke --
            // never fall back to the answer the user wants to hear, show it as
            // unknown -- and it guards `r.errno`, which is 0 because the CLI had
            // already swallowed the error. `reapply_blocklist` is honest about
            // the same failure, so this was an inconsistency inside one file.
            //
            // "unreadable" is load-bearing: the WebUI routes /unread/ to the
            // grey `gone` class, so a third state needs no UI change.
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
                                println!("{pkg}\tvia {e} · uid {uid} · {}", state_of(uid));
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
                        println!("{e}\tuid {uid} · {}", state_of(uid));
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
                // "no blocked apps" is the WebUI's exact test for the empty
                // state, so an unreadable engine must NOT print it -- it is the
                // reassuring answer for a question that was never asked. A
                // tab-separated row instead, because a line without a tab lands
                // in the default `live` class and would be counted as an app
                // being hidden.
                if engine_unknown {
                    println!(
                        "hide list empty\tengine unreadable — cannot say what the kernel is hiding"
                    );
                } else {
                    println!("no blocked apps");
                }
            }
        }
        // Apply: re-assert the whole list. The kernel's set is empty at boot and
        // after every `clear`, so the first pass genuinely hides each; re-runs are
        // idempotent.
        UidAction::Apply { early } => {
            let rep = reapply_blocklist(&nm, early);
            println!(
                "hidden {}, not installed {}, skipped {}, retired {}, failed {}",
                rep.hidden, rep.not_installed, rep.skipped, rep.retired, rep.failed
            );
            if rep.failed > 0 {
                bail!("{} entr(ies) could not be applied", rep.failed);
            }
        }
        // Presets are ordinary hide-list entries — nothing about them is special
        // once added, so they can be removed one by one like anything else.
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
                bail!("unknown preset {name:?} — try `nomount uid preset` for the list");
            };
            if globs {
                entries.retain(|e| blocklist::is_pattern(e));
            }
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
            // See VfsAction::Clear. A preset is the largest batch this tool
            // applies (~50 entries), so "48 failed" behind a green toast is the
            // loudest instance of the same bug.
            if rep.failed > 0 {
                bail!("{} preset entr(ies) could not be applied", rep.failed);
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


    /// `uid unblock` must not report a removal it did not make.
    ///
    /// The plain branch -- the one the WebUI's un-hide button calls -- discarded
    /// `blocklist::remove`'s answer and printed "removed from list" for a name
    /// that was never in the list, behind a toast the WebUI paints off errno
    /// alone. Both flags matter independently: the kernel can be hiding an appid
    /// that is not in the file ("live, not saved" in `uid list`).
    #[test]
    fn unblock_reports_both_halves_of_what_it_did() {
        // The two facts, and the four answers each installation state gives.
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
        // The one that used to lie.
        assert!(
            !neither.contains("removed") && !neither.contains("unhidden"),
            "unblocking something that was neither listed nor hidden must not \
             claim either: {neither}"
        );

        // Not installed: same rule, and still not a claim of removal.
        let gone_unlisted = unblock_message("com.a", None, false, false);
        assert!(
            !gone_unlisted.contains("removed") && !gone_unlisted.contains("unhidden"),
            "{gone_unlisted}"
        );
        assert!(unblock_message("com.a", None, true, false).contains("removed"));

        // Every combination says something different, so no two states can be
        // confused by reading the output.
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
