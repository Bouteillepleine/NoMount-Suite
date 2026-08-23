//! `nomount doctor` — lint the mount plan before a reboot turns a bad rule into a bootloop.
//!
//! The checks below are not generic: each one encodes a failure this engine (or the
//! Android platform underneath it) actually produces, so a clean run means something.
//! The plan is resolved by [`crate::mount::collect_plan`], i.e. the *same* decisions the
//! mount pass will make — following the "detect conflicts at plan time, not randomly at
//! boot" approach the other mount metamodules settled on.
//!
//! Live rules are cross-checked too when the engine is up, because some hazards can only
//! come from a hand-written `nm add` (the plan can no longer produce them).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::mount::{collect_plan, PlanKind};
use crate::nm::Nm;

/// Partitions whose file descriptors zygote will accept across `forkSystemServer`.
///
/// `FileDescriptorInfo::CreateFromFd` validates every open FD against this set when
/// zygote forks system_server. An RRO overlay APK served from anywhere else (OnePlus/Oppo
/// ship `/my_product/cust/<region>/overlay/…` twins) aborts the fork with
/// `JNI FatalError: Not allowlisted` *before* system_server or OMS ever runs — an
/// unrecoverable early bootloop with no useful logcat.
const ZYGOTE_FD_ALLOWLISTED: &[&str] = &[
    "system", "product", "vendor", "system_ext", "odm", "apex", "oem",
];

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Error,
    Warn,
    /// Worth printing, not worth acting on. Kept out of the warning count so a
    /// standing observation about a working configuration cannot bury a real one.
    Info,
}

struct Finding {
    level: Level,
    check: &'static str,
    detail: String,
}

fn partition_of(p: &Path) -> Option<String> {
    p.components()
        .nth(1)
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
}

fn is_partition_root(p: &Path) -> bool {
    p.components().skip(1).count() == 1
}

/// Parse `nm list` output ("<target> -> <source>" per line) into pairs.
fn parse_live(list: &str) -> Vec<(PathBuf, PathBuf)> {
    list.lines()
        .filter_map(|l| {
            // Match mount.rs: strip the ` [UID: N]` suffix (else it lands in the
            // source path and every metadata check on a per-UID rule silently
            // no-ops), and split on the LAST arrow so a target containing one is
            // not mis-split.
            let l = l.split(" [UID:").next().unwrap_or(l);
            let (t, s) = l.rsplit_once(" -> ")?;
            let (t, s) = (t.trim(), s.trim());
            if t.is_empty() || s.is_empty() {
                return None;
            }
            Some((PathBuf::from(t), PathBuf::from(s)))
        })
        .collect()
}




pub fn run_doctor() -> Result<()> {
    // partition -> count of non-overlay entries not in zygote's FD allowlist
    let mut fd_note: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut f: Vec<Finding> = Vec::new();
    let (plan, skipped) = collect_plan();

    // ---- plan-level checks -------------------------------------------------
    let mut by_target: HashMap<&Path, Vec<&str>> = HashMap::new();
    for e in &plan {
        by_target
            .entry(e.target.as_path())
            .or_default()
            .push(e.module.as_str());

        // A rule on a bare partition root redirects/masks the WHOLE partition, hiding
        // every stock entry under it. Fatal for a whiteout just as much as an inject, so
        // this is checked for both kinds (a whiteout on a root was previously unguarded).
        if is_partition_root(&e.target) {
            f.push(Finding {
                level: Level::Error,
                check: "partition-root target",
                detail: format!(
                    "{} would {} all of {}",
                    e.module,
                    if e.kind == PlanKind::Whiteout { "hide" } else { "replace" },
                    e.target.display()
                ),
            });
        }

        // Only where a hole genuinely REMAINS: from engine v13 a single-block
        // erofs parent is recomputed, so reporting those would cry wolf on the
        // debloat case -- the very one the fix made clean.
        if e.kind == PlanKind::Whiteout && crate::mount::whiteout_leaves_hole(&e.target) {
            f.push(Finding {
                level: Level::Info,
                check: "whiteout leaves a measurable hole",
                detail: format!(
                    "{} hides {}, whose parent is multi-block erofs (or the engine predates \
                     v13): the size and link count still count the hidden entry and the engine \
                     cannot recompute them there, so a caller that replays erofs block packing \
                     can spot it. Applied anyway — declining it would silently neuter the module",
                    e.module,
                    e.target.display()
                ),
            });
        }

        if e.kind == PlanKind::Inject {
            // Backing gone (module updated/removed underneath us) -> rule serves nothing.
            // `exists()` follows symlinks, so a DANGLING symlink lands here too — and
            // reporting that as "source missing" sends the reader to a path that is
            // plainly there in `ls`. Injection resolves a symlink to its target, so a
            // link with no target yields no rule at all: `plan` lists the entry and
            // `reload` counts it, then the path simply never appears. Name which of
            // the two it is, because the fixes differ.
            if !e.source.exists() {
                let detail = match fs::symlink_metadata(&e.source) {
                    Ok(m) if m.file_type().is_symlink() => {
                        let dest = fs::read_link(&e.source).unwrap_or_default();
                        format!(
                            "{} -> {} is a symlink to {}, which does not exist. Injection \
                             serves a link's TARGET, so this produces no rule and the path \
                             never appears — an installer that symlinks before its target \
                             lands hits this",
                            e.target.display(),
                            e.source.display(),
                            dest.display()
                        )
                    }
                    _ => format!("{} -> {} (source missing)", e.target.display(), e.source.display()),
                };
                f.push(Finding { level: Level::Error, check: "missing backing", detail });
            }
        }

        // Target on a partition this device doesn't have -> silently dead rule.
        if let Some(part) = partition_of(&e.target) {
            if !Path::new(&format!("/{part}")).is_dir() {
                f.push(Finding {
                    level: Level::Warn,
                    check: "no such partition",
                    detail: format!("{} targets /{} which does not exist", e.module, part),
                });
            }
        }
    }

    // MODULE-LEVEL rollup, kept but inverted: with the policy flip nothing is
    // declined, so the question is no longer "does this module work" but "how
    // much detectable surface does it add". Reported per module because that is
    // the unit a user installs and can uninstall.
    let mut per_mod: HashMap<&str, usize> = HashMap::new();
    for e in &plan {
        if e.kind == PlanKind::Whiteout && crate::mount::whiteout_leaves_hole(&e.target) {
            *per_mod.entry(e.module.as_str()).or_default() += 1;
        }
    }
    let mut rolled: Vec<(&str, usize)> = per_mod.into_iter().collect();
    rolled.sort_by_key(|(m, _)| *m);
    for (module, n) in rolled {
        f.push(Finding {
            level: Level::Info,
            check: "module hides where the hole remains",
            detail: format!(
                "{module} applies {n} hide(s) the engine cannot make consistent (multi-block \
                 erofs parents). Hides on single-block parents are corrected and not counted \
                 here. Uninstall the module or move its targets if that matters more"
            ),
        });
    }

    // Two modules writing the same path: last one wins, silently.
    let mut collisions: Vec<(&Path, Vec<&str>)> = by_target
        .into_iter()
        .filter(|(_, m)| {
            let mut u: Vec<&&str> = m.iter().collect();
            u.sort_unstable();
            u.dedup();
            u.len() > 1
        })
        .collect();
    collisions.sort_by_key(|(t, _)| *t);
    for (target, mods) in &collisions {
        let mut m = mods.clone();
        m.sort_unstable();
        m.dedup();
        f.push(Finding {
            level: Level::Warn,
            check: "target claimed twice",
            detail: format!("{} <- {}", target.display(), m.join(", ")),
        });
    }

    // Stale entries in the legacy `blocklist` file. blocklist.rs migrates app
    // names out of it into `uidhide` but deliberately COPIES rather than moves --
    // deleting an entry that really is a module id would let a self-mounting
    // module inject and break boot, which is the worse mistake. The cost is that
    // the leftovers are invisible: mount.rs reads that file as a module-id skip
    // list, so a module whose id happens to match a hidden package would be
    // silently skipped, and nothing would say so. Report them instead of
    // deleting them. Measured on OP15 2026-08-21: four package names still there.
    if let Ok(raw) = std::fs::read_to_string("/data/adb/nomount/blocklist") {
        let hidden: std::collections::HashSet<String> =
            crate::blocklist::read().unwrap_or_default().into_iter().collect();
        let stale: Vec<String> = raw
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter(|l| !Path::new("/data/adb/modules").join(l).is_dir())
            .filter(|l| hidden.contains(*l))
            .map(str::to_string)
            .collect();
        if !stale.is_empty() {
            f.push(Finding {
                level: Level::Info,
                check: "stale legacy blocklist entries",
                detail: format!(
                    "{} entry/entries in /data/adb/nomount/blocklist are hidden APPS, already migrated to uidhide, and inert there ({}). That file is read as a module-id skip list; remove them if you want it to mean only what it says",
                    stale.len(),
                    stale.join(", ")
                ),
            });
        }
    }

    // The root manager's own "umount modules" switch. With the Suite this is
    // inert -- injection is a VFS redirect, not a mount, so there is nothing for
    // it to unmount and the kernel's umount list stays empty. Users reach for it
    // expecting it to hide modules, which it cannot do here, and on this build
    // enabling it once cost ~8 reboots: su used to arrive as a module overlay,
    // so anything stripping module content stripped su with it. The Suite keeps
    // su out entirely now (kernel sucompat), but there is still no upside.
    let kernel_umount = crate::manager::kernel_umount_enabled();
    if kernel_umount == Some(true) {
        f.push(Finding {
            level: Level::Warn,
            check: "manager kernel umount ON",
            detail: "manager \"Kernel umount\" is ON — it hides nothing here (injections are \
                     not mounts). Turn it OFF; use `nomount uid block <uid>` per app."
                .to_string(),
        });
    }

    // The GLOBAL "Umount modules by default". This is the dangerous one: it
    // strips module content from every app WITHOUT a profile, which in July
    // included any app the moment it asked for root, and that is what broke root
    // on this device. Warned above kernel_umount's own finding because enabling
    // kernel_umount is what silently turned THIS on.
    if crate::manager::global_umount_default() == Some(true) {
        f.push(Finding {
            level: Level::Warn,
            check: "manager global umount ON",
            detail: "manager \"Umount modules by default\" is ON — strips module content from \
                     every profile-less app and hides nothing here. Turn it OFF"
                .to_string(),
        });
    }

    // Per-app "umount modules" profiles. Read from the allowlist rather than
    // guessed: the layout is verified against known uids before it is trusted,
    // and a decode that stops making sense yields nothing instead of invented
    // flags. Info, not warn -- these are harmless here, just pointless.
    let flags = crate::manager::app_umount_flags();
    let umounters: Vec<&str> =
        flags.iter().filter(|a| a.umount_modules).map(|a| a.package.as_str()).collect();
    if !umounters.is_empty() {
        let shown: Vec<&str> = umounters.iter().take(2).copied().collect();
        f.push(Finding {
            level: Level::Info,
            check: "per-app umount profiles",
            detail: format!(
                "{} app(s) have an \"umount modules\" profile ({}{}) — harmless here, hides \
                 nothing we inject",
                umounters.len(),
                shown.join(", "),
                if umounters.len() > shown.len() { ", …" } else { "" }
            ),
        });
    }

    // ---- live checks (engine up) ------------------------------------------
    let nm = Nm::new();
    let engine = nm.version().ok();
    let live_ok = engine.is_some();
    let mut live_count = 0usize;
    // Apps hidden from the injections, and the live rules the PackageManager
    // advertises regardless -- the pair the opt-out check below is about.
    let hidden_apps = crate::blocklist::read().unwrap_or_default();
    let mut rom_apk_rules = 0usize;
    if live_ok {
        if let Ok(list) = nm.list() {
            let live = parse_live(&list);
            live_count = live.len();
            rom_apk_rules = live
                .iter()
                .filter(|(t, _)| crate::pmcache::is_rom_apk(t))
                .count();
            for (target, source) in &live {
                if is_partition_root(target) {
                    f.push(Finding {
                        level: Level::Error,
                        check: "partition-root rule live",
                        detail: format!("{} is redirected wholesale -> {}", target.display(), source.display()),
                    });
                }
                // The zygote FD-allowlist trap. Overlay APKs are the dangerous case because
                // zygote preloads them; flag anything else on such a partition as a warning.
                if let Some(part) = partition_of(target) {
                    if !ZYGOTE_FD_ALLOWLISTED.contains(&part.as_str()) {
                        let is_overlay_apk = target.extension().and_then(|x| x.to_str()) == Some("apk")
                            && target.components().any(|c| c.as_os_str() == "overlay");
                        if is_overlay_apk {
                            // The genuinely dangerous case: zygote preloads these and an
                            // identity mismatch aborts forkSystemServer. Always per-file.
                            f.push(Finding {
                                level: Level::Error,
                                check: "not FD-allowlisted",
                                detail: format!(
                                    "{} lives on /{part} — an overlay APK here aborts forkSystemServer",
                                    target.display()
                                ),
                            });
                        } else {
                            // Everything else on such a partition is the same observation
                            // repeated once per file. Emitting one warning per entry buried
                            // real findings under ~85 identical lines on a device that boots
                            // fine, so count them and report once per partition below.
                            *fd_note.entry(part).or_insert(0usize) += 1;
                        }
                    }
                }
                // Served content should be byte-identical in size to its backing; a mismatch
                // means the redirect is not actually being served.
                if let (Ok(a), Ok(b)) = (fs::metadata(target), fs::metadata(source)) {
                    if a.is_file() && b.is_file() && a.len() != b.len() {
                        f.push(Finding {
                            level: Level::Warn,
                            check: "size mismatch",
                            detail: format!(
                                "{} is {} bytes, backing is {}",
                                target.display(),
                                a.len(),
                                b.len()
                            ),
                        });
                    }
                }
            }
        }
    }

    // A ROM APK is the one injection the system advertises to an app that is
    // hidden from us: the PackageManager scans those directories as system_server
    // (never blocked), registers what it finds, and names the path to every app
    // that asks. `Nm::add` therefore serves them with the hiding opt-out — but
    // that flag only exists from engine v15, and an older one strips it with
    // every other unknown bit. The result is silent: the rule applies, the app
    // still gets ENOENT on a path the PM says exists, and the only symptom is
    // whatever that app does about it (Trusteer SIGSEGVs). Say so instead.
    if live_ok && !hidden_apps.is_empty() && rom_apk_rules > 0 && engine.unwrap_or(0) < 15 {
        f.push(Finding {
            level: Level::Warn,
            check: "engine predates the hiding opt-out",
            detail: format!(
                "engine v{} < 15: {rom_apk_rules} ROM APK rule(s) cannot opt out of per-UID \
                 hiding, so the {} hidden app(s) see a PackageManager-registered path that \
                 open() refuses. Rebuild the kernel from kbuild@hookless >= 15, or unhide \
                 any app that walks the package list",
                engine.unwrap_or(0),
                hidden_apps.len()
            ),
        });
    }

    // ---- report ------------------------------------------------------------
    let injects = plan.iter().filter(|e| e.kind == PlanKind::Inject).count();
    let whiteouts = plan.iter().filter(|e| e.kind == PlanKind::Whiteout).count();
    let binds = plan.iter().filter(|e| e.kind == PlanKind::Bind).count();
    let modules = {
        let mut m: Vec<&str> = plan.iter().map(|e| e.module.as_str()).collect();
        m.sort_unstable();
        m.dedup();
        m.len()
    };
    println!(
        "nomount doctor: {modules} modules planned | {injects} injects, {whiteouts} whiteouts, \
         {binds} my_* binds, {skipped} blocklisted | live: {}",
        if live_ok {
            format!("{live_count} rules")
        } else {
            "engine not responding".to_string()
        }
    );

    f.sort_by(|a, b| a.level.cmp(&b.level).then(a.check.cmp(b.check)));
    // Any module-backed mount still standing is an app-visible detection surface:
    // it is the one thing the mountless posture exists to deny, and after absorb
    // has run the only ones left are those deliberately skipped. Report them, so
    // opting out of absorption is a visible trade rather than a silent one.
    // A mount left standing on purpose is an observation, not a warning: absorb is
    // never going to take it, so there is nothing to act on. Only a mount that
    // nothing declined is worth flagging — that one means absorb has not run or
    // could not do its job.
    for s in crate::absorb::survey().unwrap_or_default() {
        let (level, check, detail) = match &s.disposition {
            crate::absorb::Disposition::Declined(crate::absorb::Declined::Framework(id)) => (
                Level::Info,
                "module mount left by design",
                format!(
                    "{} <- {} — {id} is a hook framework; absorb leaves it alone",
                    s.target.display(),
                    s.source.display()
                ),
            ),
            crate::absorb::Disposition::Declined(crate::absorb::Declined::Listed(from)) => (
                Level::Info,
                "module mount left by design",
                format!(
                    "{} <- {} stays mounted: listed in {from}. Remove its entry to absorb it",
                    s.target.display(),
                    s.source.display()
                ),
            ),
            crate::absorb::Disposition::Declined(crate::absorb::Declined::HooksElsewhere(id)) => (
                Level::Info,
                "module mount left by design",
                format!(
                    "{} <- {} stays mounted: {id} also mounts a known hook path, so absorb \
                     leaves everything it owns alone",
                    s.target.display(),
                    s.source.display()
                ),
            ),
            crate::absorb::Disposition::Declined(crate::absorb::Declined::MustBind) => (
                Level::Info,
                "module mount left by design",
                format!(
                    "{} <- {} stays mounted: a my_* target is served by a real bind, so \
                     absorbing it into an injection would bootloop zygote",
                    s.target.display(),
                    s.source.display()
                ),
            ),
            // Nothing declined it and absorb cannot take it, so it is simply
            // there — the exact condition the mountless posture exists to deny.
            crate::absorb::Disposition::Leaking(why) => (
                Level::Warn,
                "foreign mount absorb cannot take",
                format!(
                    "{} <- {} is a real mount visible to any app, and absorb cannot convert \
                     it: {why}",
                    s.target.display(),
                    s.source.display()
                ),
            ),
            // Already served by an injection, so absorb only has to unmount it —
            // no `--include-dirs`, nothing to re-serve. Still a warning while it
            // stands: a redundant mount is every bit as visible to an app as a
            // load-bearing one.
            crate::absorb::Disposition::Redundant => (
                Level::Warn,
                "module mount not absorbed",
                format!(
                    "{} <- {} is still a real mount and visible to any app, but its content is ALREADY served by live injections, so the mount is redundant — `nomount absorb` just unmounts it. The owning module is bind-mounting content NoMount already injects; dropping that bind from its post-fs-data.sh stops it coming back at boot",
                    s.target.display(),
                    s.source.display()
                ),
            ),
            // A DIRECTORY bind is absorbable in principle but a plain run always
            // skips it, so telling the reader to "run nomount absorb" would send
            // them to a command that declines it again and explains nothing.
            crate::absorb::Disposition::Absorb if s.source.is_dir() => (
                Level::Warn,
                "module mount not absorbed",
                format!(
                    "{} <- {} is a directory bind, still a real mount and visible to any \
                     app. A plain `nomount absorb` skips it, because injecting a directory \
                     snapshots its listing and would miss files the module adds later — \
                     `nomount absorb --include-dirs` takes it anyway",
                    s.target.display(),
                    s.source.display()
                ),
            ),
            crate::absorb::Disposition::Absorb => (
                Level::Warn,
                "module mount not absorbed",
                format!(
                    "{} <- {} is still a real mount and visible to any app, and nothing \
                     declined it — run `nomount absorb` (it runs at boot, so this usually \
                     means it failed)",
                    s.target.display(),
                    s.source.display()
                ),
            ),
        };
        f.push(Finding { level, check, detail });
    }

    // Mounts absorb can neither see nor remove, because they live in a namespace
    // it is not in. Reported separately from the survey above: the verdict there
    // is about our own mountinfo, and an app's view can be strictly worse.
    for e in crate::absorb::survey_elsewhere() {
        f.push(Finding {
            level: Level::Warn,
            check: "foreign mount in another namespace",
            detail: format!(
                "{} <- {} is mounted in {} but not here, so `nomount absorb` can neither \
                 see nor unmount it — it was replicated with nsenter and is visible to apps",
                e.mount.target.display(),
                e.mount.source.display(),
                e.seen_in
            ),
        });
    }

    // Static pre-flight: what each module's OWN scripts will do to the mount
    // table. The checks above describe mounts that already exist; this one runs
    // off the scripts on disk, so it lands BEFORE boot -- which is the only
    // point at which the nsenter family can still be avoided rather than
    // discovered. See preflight.rs for the survey this is sized from.
    for h in crate::preflight::scan_all("/data/adb/modules", "meta-nomount") {
        let (level, check, detail) = match h.habit {
            crate::preflight::MountHabit::Namespace => (
                Level::Warn,
                "mounts into other namespaces",
                format!(
                    "{} uses {} — mounts in other processes' namespaces; absorb cannot \
                     remove those",
                    h.module, h.evidence
                ),
            ),
            crate::preflight::MountHabit::ForeignFs => (
                Level::Warn,
                "mounts its own filesystem",
                format!(
                    "{} sets up {} — absorb cannot re-serve it, so it stays a real mount",
                    h.module, h.evidence
                ),
            ),
            crate::preflight::MountHabit::Pseudo => (
                Level::Info,
                "mounts a pseudo-fs",
                format!(
                    "{} mounts {} — kernel pseudo-fs, no module content", h.module, h.evidence
                ),
            ),
            crate::preflight::MountHabit::Absorbable => (
                Level::Info,
                "self-mounts, absorbed",
                format!(
                    "{} uses {} — absorb takes it over at boot", h.module, h.evidence
                ),
            ),
        };
        f.push(Finding { level, check, detail });
    }

    // A module rewriting the root manager's global settings from its own
    // scripts. Separate from the mount scan because the module that motivated it
    // makes no mount call at all: it drives a susfs binary, so the mount scan is
    // blind to it while it flips kernel_umount on every boot.
    // A SUSFS module on a kernel without SUSFS. This is the case where the
    // advice really is "remove it", not "adjust it": every hiding call it makes
    // is a no-op here, while its side effects -- manager settings, props,
    // mounts -- still apply in full. Checked against the kernel, not assumed, so
    // it stays silent on a SUSFS build where these modules do their job.
    // Only claim something about SUSFS when the manager actually answered. On a
    // manager whose ksud has no `susfs` command (KernelSU Next) the probe says
    // nothing about the kernel, and treating that as "no SUSFS" told a user with a
    // SUSFS kernel to delete a working module (KsuNext_NMS#13). The Suite does not
    // use SUSFS and knows nothing of its internals, so silence is the honest answer
    // when nobody could tell us.
    let susfs = crate::manager::susfs_state();
    if susfs != crate::manager::Susfs::Present {
        for u in crate::preflight::scan_susfs_users("/data/adb/modules", "meta-nomount") {
            // "Remove it" is only right for a module whose PURPOSE is SUSFS
            // hiding. A content module making a best-effort SUSFS call in a
            // fallback branch loses nothing here -- saying remove would cost the
            // user the content they installed it for.
            let known_absent = susfs == crate::manager::Susfs::Absent;
            let (level, detail) = match (u.susfs_is_its_purpose, known_absent) {
                (true, true) => (
                    Level::Warn,
                    format!(
                        "{} is a SUSFS module and this kernel has no SUSFS — it hides \
                         nothing here while its side effects still apply. Remove it",
                        u.module
                    ),
                ),
                // Same module, but we could not confirm the kernel. State the
                // condition, do not assert it, and do not tell anyone to delete
                // something that may well be working.
                (true, false) => (
                    Level::Info,
                    format!(
                        "{} is a SUSFS module. This manager cannot report whether the kernel \
                         has SUSFS — if it does not, the module hides nothing here while its \
                         side effects still apply",
                        u.module
                    ),
                ),
                (false, true) => (
                    Level::Info,
                    format!(
                        "{} makes SUSFS calls (no SUSFS here, so they no-op) but ships its \
                         own content — keep it", u.module
                    ),
                ),
                (false, false) => (
                    Level::Info,
                    format!(
                        "{} makes SUSFS calls but ships its own content — keep it", u.module
                    ),
                ),
            };
            let check = if known_absent { "SUSFS calls, no SUSFS" } else { "SUSFS calls" };
            f.push(Finding { level, check, detail });
        }
    }

    for w in crate::preflight::scan_manager_writes("/data/adb/modules", "meta-nomount") {
        let shown = w.value.clone().unwrap_or_else(|| "<computed>".into());
        let (level, detail) = match w.harm {
            Some(why) => (
                Level::Warn,
                format!(
                    "{} sets {}={} every boot — your manual change will not stick. {}",
                    w.module, w.key, shown, why
                ),
            ),
            None => (
                Level::Info,
                format!(
                    "{} sets {}={} every boot", w.module, w.key, shown
                ),
            ),
        };
        f.push(Finding { level, check: "rewrites manager setting", detail });
    }

    for (part, n) in &fd_note {
        f.push(Finding {
            level: Level::Info,
            check: "not FD-allowlisted for zygote",
            detail: format!(
                "{n} injected file(s) on /{part} — zygote does not preload these; fine"
            ),
        });
    }
    let errors = f.iter().filter(|x| x.level == Level::Error).count();
    let warns = f.iter().filter(|x| x.level == Level::Warn).count();
    let infos = f.iter().filter(|x| x.level == Level::Info).count();

    if f.is_empty() {
        println!("[ok] no problems found");
    } else {
        for x in &f {
            let tag = match x.level {
                Level::Error => "error",
                Level::Warn => "warn",
                Level::Info => "info",
            };
            println!("[{tag}] {}: {}", x.check, x.detail);
        }
    }
    if infos > 0 {
        println!("summary: {errors} errors, {warns} warnings, {infos} informational");
    } else {
        println!("summary: {errors} errors, {warns} warnings");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verbatim from `ksud feature get kernel_umount` on OP15 / ReSukiSU.
    /// The parser itself now lives in manager.rs; this keeps the real-device
    /// sample exercising it from here too.
    #[test]
    fn parses_ksud_feature_output() {
        let off = "Feature: kernel_umount (1)\nDescription: Kernel Umount - controls whether \
                   kernel automatically unmounts modules when not needed\nValue: 0\n";
        assert_eq!(crate::manager::parse_feature_value(off), Some(0));
        assert_eq!(crate::manager::parse_feature_value("Feature: x (1)\nValue: 1\n"), Some(1));
        assert_eq!(crate::manager::parse_feature_value("no value here"), None);
    }

    #[test]
    fn partition_of_extracts_top_level() {
        assert_eq!(partition_of(Path::new("/product/overlay/x.apk")).as_deref(), Some("product"));
        assert_eq!(partition_of(Path::new("/system/etc/y.xml")).as_deref(), Some("system"));
        assert_eq!(partition_of(Path::new("/vendor/lib/z.so")).as_deref(), Some("vendor"));
        assert_eq!(partition_of(Path::new("/")), None);
    }

    #[test]
    fn is_partition_root_only_for_bare_roots() {
        assert!(is_partition_root(Path::new("/product")));
        assert!(is_partition_root(Path::new("/system")));
        assert!(!is_partition_root(Path::new("/product/overlay")));
        assert!(!is_partition_root(Path::new("/product/overlay/x.apk")));
    }

    #[test]
    fn parse_live_keeps_only_arrow_pairs() {
        let s = "/product/x.apk -> /data/adb/modules/M/product/x.apk\n\
                 /system/y (whiteout)\n\
                 not a rule line\n\
                 /product/z -> /data/adb/modules/M/product/z\n";
        let v = parse_live(s);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].0, PathBuf::from("/product/x.apk"));
        assert_eq!(v[0].1, PathBuf::from("/data/adb/modules/M/product/x.apk"));
        assert_eq!(v[1].0, PathBuf::from("/product/z"));
    }

    #[test]
    fn parse_live_strips_the_uid_suffix() {
        let v = parse_live("/product/x.apk -> /data/adb/modules/M/x.apk [UID: 10123]\n");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].1, PathBuf::from("/data/adb/modules/M/x.apk"));
    }

    #[test]
    fn parse_live_drops_empty_sides() {
        assert!(parse_live(" -> /data/x").is_empty());
        assert!(parse_live("/product/x -> ").is_empty());
    }
}
