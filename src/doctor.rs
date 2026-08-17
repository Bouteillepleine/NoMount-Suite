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
            let (t, s) = l.split_once(" -> ")?;
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

    // ---- live checks (engine up) ------------------------------------------
    let nm = Nm::new();
    let live_ok = nm.version().is_ok();
    let mut live_count = 0usize;
    if live_ok {
        if let Ok(list) = nm.list() {
            let live = parse_live(&list);
            live_count = live.len();
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
                                check: "not FD-allowlisted for zygote",
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
                    "{} <- {} stays mounted: {id} is a hook framework (Zygisk/Xposed), which \
                     absorb never takes over because a broken hook only surfaces later, \
                     during dexopt",
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

    for (part, n) in &fd_note {
        f.push(Finding {
            level: Level::Info,
            check: "not FD-allowlisted for zygote",
            detail: format!(
                "{n} injected file(s) on /{part} — zygote does not preload these, so this is \
                 informational; an overlay APK here would be reported separately as an error"
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
    fn parse_live_drops_empty_sides() {
        assert!(parse_live(" -> /data/x").is_empty());
        assert!(parse_live("/product/x -> ").is_empty());
    }
}
