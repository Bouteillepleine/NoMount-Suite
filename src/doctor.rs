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
    let mut f: Vec<Finding> = Vec::new();
    let (plan, skipped) = collect_plan();

    // ---- plan-level checks -------------------------------------------------
    let mut by_target: HashMap<&Path, Vec<&str>> = HashMap::new();
    for e in &plan {
        by_target
            .entry(e.target.as_path())
            .or_default()
            .push(e.module.as_str());

        if e.kind == PlanKind::Inject {
            // A rule on a bare partition root redirects the WHOLE partition, hiding every
            // stock entry under it. Bind-mount semantics make that correct for the rule as
            // written, so the engine will not stop you — but a module never means it.
            if is_partition_root(&e.target) {
                f.push(Finding {
                    level: Level::Error,
                    check: "partition-root target",
                    detail: format!("{} would replace all of {}", e.module, e.target.display()),
                });
            }
            // Backing gone (module updated/removed underneath us) -> rule serves nothing.
            if !e.source.exists() {
                f.push(Finding {
                    level: Level::Error,
                    check: "missing backing",
                    detail: format!("{} -> {} (source missing)", e.target.display(), e.source.display()),
                });
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
                        f.push(Finding {
                            level: if is_overlay_apk { Level::Error } else { Level::Warn },
                            check: "not FD-allowlisted for zygote",
                            detail: format!(
                                "{} lives on /{part}{}",
                                target.display(),
                                if is_overlay_apk {
                                    " — an overlay APK here aborts forkSystemServer"
                                } else {
                                    ""
                                }
                            ),
                        });
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
    let whiteouts = plan.len() - injects;
    let modules = {
        let mut m: Vec<&str> = plan.iter().map(|e| e.module.as_str()).collect();
        m.sort_unstable();
        m.dedup();
        m.len()
    };
    println!(
        "nomount doctor: {modules} modules planned | {injects} injects, {whiteouts} whiteouts, \
         {skipped} blocklisted | live: {}",
        if live_ok {
            format!("{live_count} rules")
        } else {
            "engine not responding".to_string()
        }
    );

    f.sort_by(|a, b| a.level.cmp(&b.level).then(a.check.cmp(b.check)));
    let errors = f.iter().filter(|x| x.level == Level::Error).count();
    let warns = f.len() - errors;

    if f.is_empty() {
        println!("[ok] no problems found");
    } else {
        for x in &f {
            let tag = match x.level {
                Level::Error => "error",
                Level::Warn => "warn",
            };
            println!("[{tag}] {}: {}", x.check, x.detail);
        }
    }
    println!("summary: {errors} errors, {warns} warnings");
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
