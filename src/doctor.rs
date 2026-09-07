//! The PLAN section of `nomount check` — lint the mount plan before a reboot
//! turns a bad rule into a bootloop.
//!
//! The checks below are not generic: each one encodes a failure this engine (or the
//! Android platform underneath it) actually produces, so a clean run means something.
//! The plan is resolved by [`crate::mount::collect_plan`], i.e. the *same* decisions the
//! mount pass will make — following the "detect conflicts at plan time, not randomly at
//! boot" approach the other mount metamodules settled on.
//!
//! Live rules are cross-checked too when the engine is up, because some hazards can only
//! come from a hand-written `nm add` (the plan can no longer produce them).

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::check::{slug, Check, Section, Verdict};
use crate::mount::{collect_plan, is_partition_root, PlanEntry, PlanKind};
use crate::nm::{LiveRule, Nm};

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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Error,
    /// The check could not run at all. NOT a hazard and NOT a pass -- the state
    /// the device-side report already has a bucket for, and the one a plan
    /// finding had no way to say. Reported as Warn, "the engine did not answer"
    /// and "the cloak could not be probed" both counted against a device where
    /// nothing was wrong; reported as Info they would have read as observations
    /// about a working configuration, which is the opposite lie.
    ///
    /// Ordered above Warn deliberately: `Level` derives `Ord` and findings sort
    /// by it, and `Verdict`'s own declaration order puts Unmeasured above Warn.
    /// The two orders have to agree or the report and the plan disagree about
    /// which line matters more.
    Unmeasured,
    Warn,
    /// "Does not apply here" -- the plan side of the same word the device side
    /// already had. Without it a plan check with nothing to look at had to say
    /// Unmeasured, which claims the check COULD have run and did not, and sent
    /// the reader after a remedy that cannot exist. Measured on an OP15 whose
    /// modules are all script-only: nine device checks correctly said n/a while
    /// the one plan check still said "not measured", so the card stayed amber on
    /// a device doing exactly the right thing.
    ///
    /// Ordered between Warn and Info to match `Verdict`, whose declaration order
    /// is Warn < Pass < NotApplicable < Note. `Level` derives `Ord` and findings
    /// sort by it; the two orders have to agree.
    NotApplicable,
    /// Worth printing, not worth acting on. Kept out of the warning count so a
    /// standing observation about a working configuration cannot bury a real one.
    Info,
}

struct Finding {
    level: Level,
    check: &'static str,
    detail: String,
}

/// This file's three levels, onto the one shared verdict.
///
/// `Level` stays as the vocabulary the check bodies are WRITTEN in -- a plan lint
/// naturally says "this is an error" -- and the translation happens once, here.
/// The two enums were never really different: `Error` and
/// `audit::Verdict::Fail` meant the same thing, `Info` and a passing observation
/// meant the same thing, and the only reason there were two was that neither
/// could express the other's remaining states.
///
/// `Info` becomes `Note`, not `Pass`. A plan finding is never a measurement, so
/// it must not land in the pass count: "the plan does not obviously contain this
/// hazard" is not evidence that the device is clean, and folding the two is how a
/// green count gets inflated by observations.
fn verdict_of(level: &Level) -> Verdict {
    match level {
        Level::Error => Verdict::Fail,
        Level::Unmeasured => Verdict::Unmeasured,
        Level::Warn => Verdict::Warn,
        Level::NotApplicable => Verdict::NotApplicable,
        Level::Info => Verdict::Note,
    }
}

/// Who a doctor finding is about, where the check name makes it recoverable.
///
/// Most doctor findings name their module in the detail text as the first word,
/// because they are generated per module. Pulling it out lets the merged list
/// show "from: <module>" the same way an audit finding does.
fn owner_of(f: &Finding) -> Option<String> {
    // These checks are emitted per module and start with the module id.
    const PER_MODULE: &[&str] = &[
        "partition-root target",
        "no such partition",
        "whiteout leaves a measurable hole",
        "wide replacement expansion",
    ];
    if !PER_MODULE.contains(&f.check) {
        return None;
    }
    // The module id is the leading token up to the first space or colon.
    let head = f.detail.split([' ', ':']).next().unwrap_or("");
    if head.is_empty() || head.len() > 64 {
        None
    } else {
        Some(head.trim_end_matches(':').to_string())
    }
}

/// What a hidden caller sees at a ghosted path. Ordered by severity.
#[derive(PartialEq)]
enum GhostSeen {
    /// Indistinguishable from a path that does not exist. What _ghost is for.
    Absent,
    /// The path is VISIBLE to a uid the cloak claims to hide it from, so the
    /// cloak is lying about it: `stat` succeeds while the guarded syscalls
    /// answer ENOENT, a contradiction no real file can produce.
    Visible,
    /// Hidden from `stat`, but `getxattr(security.selinux)` still answers. The
    /// guards are compiled in and not effective -- the shape a kernel takes when
    /// the patch applied but the wrapper it targets is not the one this tree
    /// actually routes through.
    XattrLeak,
    Unknown,
}

/// Become `uid` in a forked child and look at `path`. READ-ONLY: `stat` and
/// `lgetxattr` only, never the write-ish members of the oracle class -- those
/// are safe on a read-only ROM and unsafe anywhere else, and a check that has to
/// reason about which one it is on does not belong in a linter.
///
/// This exists because _ghost is boot-proven on 6.12 alone; 6.6, 6.1, 5.15 and
/// 5.10 are only apply- and compile-verified, and no amount of CI can close that
/// gap. The device can: the guards are inert until the tables are populated, so
/// what is genuinely unknown on those kernels is not whether they boot but
/// whether the cloak WORKS. That is a question the running kernel can be asked.
fn ghost_seen_by(uid: u32, path: &Path) -> GhostSeen {
    use std::os::unix::ffi::OsStrExt;
    let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return GhostSeen::Unknown;
    };
    let Ok(attr) = std::ffi::CString::new("security.selinux") else {
        return GhostSeen::Unknown;
    };
    const ABSENT: u32 = 0;
    const VISIBLE: u32 = 1;
    const XLEAK: u32 = 2;
    // The fork, the setgroups/setgid/setuid ordering and the waitpid live in
    // `audit::probe_as_uid`. This used to carry its own copy, exit statuses and
    // all, plus its own paragraph on why the group list has to go first.
    let seen = crate::audit::probe_as_uid(uid, || unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::stat(cpath.as_ptr(), &mut st) == 0 {
            return [VISIBLE];
        }
        let mut buf = [0u8; 256];
        let n = libc::lgetxattr(
            cpath.as_ptr(),
            attr.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        );
        [if n >= 0 { XLEAK } else { ABSENT }]
    });
    match seen {
        Ok([ABSENT]) => GhostSeen::Absent,
        Ok([VISIBLE]) => GhostSeen::Visible,
        Ok([XLEAK]) => GhostSeen::XattrLeak,
        _ => GhostSeen::Unknown,
    }
}

/// How a finding names a uid that came off the hide list.
///
/// `redact` is [`crate::blocklist::redact_hide_list`], passed in rather than read
/// here so the decision is a pure function a test can pin: the env var is
/// process-global and two tests toggling it would race.
///
/// The appid is what makes a report actionable, so a PRIVATE destination gets it.
/// A shared one must not: `PackageManager.getNameForUid()` turns the number back
/// into a package name, which is the same secret as the hide list itself.
/// audit.rs's PM-open probe makes the same choice in its own words ("uid N
/// (hidden)"); that wording is left alone deliberately, since it is a line that has
/// been verified on-device.
fn hidden_uid_label(uid: u32, redact: bool) -> String {
    if redact {
        "a hidden app".to_string()
    } else {
        format!("hidden uid {uid}")
    }
}

/// Split `nm l g` output into its two tables.
fn parse_ghost_tables(txt: &str) -> (Vec<PathBuf>, Vec<u32>) {
    let mut paths = Vec::new();
    let mut uids = Vec::new();
    for line in txt.lines() {
        let line = line.trim();
        if let Some(p) = line.strip_prefix("p ") {
            if p.starts_with('/') {
                paths.push(PathBuf::from(p));
            }
        } else if let Some(u) = line.strip_prefix("u ") {
            if let Ok(v) = u.trim().parse::<u32>() {
                uids.push(v);
            }
        }
    }
    (paths, uids)
}

fn partition_of(p: &Path) -> Option<String> {
    p.components()
        .nth(1)
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
}

// `is_partition_root` is mount.rs's, imported above. This file used to keep its
// own copy, and it was the `count() == 1` form -- the one mount.rs widened to
// `<= 1` because it answered FALSE for `/`, "the one path where serving a rule is
// most catastrophic", and called "a trap for the next caller". This file lints
// the plan for exactly that class of rule, so it is the last place that should
// have been asking the question with the older answer.

/// Does the engine actually hold the rules the plan describes -- and nothing else?
///
/// doctor already read both halves and never compared them. It resolves the whole
/// plan for the checks above, then dumps the live rule list for the per-rule
/// checks, and the only trace of the two ever meeting was the header line.
/// Measured on an OP15: `258 injects, 0 whiteouts, 0 my_* binds | live: 261 rules`
/// followed by `summary: 0 errors, 0 warnings`. Three live rules the plan could
/// not account for, and the verdict was clean.
///
/// The accounting is [`crate::mount::run_reload`]'s, read-only. Three exemptions
/// are load-bearing, and without them this cries wolf on a healthy device:
///
///   * per-UID rules (`uid != 0`) come from the hide path, not from any module
///     tree, and `nm del` cannot even address them;
///   * a durable whiteout (`nomount whiteout add`) hides a STOCK path, so it has
///     no module and no plan entry;
///   * an absorbed rule was created from another module's bind, whose source can
///     sit anywhere in that module -- including where the plan walk never goes.
///
/// Reload's prune pass exempts exactly these, so a rule it would keep is not one
/// doctor may call unexplained. Virtual dirs are the engine materialising a
/// parent for a rule, never a rule in their own right.
///
/// When either durable list cannot be READ, no extras are reported at all: the
/// alternative is naming every whiteout and every absorbed rule on the device as
/// unaccounted-for, which is the same collapse-an-error-into-an-empty-set that
/// reload refuses by hand.
fn reconcile_plan_and_live(
    plan: &[PlanEntry],
    live: &[LiveRule],
    durable: Option<&HashSet<PathBuf>>,
    absorbed: Option<&HashSet<PathBuf>>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    // Only the two kinds that become rules. A my_* bind is a real mount, tracked
    // in binds.list, and produces no engine rule at all.
    let planned: HashMap<&Path, &PlanEntry> = plan
        .iter()
        .filter(|e| e.kind != PlanKind::Bind)
        .map(|e| (e.target.as_path(), e))
        .collect();
    let global: HashMap<&Path, &LiveRule> = live
        .iter()
        .filter(|r| r.uid == 0 && r.kind != crate::nm::LiveKind::VirtualDir)
        .map(|r| (r.target.as_path(), r))
        .collect();

    // Planned but not live, or live with the wrong source/kind. Either way the
    // module's file is not being served the way the plan says it is.
    let mut missing: Vec<String> = Vec::new();
    let mut wrong: Vec<String> = Vec::new();
    for (t, e) in &planned {
        match global.get(t) {
            None => missing.push(format!("{} (from {})", t.display(), e.module)),
            Some(r) => {
                let agrees = match (e.kind, r.kind) {
                    (PlanKind::Inject, crate::nm::LiveKind::Inject) => {
                        r.source.as_deref() == Some(e.source.as_path())
                    }
                    (PlanKind::Whiteout, crate::nm::LiveKind::Whiteout) => true,
                    _ => false,
                };
                if !agrees {
                    wrong.push(format!(
                        "{} (plan: {} from {}; live: {})",
                        t.display(),
                        match e.kind {
                            PlanKind::Whiteout => "whiteout".to_string(),
                            _ => e.source.display().to_string(),
                        },
                        e.module,
                        match (&r.kind, &r.source) {
                            (crate::nm::LiveKind::Inject, Some(s)) => s.display().to_string(),
                            (k, _) => format!("{k:?}"),
                        }
                    ));
                }
            }
        }
    }

    // Live and unexplained. A failure to READ either exemption list means the
    // question cannot be answered, not that the answer is "all of them".
    let extra: Option<Vec<String>> = match (durable, absorbed) {
        (Some(d), Some(a)) => Some(
            global
                .iter()
                .filter(|(t, _)| {
                    !planned.contains_key(*t) && !d.contains(**t) && !a.contains(**t)
                })
                .map(|(t, r)| match (&r.kind, &r.source) {
                    (crate::nm::LiveKind::Inject, Some(s)) => {
                        format!("{} -> {}", t.display(), s.display())
                    }
                    _ => format!("{} (whiteout)", t.display()),
                })
                .collect(),
        ),
        _ => None,
    };

    // Three lists, three findings, each naming a handful. A device where the plan
    // and the engine have genuinely diverged can diverge by hundreds of rules, and
    // one line each is what keeps this from burying every other finding.
    let name = |v: &[String]| -> String {
        let shown: Vec<&str> = v.iter().take(5).map(String::as_str).collect();
        let more = v.len().saturating_sub(shown.len());
        format!(
            "{}{}",
            shown.join(", "),
            if more > 0 { format!(", and {more} more") } else { String::new() }
        )
    };
    if !missing.is_empty() {
        missing.sort();
        out.push(Finding {
            level: Level::Warn,
            check: "planned rule not live",
            detail: format!(
                "{} rule(s) the plan describes are not in the engine, so those files are NOT \
                 being served -- the stock ROM version is what apps see. Run `nomount reload`; \
                 if they do not come back, the add failed. {}",
                missing.len(),
                name(&missing)
            ),
        });
    }
    if !wrong.is_empty() {
        wrong.sort();
        out.push(Finding {
            level: Level::Error,
            check: "live rule disagrees with the plan",
            detail: format!(
                "{} live rule(s) name a different source or kind than the plan resolves for the \
                 same path, so the content being served is not the content the module set \
                 implies. Run `nomount reload`. {}",
                wrong.len(),
                name(&wrong)
            ),
        });
    }
    match extra {
        Some(mut e) if !e.is_empty() => {
            e.sort();
            out.push(Finding {
                level: Level::Warn,
                check: "live rule the plan cannot account for",
                detail: format!(
                    "{} rule(s) are live that no enabled module, durable whiteout or absorbed \
                     mount explains -- a hand-written `nomount vfs add`, or a leftover from a \
                     module removed without a reload. `nomount reload` prunes them. {}",
                    e.len(),
                    name(&e)
                ),
            });
        }
        None => {
            out.push(Finding {
                level: Level::Info,
                check: "live rules not fully accounted for",
                detail: "the durable whiteout list or the absorbed-rule record could not be \
                         read, so live rules were checked for missing entries only -- an extra \
                         rule would not have been reported."
                    .to_string(),
            });
        }
        _ => {}
    }
    out
}


/// One `.replace` marker or opaque dir expands into a whiteout per stock entry the
/// module does not ship (see `mount::expand_replacement`), so a single marker can
/// be responsible for a great many rules. Group them by the marker that produced
/// them: every whiteout from one expansion carries that marker as its `source`,
/// while a 0:0 char device is its own source and so always counts 1.
fn expansions_by_marker(plan: &[PlanEntry]) -> Vec<(&Path, &str, usize)> {
    let mut by: HashMap<&Path, (&str, usize)> = HashMap::new();
    for e in plan.iter().filter(|e| e.kind == PlanKind::Whiteout) {
        let slot = by.entry(e.source.as_path()).or_insert((e.module.as_str(), 0));
        slot.1 += 1;
    }
    let mut v: Vec<(&Path, &str, usize)> =
        by.into_iter().map(|(m, (module, n))| (m, module, n)).collect();
    // Widest first, and by path for a stable order when counts tie.
    v.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(b.0)));
    v
}

/// Report threshold for one marker's expansion.
///
/// Deliberately a REPORT and not a cap. Refusing to expand past some N would leave
/// the module looking applied while the stock entries past the cutoff still showed
/// through -- silent truncation, which is the failure this project refuses to ship
/// elsewhere. So the count is surfaced and the expansion happens in full.
///
/// The numbers are calibrated against a stock OP15, which runs ~258 rules total:
/// `.replace` on `/system/app` is 15 entries, on `/product/app` 75, but a FLAT
/// directory is the pathological case -- `/system/fonts` is 224 and
/// `/product/overlay` 217, either of which would roughly double the rule count
/// from a single marker.
fn expansion_level(count: usize) -> Option<Level> {
    match count {
        0..=49 => None,
        50..=199 => Some(Level::Info),
        _ => Some(Level::Warn),
    }
}

/// A way a module can be incompatible with this environment, and why.
///
/// One scanner for three findings that share a shape: something the module's
/// own scripts do that cannot work here, where the failure is silent. Silence
/// is the whole problem -- a module that copies into /system gets no error, it
/// just carries on believing it worked, and the user is left with a feature
/// that does nothing and no way to know why.
///
/// Measured across 576 real module payloads to size each one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Incompat {
    /// Writes into a ROM partition at runtime. 5.9% of the corpus.
    RomWrite,
    /// Reads through Magisk's mirror. 23% of the corpus mentions it.
    ///
    /// NOT a NoMount limitation, and the finding says so: there is no mirror on
    /// KernelSU at all -- no `/sbin/.magisk`, no `magisk` binary -- so these
    /// modules read nothing on a KSU device with or without NoMount. Reported
    /// because the user still ends up with a module that silently does nothing,
    /// and nothing else on the device will tell them why.
    MagiskMirror,
    /// Loop-mounts an image or runs a chroot. 6.2% of the corpus.
    ///
    /// No redirection can make a block device appear, so this is not something
    /// the VFS engine will ever serve. The module keeps its own mount and the
    /// device section's mount checks report it honestly -- the point of naming it
    /// here is that the mount is then explained rather than anonymous.
    ImageBacked,
    /// Bind-mounts its own content over a ROM path. 28 bind-only + 22 mixed of
    /// the 576-payload corpus -- the single largest mount-creating family, and
    /// the one absorb exists for.
    ///
    /// The ONLY kind here that resolves itself: absorb re-serves the content as
    /// an injection and unmounts the original, four times a boot. So this is not
    /// a hazard and not a silent failure -- it is the answer to "why did a mount
    /// exist for part of my boot", and the list of modules that depend on absorb
    /// working. If absorb is ever disabled or times out, these are exactly the
    /// ones that leak a mount.
    ///
    /// Measured 2026-09-05: it is invisible at plan time by construction, because
    /// `plan` reads the LIVE mount table and a module that has not run yet has
    /// no mount to see. Reading the module's own scripts is the only way to say
    /// it BEFORE the mount happens.
    SelfMount,
}

impl Incompat {
    /// How loud this kind is, and why they are not all the same.
    ///
    /// Not "can the user fix it" — none of the three is fixable in NoMount and the
    /// only lever for any of them is to remove the module. The axis is whether the
    /// finding CONTRADICTS what the user believes they have: a ROM write that goes
    /// nowhere and a Magisk-mirror read that returns nothing both mean the module
    /// silently is not doing its job, and nothing else on the device will say so.
    /// An image-backed module does its job; it just keeps a mount, which the device
    /// section reports on its own. Explaining that mount is a standing observation
    /// about a working configuration, which is `Note`, not a hazard, which is
    /// `Warn`.
    fn level(self) -> Level {
        match self {
            Incompat::RomWrite | Incompat::MagiskMirror => Level::Warn,
            // SelfMount is the mildest of the four: absorb undoes it every boot,
            // so unlike ImageBacked the mount does not even persist. An
            // observation about a working configuration.
            Incompat::ImageBacked | Incompat::SelfMount => Level::Info,
        }
    }

    fn check(self) -> &'static str {
        match self {
            Incompat::RomWrite => "writes into a ROM partition",
            Incompat::MagiskMirror => "needs Magisk's mirror",
            Incompat::ImageBacked => "image-backed or chroot module",
            Incompat::SelfMount => "bind-mounts its own content",
        }
    }

    fn explain(self) -> &'static str {
        match self {
            Incompat::RomWrite =>
                "NoMount serves ROM paths by read-only redirection, so this write goes \
                 nowhere the module can read back and will fail silently. Expect that \
                 feature of the module not to work.",
            Incompat::MagiskMirror =>
                "there is no Magisk mirror on KernelSU -- no /sbin/.magisk and no magisk \
                 binary -- so this read returns nothing, with or without NoMount. This is \
                 a Magisk-only module running on KSU, not something NoMount broke.",
            Incompat::ImageBacked =>
                "no path redirection can make a block device appear, so the engine cannot \
                 serve this. The module keeps its own mount; the mount checks will report \
                 it, and that report is correct rather than a leak.",
            // `\` continuations, NOT `\n` escapes. Every arm here is one LINE in
            // the report -- check.rs renders it as `       measured: <detail>` --
            // and this arm shipped with five literal `\n` in it, so it printed a
            // five-line blob with seventeen spaces of indent on each continuation
            // while every other finding stayed on one line. The other three arms
            // above use the continuation form; a test now pins it for all of them.
            Incompat::SelfMount =>
                "this module mounts its own content over a ROM path instead of shipping a \
                 tree, so for part of every boot the mount is real and readable by any app. \
                 absorb re-serves it as an injection and unmounts it -- automatically, four \
                 times per boot -- so nothing needs doing. Named here because the module \
                 depends on absorb running: if absorb is disabled or times out, this is one \
                 of the mounts that stays visible.",
        }
    }
}

/// Scan enabled modules' scripts for the three incompatibilities above.
///
/// Deliberately narrow, because the obvious patterns over-count badly and were
/// measured doing so:
///
///   * `$MODPATH/system/...` is how 56% of modules build their payload and is
///     completely fine. The ROM-write match therefore requires whitespace before
///     the leading slash, which `$MODPATH/system/` cannot satisfy.
///   * `mount -o rw,remount $MAGISKTMP` remounts the module's OWN tmpfs, not a
///     ROM partition -- nine corpus modules do it. The remount arm requires the
///     target to name a partition.
///   * Merely assigning `MAGISKTMP=` is boilerplate; 50 of 182 corpus matches
///     never path into the mirror at all. The mirror arm requires a path
///     component after it.
///
/// One finding per (module, kind), not one per line.
/// Variables a script assigns a ROM path to, so a bind THROUGH one is visible.
///
/// Measured 2026-09-05 on Re-Malwack (445 stars), the flagship self-mounter:
///
///     system_hosts="/system/etc/hosts"              (rmlwk.sh:17)
///     mount --bind "$hosts_file" "$system_hosts"    (rmlwk.sh:562)
///
/// A line-only classifier sees no ROM path on the mount line and says nothing --
/// which is exactly how the most common absorb-relevant module shape in the
/// corpus stayed invisible. bindhosts writes the destination literally
/// (`mount --bind "$MODDIR/system/etc/hosts" /system/etc/hosts`) and was already
/// caught, so both shapes are real and the lint has to handle both.
///
/// Deliberately trivial, for the same reason every arm above is: the value must
/// START with a ROM partition path and nested variables are not expanded. This is
/// not a shell interpreter, and each previous attempt to be clever here
/// over-counted.
fn rom_path_vars(script: &str) -> std::collections::HashMap<String, String> {
    // The ONE list, shared with pmcache. It used to be five names here and five
    // more in the caller, both matched as `/{p}/` -- and `/my_product/` does not
    // contain `/product/`, so every `my_*` partition was invisible to this whole
    // chain on the ROM family the project targets. See pmcache::ROM_PARTITIONS.
    const PARTS: &[&str] = crate::pmcache::ROM_PARTITIONS;
    let mut out = std::collections::HashMap::new();
    for line in script.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let Some(eq) = t.find('=') else { continue };
        let name = &t[..eq];
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let val = t[eq + 1..].trim().trim_matches(['"', '\'']);
        if PARTS.iter().any(|p| val.starts_with(&format!("/{p}/"))) {
            out.insert(name.to_string(), val.to_string());
        }
    }
    out
}

/// Substitute `$NAME` / `${NAME}` for the ROM paths [`rom_path_vars`] found.
///
/// Longest name first: with `hosts` and `hosts_file` both known, replacing
/// `$hosts` first would leave `_file` dangling and corrupt the path it is about
/// to be matched on.
fn expand_rom_vars(line: &str, vars: &std::collections::HashMap<String, String>) -> String {
    let mut names: Vec<&String> = vars.keys().collect();
    names.sort_by_key(|n| std::cmp::Reverse(n.len()));
    let mut acc = line.to_string();
    for n in names {
        let v = &vars[n];
        acc = acc.replace(&format!("${{{n}}}"), v).replace(&format!("${n}"), v);
    }
    acc
}

/// Which incompatibility, if any, ONE line of a module script announces.
///
/// Pure, and split out of [`scan_module_incompat`] so it can be tested: that
/// function walks `/data/adb/modules`, so every precision fix in here -- and this
/// chain is almost entirely precision fixes -- was previously only verifiable by
/// installing a module and reading the report.
fn classify_incompat_line(t: &str) -> Option<Incompat> {
    // The ONE list, shared with pmcache. It used to be five names here and five
    // more in the caller, both matched as `/{p}/` -- and `/my_product/` does not
    // contain `/product/`, so every `my_*` partition was invisible to this whole
    // chain on the ROM family the project targets. See pmcache::ROM_PARTITIONS.
    const PARTS: &[&str] = crate::pmcache::ROM_PARTITIONS;
    // A capability PROBE is not a use.
    //
    // Reported from a OnePlus CPH2649 running v1.3.122: AutoSystemBoost was named
    // an "image-backed or chroot module" and the evidence quoted was
    // `if command -v nsenter >/dev/null 2>&1`, which ASKS WHETHER the tool exists
    // and does not run it.
    //
    // The VERDICT was right and only the EVIDENCE was wrong, which is worth being
    // precise about: that probe is the first half of a two-line condition, and
    // service.sh:503 continues `&& nsenter -t 1 -m -- mount --bind ...`. The module
    // really does bind-mount inside PID 1's namespace -- the case absorb.rs calls
    // one we "cannot see or unmount (replicated with nsenter)". Because only the
    // FIRST match per module is reported, quoting the guard made a true finding
    // read as a false one. After this fix the same module is still flagged, on
    // line 503. Do not "fix" that warning away.
    //
    // Same over-matching this chain already learned twice, once for
    // `MIRROR=$MAGISKTMP/mirror` boilerplate (50 of 182 corpus matches) and once
    // for `rm ` inside `set_perm`. `chroot `, `proot ` and `unshare ` carry a
    // trailing space for the same reason; `nsenter` and `losetup` are matched bare
    // and so had no defence.
    //
    // The probe expression is REMOVED rather than the line skipped, so a line that
    // probes and then uses the tool still counts as a use.
    let probeless = {
        let mut acc = t.to_string();
        for pfx in ["command -v ", "command -V ", "which ", "type -p ", "hash "] {
            while let Some(at) = acc.find(pfx) {
                let rest = &acc[at + pfx.len()..];
                let cut = rest.find(char::is_whitespace).unwrap_or(rest.len());
                acc = format!("{}{}", &acc[..at], &rest[cut..]);
            }
        }
        acc
    };
    // The ROM path must be the DESTINATION. `cp /system/etc/hosts
    // $MODPATH/system/etc/hosts` reads a stock file to seed a module
    // copy -- the standard opening move of every hosts module -- and
    // reporting that as a write told the user their module would not
    // work when nothing was wrong. Require that no `$MODPATH`/`$MODDIR`
    // destination follows the ROM path on the line.
    // `cp SRC DST`: the ROM path is a WRITE only when it is the DESTINATION.
    //
    // This used to ask "is `$MODPATH`/`$MODDIR` mentioned after the ROM path",
    // which recognises `cp /system/etc/hosts $MODPATH/...` and nothing else. It
    // misses every other place a module copies ROM content TO, and measured over
    // the 116 most-starred modules that cost a false positive: HyperUnlocked runs
    //
    //     su -c "cp -r ${DEFAULT_XMLDIR}/* $RESDIR/bakxml/"
    //
    // with `DEFAULT_XMLDIR=/system/system/etc/device_features` and
    // `RESDIR=/data/adb/HyperUnlocked` -- a BACKUP out of the ROM into /data,
    // reported as a write into a ROM partition. (It only became visible at all
    // once the classifier started resolving ROM-path variables; the blind spot
    // predates that and the expansion widened it.)
    //
    // The destination of a copy is its LAST path-shaped argument, so ask that
    // directly: if the final `/`- or `$`-leading token is not itself a ROM path,
    // the ROM path on the line was being read.
    let last_path_tok = t
        .replace(['"', '\''], " ")
        .split_whitespace()
        .rfind(|w| w.starts_with('/') || w.starts_with('$'))
        .map(str::to_string);
    let rom_is_source = match &last_path_tok {
        Some(dst) => !PARTS.iter().any(|p| dst.starts_with(&format!("/{p}/"))),
        // No path-shaped token at all: nothing to call a destination.
        None => false,
    };
    // `rm` needs BOTH spellings, and only `rm` does.
    //
    // It was `" rm "` alone, with spaces rather than the bare `"rm "` the other
    // four verbs use, because `"rm "` is a substring of `"perm "` and
    // `set_perm /system/bin/foo 0 0 0755` matched it. That reasoning is right and
    // is still pinned below -- but `t` is TRIMMED before it gets here, so a line
    // that simply BEGINS with `rm` carries no leading space and was invisible.
    // Measured: `rm -rf /system/app/Foo` classified as None, while the same
    // command behind `su -c` was correctly a RomWrite. Deleting ROM content is
    // the loudest thing in this arm, and the commonest way to write it is at the
    // start of a line.
    //
    // `starts_with`, not a second `contains`: anchoring at the start cannot
    // reintroduce the `perm ` match, since a line beginning with `perm ` is not
    // one beginning with `rm `.
    let removes = t.starts_with("rm ") || t.contains(" rm ");
    if ((removes || ["cp ", "mv ", "ln ", "touch "].iter().any(|v| t.contains(v)))
        && !rom_is_source
        && PARTS.iter().any(|p| t.contains(&format!(" /{p}/"))))
        || (t.contains("remount")
            && PARTS.iter().any(|p| {
                t.contains(&format!(" /{p} ")) || t.ends_with(&format!(" /{p}"))
            }))
    {
        Some(Incompat::RomWrite)
    // A path component after /mirror, matching what the doc above
    // claims. `MIRROR=$MAGISKTMP/mirror` on its own is boilerplate --
    // 50 of 182 corpus matches were exactly that and never read
    // through it.
    } else if t.contains(".magisk/mirror/")
        || (t.contains("MAGISKTMP") && t.contains("/mirror/"))
        || t.contains("mirror/system")
        || t.contains("mirror/vendor")
    {
        Some(Incompat::MagiskMirror)
    // `probeless`, not `t`: see the note on it above. Every token here is matched
    // against the line with any `command -v X` / `which X` / `type -p X` / `hash X`
    // removed, so asking whether a tool exists no longer reads as using it.
    } else if probeless.contains("losetup")
        || probeless.contains("mount -o loop")
        || probeless.contains("mkfs.ext4")
        || probeless.contains("chroot ")
        || probeless.contains("proot ")
        || probeless.contains("nsenter")
        || probeless.contains("unshare ")
    {
        Some(Incompat::ImageBacked)
    // AFTER ImageBacked, deliberately. `nsenter -t 1 -m -- mount --bind ...` is
    // both a bind AND a namespace replication, and the namespace half is the
    // worse news: absorb says it "cannot see or unmount (replicated with
    // nsenter)". Testing bind first would have retagged AutoSystemBoost from
    // image-backed to self-mounting and quietly promised absorb would handle a
    // mount absorb has explicitly said it cannot. See the note above -- that
    // finding is not to be softened.
    //
    // Narrow, on the same evidence the arms above were narrowed on:
    //   * an explicit bind/overlay FLAG, not the word "mount". Re-Malwack's
    //     scripts carry `echo "...mount hosts..."` and `ui_print` lines with
    //     "mount" in them; matching the word alone flags prose.
    //   * a ROM partition as the DESTINATION, with a trailing slash. A module
    //     bind-mounting inside its own tree or into /data is not putting a mount
    //     over the ROM and is not absorb's business.
    //   * not `umount`: removing a mount is not making one, and every module
    //     that binds also unbinds somewhere.
    // The ROM path must start a TOKEN, not merely follow a space.
    //
    // The RomWrite arm above requires whitespace before the leading slash, to
    // stop `$MODPATH/system/` reading as a ROM write. That is right for it and
    // wrong here: a real bind quotes its destination, so after variable
    // expansion the line reads `mount --bind "$hosts_file" "/system/etc/hosts"`
    // and there is a QUOTE before the slash, not a space. Requiring a space
    // missed Re-Malwack -- the exact module this arm was added for.
    //
    // So: allow start-of-line, whitespace, `"` or `'` before it, and nothing
    // else. `$MODDIR/system/...` is still excluded, because the preceding char
    // there is `R`.
    } else if !probeless.contains("umount")
        && (probeless.contains("--bind")
            || probeless.contains("--rbind")
            || probeless.contains("-o bind")
            || probeless.contains("-o rbind")
            || probeless.contains("-t overlay"))
        && PARTS.iter().any(|p| {
            let needle = format!("/{p}/");
            probeless.match_indices(&needle).any(|(at, _)| {
                at == 0
                    || probeless[..at]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_whitespace() || c == '"' || c == '\'')
            })
        })
    {
        Some(Incompat::SelfMount)
    } else {
        None
    }
}

/// Module-local scripts an entry script pulls in, as relative paths.
///
/// The scanner reads five fixed filenames, and modules put their mount logic in
/// helpers those five source. Measured 2026-09-05 over 93 scripts in the 14
/// most-starred modules: MoveCertificate (1947 stars) runs
/// `. $MODDIR/sh/compatible.sh` from post-fs-data.sh, and ALL FOUR of its bind
/// and nsenter lines live in that file -- so the module was completely invisible
/// to all four lints, on a boot path. Re-Malwack only escaped the same fate
/// because its bind happens to be duplicated into service.sh.
///
/// Following the reference is the precise fix. Reading every `*.sh` in the module
/// instead would more than double the scan (40 -> 85 files in that corpus) and
/// pull in `uninstall.sh` and `action.sh` -- neither of which runs at boot, and
/// the first of which legitimately unmounts things.
///
/// ONE level, not transitive: bounded work, and it covers the corpus. `$MODDIR`
/// and `$MODPATH` are the two spellings modules use for their own directory;
/// anything that is not a module-relative path is ignored, so a `. /system/...`
/// cannot walk the scanner out of the module.
fn sourced_scripts(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        for kw in [". ", "source ", "sh ", "bash "] {
            let mut from = 0usize;
            while let Some(at) = t[from..].find(kw) {
                let abs = from + at;
                // Must start a word: `. $MODDIR/x` yes, `wish $MODDIR/x` no.
                if abs > 0 && !t.as_bytes()[abs - 1].is_ascii_whitespace() {
                    from = abs + kw.len();
                    continue;
                }
                // Strip the OPENING quote before reading the token, not after:
                // `sh "$MODDIR/rmlwk.sh"` is the common spelling, and stopping at
                // the first quote made the token empty and the reference invisible.
                let rest = t[abs + kw.len()..].trim_start().trim_start_matches(['"', '\'']);
                let tok: String = rest
                    .chars()
                    .take_while(|c| !c.is_whitespace() && *c != ';' && *c != '"' && *c != '\'')
                    .collect();
                let tok = tok.as_str();
                for var in ["$MODDIR/", "$MODPATH/", "${MODDIR}/", "${MODPATH}/"] {
                    if let Some(rel) = tok.strip_prefix(var) {
                        // No escaping the module directory.
                        if !rel.is_empty()
                            && !rel.contains("..")
                            && !rel.starts_with('/')
                            && !out.iter().any(|e| e == rel)
                        {
                            out.push(rel.to_string());
                        }
                    }
                }
                from = abs + kw.len();
            }
        }
    }
    out
}

/// Installed modules whose scripts write the `my_hookless` marker.
///
/// The marker switches every `my_*` target from a real bind to a hookless
/// injection, which `mount::my_hookless_enabled` documents as a TRIAL with a
/// named failure mode: a leaf my_* inject can trip zygote's FD allowlist at
/// forkSystemServer, i.e. a bootloop. The Suite never creates the file, so it is
/// either the user's decision or somebody else's.
///
/// Measured on an OP11, 2026-09-06: it was somebody else's.
/// `OnePlus_Dialer_Universal/post-fs-data.sh` does
/// `touch /data/adb/nomount/my_hookless` whenever it detects NoMount is active,
/// and re-creates it on every boot -- while that same module ships 84 files
/// across `my_product`, `my_region` and `my_stock`. Three boots failed on
/// 2026-09-01, both that module's guard and the Suite's tripped, and nothing in
/// any report connected the marker to the module that wrote it.
///
/// Cheap by construction: only the module's own `*.sh` are read, and only their
/// text is matched -- this names a candidate, it does not prove authorship.
/// Returns `(module id, the script that mentions it)`. The FILE is half the
/// answer: whether the marker comes back depends entirely on whether that script
/// is one a manager runs at boot. See [`marker_returns_when`].
fn my_hookless_writers() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/data/adb/modules") else { return out };
    let mut dirs: Vec<_> = rd.flatten().collect();
    dirs.sort_by_key(|d| d.file_name());
    for d in dirs {
        let mdir = d.path();
        let Some(id) = mdir.file_name().and_then(|n| n.to_str()) else { continue };
        if id == "meta-nomount" || !mdir.is_dir() {
            continue;
        }
        let Ok(files) = std::fs::read_dir(&mdir) else { continue };
        let mut names: Vec<_> = files.flatten().map(|f| f.path()).collect();
        names.sort();
        for p in names {
            if p.extension().and_then(|e| e.to_str()) != Some("sh") {
                continue;
            }
            if std::fs::read_to_string(&p).is_ok_and(|b| b.contains("my_hookless")) {
                let file = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("?")
                    .to_string();
                out.push((id.to_string(), file));
                break;
            }
        }
    }
    out
}

/// When a deleted `my_hookless` marker would come back.
///
/// The report used to say, flatly, "or it returns on the next boot". That is
/// true only when the script that writes it is one a MANAGER runs. Measured on
/// an OP15, 2026-09-07: the only writer there is
/// `OnePlus_Dialer_Universal/stage_overrides.sh`, whose sole caller is that
/// module's `action.sh` — the ▶ button — so deleting the marker holds until the
/// user taps it, and the advice as written was wrong about the one thing the
/// reader needs in order to act. (On an OP11 the same module writes it from
/// `post-fs-data.sh`, where the original wording was right; the two devices ran
/// different builds of it, which is exactly why this cannot be a fixed sentence.)
///
/// Pure, and keyed on [`ENTRY_SCRIPTS`], the same list that decides whether an
/// incompatibility hit is conditional.
fn marker_returns_when(files: &[String]) -> &'static str {
    if files.iter().any(|f| ENTRY_SCRIPTS.contains(&f.as_str())) {
        "it is written from a boot script, so it returns on the next boot"
    } else {
        "that is not a boot script, so it returns the next time the module runs it \
         (an action button, an update, its WebUI)"
    }
}

/// Why a module that ships ROM content is contributing nothing, or `None` if
/// there is nothing to say.
///
/// Pure, so the judgement is testable without a module tree.
///
/// `disable` and `remove` are NOT findings: the user turned the module off, and
/// content not being served is the whole point. Everything else is, because the
/// module is switched ON and its files are not reaching the ROM -- which is
/// precisely the "installed and silently not applied" state this report exists
/// to end, and it is invisible everywhere else. The WebUI's module list says
/// "skipped" in small grey text; nothing else mentions it at all.
fn unserved_reason(markers: &[String], served: bool) -> Option<&'static str> {
    if served || markers.iter().any(|m| m == "disable" || m == "remove") {
        return None;
    }
    if markers.iter().any(|m| m == "skip_mount") {
        Some("skip_mount")
    } else {
        Some("none")
    }
}

/// Files a module ships under a real ROM partition, and which partitions.
///
/// Mirrors the injector: content lives under ANY top-level directory that names
/// a partition, not just `system/`. Symlinks are not followed -- a module's
/// `system/product -> ../product` convergence link would double-count.
fn module_rom_files(mdir: &Path) -> (usize, Vec<String>) {
    let mut n = 0usize;
    let mut parts: Vec<String> = Vec::new();
    let Ok(rd) = std::fs::read_dir(mdir) else { return (0, parts) };
    for e in rd.flatten() {
        let p = e.path();
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else { continue };
        if !crate::pmcache::ROM_PARTITIONS.contains(&name) {
            continue;
        }
        if p.is_symlink() || !p.is_dir() || !Path::new("/").join(name).is_dir() {
            continue;
        }
        let c = count_files(&p, 0);
        if c > 0 {
            n += c;
            parts.push(format!("{name}({c})"));
        }
    }
    (n, parts)
}

/// Bounded recursive file count. The depth cap is the same reflex as the plan
/// walk's: a module is free to ship a pathological tree and this runs on the
/// report path.
fn count_files(dir: &Path, depth: usize) -> usize {
    if depth > 12 {
        return 0;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    let mut n = 0;
    for e in rd.flatten() {
        let p = e.path();
        if p.is_symlink() {
            // A symlink to a DIRECTORY is not shipped content, it is the
            // layout-convergence link (`system/product -> ../product`) every
            // OPlus-shaped module carries -- and `serve_mode` refuses its target
            // as a bare partition root, so nothing behind it is ever served.
            // Counting it both inflates the total and, worse, attributes the
            // count to the wrong partition.
            //
            // Measured on an OP15, 2026-09-07, with SAN (systemapp_nuker) v2.2.2
            // installed: two whiteouts under `my_stock/` and `product/`, plus the
            // two links `system/my_stock` and `system/product` that its installer
            // creates, were reported as "ships 4 file(s) under system(2)
            // my_stock(1) product(1)" -- twice the real number, and naming
            // /system, where the module ships nothing at all.
            //
            // A symlink to a FILE still counts: `plan_tree` treats it as a leaf
            // and injects it like any other entry. `is_dir()` follows the link,
            // which is exactly the question being asked; a DANGLING link answers
            // false and counts, which is right -- it is content the module meant
            // to ship, and `source_resolves` is what reports it as unservable.
            if !p.is_dir() {
                n += 1;
            }
        } else if p.is_dir() {
            n += count_files(&p, depth + 1);
        } else {
            n += 1;
        }
    }
    n
}

/// Can a live rule of this kind reach zygote's FD-allowlist trap at all?
///
/// Only an INJECT. The trap fires on an open FD whose path
/// `FileDescriptorInfo::CreateFromFd` does not allowlist, and both other kinds
/// are structurally incapable of producing one: a whiteout makes a name ABSENT,
/// so there is no fd, and a virtual dir is a directory the engine materialised,
/// which nothing preloads.
///
/// Pure and separate so the one un-gated consumer of `parse_list`'s kind cannot
/// come back. Every other arm of that loop already tests `r.kind`; this one did
/// not, and the per-partition tally it fed said "N injected file(s)" while
/// counting all three. That tally is gone now (a row ending in "fine" is not a
/// finding), but the gate still guards the Error arm below it, where a whiteout
/// on an `/overlay/*.apk` path would otherwise be reported as a boot hazard --
/// hiding a file zygote would have preloaded is the opposite of one.
fn fd_note_applies(kind: crate::nm::LiveKind) -> bool {
    kind == crate::nm::LiveKind::Inject
}

/// The five scripts a manager runs directly. Anything else the scanner reads got
/// there through a `.` from one of them.
const ENTRY_SCRIPTS: [&str; 5] = [
    "post-fs-data.sh", "service.sh", "boot-completed.sh", "post-mount.sh", "customize.sh",
];

/// The sentence to append when the evidence line lives in a SOURCED helper rather
/// than in a script the manager runs.
///
/// `sourced_scripts` follows one `.` level so a module cannot hide its mount
/// logic in a helper -- which is right, and which also means the scanner now
/// quotes lines that may sit inside a branch the entry script never takes. It
/// cannot know: deciding that needs the module's persisted config, and reading a
/// third-party config to evaluate its own conditionals is exactly the kind of
/// clever this classifier has been narrowed away from twice.
///
/// What it CAN do is stop asserting the branch was taken. Measured on an OP15,
/// 2026-09-07: SAN (systemapp_nuker) v2.2.2 installs at `mounting_mode=2`, where
/// the metamodule serves it and `post-fs-data.sh` never reaches the
/// `. $MODDIR/mountify.sh` in its `mounting_mode=1` arm -- and the report said
/// flatly that the module "mounts its own content over a ROM path" and that
/// "absorb re-serves it as an injection and unmounts it, four times per boot".
/// Neither happened, and the device measured zero foreign mounts throughout.
///
/// Pure, and keyed on the FILENAME rather than on how it was found, because that
/// is the whole distinction: the five names below are what a manager executes.
fn reached_only_if_sourced(script: &str) -> &'static str {
    if ENTRY_SCRIPTS.contains(&script) {
        return "";
    }
    " NB: this line is in a helper the module SOURCES, not in a script the manager \
     runs, so it only takes effect if the entry script reaches the `.` that pulls \
     it in -- a mode switch or a capability test can leave it dead. Check the \
     module's own config before acting on this."
}

fn scan_module_incompat() -> Vec<(String, String, Incompat, String)> {
    const SCRIPTS: [&str; 5] = ENTRY_SCRIPTS;
    let mut out: Vec<(String, String, Incompat, String)> = Vec::new();
    let Ok(dirs) = std::fs::read_dir(crate::mount::MODULES_DIR) else { return out };
    let mut dirs: Vec<_> = dirs.flatten().collect();
    dirs.sort_by_key(|e| e.file_name());

    for d in dirs {
        let mdir = d.path();
        // NOT `module_enabled`, and the difference is the whole point of this
        // scanner.
        //
        // `module_enabled` also excludes `skip_mount`, which is correct for the
        // mount pass -- it means "do not serve my tree". It is wrong here,
        // because a `skip_mount` module still RUNS EVERY ONE OF ITS SCRIPTS. And
        // shipping `skip_mount` is precisely the convention for a module that
        // mounts its own content, so this gate made the scanner blind to exactly
        // the family SelfMount was added for: measured 2026-09-05, Re-Malwack and
        // bindhosts both ship it, and both were reported clean while their
        // service.sh ran `mount --bind ... /system/etc/hosts` at every boot.
        //
        // `disable` and `remove` still count: those scripts do not run at all.
        let stood_down =
            mdir.join("disable").exists() || mdir.join("remove").exists();
        if !mdir.is_dir() || stood_down {
            continue;
        }
        let Some(id) = mdir.file_name().and_then(|n| n.to_str()).map(str::to_string) else {
            continue;
        };
        let mut seen: Vec<Incompat> = Vec::new();
        // The five entry scripts, plus whatever they pull in. Collected first so
        // a helper sourced by two entry points is read once, and reported under
        // its OWN filename -- "(sh/compatible.sh)" is where the reader has to go
        // to see the line, and naming post-fs-data.sh there would send them to a
        // file that only contains the `.` directive.
        let mut todo: Vec<String> = SCRIPTS.iter().map(|s| (*s).to_string()).collect();
        for script in SCRIPTS {
            if let Ok(body) = std::fs::read_to_string(mdir.join(script)) {
                for rel in sourced_scripts(&body) {
                    if !todo.contains(&rel) && mdir.join(&rel).is_file() {
                        todo.push(rel);
                    }
                }
            }
        }
        for script in &todo {
            let script = script.as_str();
            let Ok(body) = std::fs::read_to_string(mdir.join(script)) else { continue };
            // Per FILE, not per line: the assignment is at the top and the mount
            // that uses it is hundreds of lines below.
            let vars = rom_path_vars(&body);
            for line in body.lines() {
                let t = line.trim();
                if t.starts_with('#') || t.is_empty() {
                    continue;
                }
                // Classify the EXPANDED line, but report the line the user can
                // actually find in the file. Quoting a rewritten line would send
                // them looking for text that is not there.
                let kind = classify_incompat_line(&expand_rom_vars(t, &vars));
                if let Some(k) = kind {
                    if !seen.contains(&k) {
                        seen.push(k);
                        out.push((
                            id.clone(),
                            script.to_string(),
                            k,
                            t.chars().take(90).collect(),
                        ));
                    }
                }
            }
        }

        // A shipped filesystem image, with nothing in the scripts to match on.
        //
        // Everything above reads script TEXT, so a module that ships a prebuilt
        // rootfs and mounts it from a compiled binary, a helper the scan does not
        // read, or an init script would go unreported.
        //
        // Honest impact: ZERO modules in the 576-payload corpus need this. The
        // single module there that ships a real .img also says `losetup` in its
        // scripts, so the text rule already had it. It was added on the strength
        // of a corpus signal that counted .tar.gz as a filesystem image, and once
        // that was corrected the case it was meant to cover evaporated.
        //
        // Kept anyway, at depth 2 rather than a full walk: doctor reading only
        // script text is a real hole in its coverage, and this closes it for
        // roughly the cost of a readdir. Delete it without hesitation if the
        // cost ever shows up -- nothing measured depends on it.
        //
        // Only if the module did not already report ImageBacked from its scripts;
        // saying it twice for one module helps nobody.
        if !seen.contains(&Incompat::ImageBacked) {
            if let Some(img) = find_shipped_image(&mdir, &mdir, 0) {
                out.push((id.clone(), "shipped file".to_string(), Incompat::ImageBacked, img));
            }
        }
    }
    out
}

/// First filesystem image found in a module tree, as a module-relative path.
///
/// Depth 2, not a full walk. A module that ships an image puts it at the top
/// level or one directory down; walking a large module tree to depth 6 on every
/// plan run costs real I/O to find nothing. Extensions only -- sniffing
/// magic bytes would mean opening every file in every module on every run.
fn find_shipped_image(
    root: &std::path::Path,
    dir: &std::path::Path,
    depth: u32,
) -> Option<String> {
    const IMG_EXT: [&str; 6] = [".img", ".img.xz", ".img.gz", ".rootfs", ".ext4", ".erofs"];
    if depth > 2 {
        return None;
    }
    let entries = std::fs::read_dir(dir).ok()?;
    let mut dirs = Vec::new();
    for e in entries.flatten() {
        let ft = match e.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        // file_type does not follow symlinks, which is what keeps a link back up
        // the tree from being descended.
        if ft.is_dir() {
            dirs.push(e.path());
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let name = e.file_name();
        let name = name.to_string_lossy().to_lowercase();
        if IMG_EXT.iter().any(|x| name.ends_with(x)) {
            // MODULE-RELATIVE, which is what the doc above promises and what
            // the reader needs. A bare `rootfs.img` gives them nowhere to look,
            // and the absolute path this used to return repeats the
            // /data/adb/modules/<id>/ prefix the finding already names.
            let p = e.path();
            return Some(p.strip_prefix(root).unwrap_or(&p).to_string_lossy().into_owned());
        }
    }
    for d in dirs {
        if let Some(found) = find_shipped_image(root, &d, depth + 1) {
            return Some(found);
        }
    }
    None
}

/// The subject a finding is ABOUT: the first token of its detail.
///
/// Every plan finding that can be emitted more than once opens its detail with
/// the thing it concerns -- a target path (`/product/app/Foo.apk <- ...`), a
/// partition (`3 injected file(s) on /my_product`), or a module (`OxygenCust: 4
/// path(s) ...`). `owner_of` already reads exactly this token for the "From:"
/// line; this reuses it as the discriminator rather than inventing a second
/// convention.
/// A COUNT is never the subject. Several details open with one -- "3 injected
/// file(s) on /my_product", "12 of 16 hidden path(s) sampled" -- and keying on it
/// produced `not-fd-allowlisted-for-zygote-83`: unique, and worthless for the one
/// thing the id is for, because it moves the moment a module gains or loses a
/// file. Measured on an OP11: two of the three repeatable plan findings took a
/// count this way. Fall through to the first PATH in the detail, which for every
/// one of them is the partition or target the finding is really about.
fn subject_of(f: &Finding) -> Option<&str> {
    // A nested fn, not a closure: a closure's inferred argument lifetime cannot
    // outlive the call, and these results are borrowed from `f.detail`.
    fn trim(t: &str) -> &str {
        t.trim_end_matches([',', ':', '.'])
    }
    fn numeric(t: &str) -> bool {
        !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit())
    }
    let head = trim(f.detail.split([' ', ':']).next().unwrap_or(""));
    if !head.is_empty() && !numeric(head) && head.len() <= 128 {
        return Some(head);
    }
    // No usable head: the first absolute path anywhere in the sentence.
    f.detail
        .split_whitespace()
        .map(trim)
        .find(|t| t.starts_with('/') && t.len() > 1 && t.len() <= 128)
}

/// Turn plan findings into checks, giving each one an id nothing else in the
/// report shares.
///
/// `slug(check)` ALONE is not unique here, and that is structural rather than
/// accidental: a plan check is emitted once per offending entity, so
/// "module mount left by design" appears once per declined mount and
/// "whiteout leaves a measurable hole" once per module. Measured on an OP11
/// running a clean setup: six plan checks, three distinct ids.
///
/// That matters because `Check::id` is documented as "what an acceptance would be
/// keyed on and what the WebUI uses for element ids" -- and the WebUI renders
/// `id="chk-<id>"`, so duplicates put repeated ids in the DOM and make its own
/// `findCheck` lookup return whichever row happens to be first. `audit.rs` has a
/// test asserting exactly this property for the device checks, whose comment
/// warns that "an acceptance keyed on that id would have silenced them all at
/// once". The plan side had no such guarantee and could not have satisfied one.
///
/// The subject is the discriminator, and the counter after it is the backstop:
/// two findings of one check about one subject cannot happen today (each loop is
/// keyed by the entity), but an id that is unique only by argument is the kind
/// that stops being unique later without anyone noticing.
fn to_checks(findings: Vec<Finding>) -> Vec<Check> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    findings
        .into_iter()
        .map(|x| {
            let owner = owner_of(&x);
            let base = match subject_of(&x) {
                Some(s) => format!("{}-{}", slug(x.check), slug(s)),
                None => slug(x.check),
            };
            let n = seen.entry(base.clone()).or_insert(0);
            *n += 1;
            let id = if *n == 1 { base } else { format!("{base}-{n}") };
            // `meaning` and `evidence` carry the same string on purpose: the
            // detail texts in this file were rewritten to BE the reader-facing
            // sentence when the three cards collapsed into one list, so there is
            // no second sentence to invent. A future plan check with separate
            // evidence has somewhere to put it.
            let mut c = Check::new(
                Section::Plan,
                id,
                x.check,
                verdict_of(&x.level),
                x.detail.clone(),
            )
            .meaning(x.detail);
            if let Some(o) = owner {
                c = c.owner(o);
            }
            c
        })
        .collect()
}

/// Every plan-side check, plus the counts the report carries as facts.
///
/// Returns rather than prints. It used to render its own header line, its own
/// prose list, its own summary and its own JSON document -- and the header was
/// the only place the plan and the live rule list ever met (see
/// [`reconcile_plan_and_live`], which is what that meeting should have been).
pub fn plan_checks() -> Result<(Vec<Check>, Vec<crate::check::Fact>)> {
    // partition -> count of non-overlay entries not in zygote's FD allowlist
    let mut f: Vec<Finding> = Vec::new();
    let (plan, skipped) = collect_plan()?;

    // ---- plan-level checks -------------------------------------------------
    let mut by_target: HashMap<&Path, Vec<&str>> = HashMap::new();
    let mut holes: HashMap<&str, Vec<&Path>> = HashMap::new();
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
        // Collected, not emitted here: one `.replace` can expand into hundreds of
        // whiteouts, and a line each buried every other finding under its own output
        // (236 informational lines on a single probe). Grouped per module below.
        if e.kind == PlanKind::Whiteout && crate::mount::whiteout_leaves_hole(&e.target) {
            holes.entry(e.module.as_str()).or_default().push(e.target.as_path());
        }

        if e.kind == PlanKind::Inject {
            // Backing gone (module updated/removed underneath us) -> rule serves nothing.
            // `exists()` follows symlinks, so a DANGLING symlink lands here too — and
            // reporting that as "source missing" sends the reader to a path that is
            // plainly there in `ls`. Injection resolves a symlink to its target, so a
            // link with no target yields no rule at all: the plan resolves the
            // entry and `reload` counts it, then the path simply never appears.
            // Name which of the two it is, because the fixes differ.
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

    // A target whose first two segments repeat a partition name -- /product/product,
    // /system/system -- is not something a module can mean. It comes from the
    // installer's partition handler moving `system/product` INTO an already-existing
    // top-level `product/` instead of merging the two, which nests the subtree one
    // level too deep. The rule that results serves real bytes at a directory the ROM
    // does not have, which is both wrong and a free existence oracle, and nothing
    // downstream notices because every individual rule looks healthy.
    //
    // Measured on an OP15: a module shipping BOTH `product/` and `system/product/`
    // produced `/product/product/etc/...` and doctor reported zero errors. A module
    // shipping only `system/product/` resolves correctly, so the trigger is the
    // collision, not the SAR alias.
    let mut nested: Vec<(&Path, &str)> = Vec::new();
    for e in &plan {
        let mut segs = e.target.components().skip(1).filter_map(|c| c.as_os_str().to_str());
        // `a == b` is the whole test. The second half used to be
        // `is_partition_root(Path::new(&format!("/{a}")))`, which reads as a device
        // check and is a tautology -- `a` is one component, so that call is
        // `count() <= 1` on a one-component path. See the same note in
        // `mount::serve_mode`, which carried the identical dead conjunct.
        if let (Some(a), Some(b)) = (segs.next(), segs.next()) {
            if a == b {
                nested.push((e.target.as_path(), e.module.as_str()));
            }
        }
    }
    nested.sort_by_key(|(t, _)| *t);
    for (target, module) in &nested {
        f.push(Finding {
            level: Level::Error,
            check: "partition name nested",
            detail: format!(
                "{} <- {module}: the path repeats a partition name, so this is serving \
                 content at a directory the ROM does not have. It happens when a module \
                 ships both `product/` and `system/product/` and the installer nests one \
                 inside the other -- ship only one of the two.",
                target.display()
            ),
        });
    }

    // A directory whose every entry is injected is its own detection oracle.
    //
    // Injected files carry inode numbers from a band the ROM never allocates
    // from. In a directory that also holds stock files that is harmless -- the
    // stock inodes are camouflage. In a directory the module invented, every
    // inode is in the injected band, so bucketing that directory by inode range
    // yields one bucket that is entirely ours and names every file in it.
    //
    // The device section already measures this, but only after the fact, on a
    // device that has already booted with the module. Saying it here means the user learns
    // at install time, when moving the files into an existing directory is still
    // an easy change.
    //
    // The stock/injected test works whether or not the engine is live: with
    // rules applied, read_dir returns the synthesised listing (ours only, if the
    // directory is wholly new); without them it returns the stock listing, or
    // fails outright when the directory does not exist yet. In every case, "no
    // entry here that is not one of ours" is the question worth asking.
    let served: Vec<&Path> = plan
        .iter()
        .filter(|e| e.kind != PlanKind::Whiteout) // whiteouts hide, they materialise nothing
        .map(|e| e.target.as_path())
        .collect();

    // Every path we serve, plus every directory on the way down to one. Built
    // once so the "is this entry ours" test is a hash lookup rather than a scan
    // of the whole plan -- the scan made this check quadratic in plan size on a
    // path that runs under `timeout 30` at boot.
    let ours_set: std::collections::HashSet<&Path> = served
        .iter()
        .flat_map(|t| t.ancestors())
        .collect();

    // Is this path one we serve, or a directory on the way down to one? A
    // sub-DIRECTORY that only holds injections is not stock camouflage, and
    // treating it as one is what made a first cut miss `/system/etc/nmt`
    // entirely: it saw the `nested/` child, did not recognise it as ours, and
    // called the directory mixed.
    let ours = |p: &Path| ours_set.contains(p);

    // An APK has to live in a directory of its own -- that is the layout
    // PackageManager requires, and stock `/system/priv-app/Mms` holds nothing
    // but `Mms.apk` either. Flagging those would be advice with no available
    // remedy, so they are deliberately not reported.
    // The whole codePath, not just the directory holding the .apk.
    //
    // An app's native libraries live at <codePath>/lib/<abi>, which is two levels
    // below priv-app, and PackageManager decides that layout -- the module has no
    // more choice about it than it has about the .apk's own directory. Measured on
    // an OP11: all 29 rules under /product/priv-app/Mms are served --public,
    // because mount.rs already treats the codePath as one unit for the public
    // flag. Checking only the immediate parent flagged Mms/lib/arm64 and left a
    // warning nobody could act on.
    let is_apk_container = |p: &Path| {
        p.ancestors().any(|a| {
            a.parent().and_then(|g| g.file_name()).is_some_and(|n| {
                matches!(n.to_str(), Some("app" | "priv-app" | "overlay" | "framework"))
            })
        })
    };

    // Bucket by parent FIRST. The stock test is a property of the directory, so
    // doing it per plan entry repeated the same readdir once per file in it.
    let mut by_parent: HashMap<&Path, (Vec<String>, usize)> = HashMap::new();
    for e in &plan {
        if e.kind == PlanKind::Whiteout {
            continue;
        }
        let Some(parent) = e.target.parent() else { continue };
        if is_partition_root(parent) || parent.parent().is_none() || is_apk_container(parent) {
            continue;
        }
        let slot = by_parent.entry(parent).or_insert((Vec::new(), 0));
        slot.0.push(e.module.clone());
        slot.1 += 1;
    }

    let mut invented: HashMap<PathBuf, (Vec<String>, usize)> = HashMap::new();
    for (parent, slot) in by_parent {
        let has_stock = match fs::read_dir(parent) {
            Ok(rd) => rd.flatten().any(|d| !ours(&parent.join(d.file_name()))),
            // Does not exist yet: once the pass runs, nothing but ours is in it.
            Err(_) => false,
        };
        if has_stock {
            continue;
        }
        invented.insert(parent.to_path_buf(), slot);
    }

    // Report the SHALLOWEST invented directory of a chain. A module shipping
    // `etc/foo/bar/baz/x` invents four directories, and naming all four says the
    // same thing four times -- the actionable unit is the top of the new subtree.
    // One injected file in a directory is not an inode BAND -- it is one inode,
    // and a single number cannot be grouped against anything.
    //
    // This matters because the common shape is not an invented directory, it is a
    // SHADOWED one: OnePlus_Dialer_Universal replaces the single stock file in each
    // of 80 country directories under /my_product/etc/extension. Stock has one file
    // there, the module serves one file there, and the directory looks exactly as
    // the ROM shipped it. Reporting that as "holds only injected files" is true by
    // the letter and useless: there is nothing to bucket, the module has no other
    // layout available, and the measured inode-band check declines the case
    // ("no directory with both enough injections and a stock population to
    // compare") -- so the finding cited a measurement that does not apply to it.
    //
    // Threshold matches what the oracle actually needs: the harness directory it
    // did fire on had 3 injected inodes alone in a band, with no stock there.
    invented.retain(|_, (_, n)| *n > 1);

    let invented_dirs: std::collections::HashSet<PathBuf> = invented.keys().cloned().collect();
    let mut rolled: Vec<(PathBuf, Vec<String>, usize)> = invented
        .into_iter()
        // Every ancestor, not just the immediate parent: a chain like
        // `nmt/nested/deep/a/b` has intermediate levels that hold no file of
        // their own, so they never enter the map and checking one level up
        // finds no ancestor to roll into.
        .filter(|(p, _)| !p.ancestors().skip(1).any(|a| invented_dirs.contains(a)))
        .map(|(p, (mods, n))| {
            // Count everything served underneath, not just the immediate level,
            // so a rolled-up chain reports the size of the whole subtree.
            let total = served.iter().filter(|t| t.starts_with(&p)).count();
            let mut m = mods;
            m.sort_unstable();
            m.dedup();
            (p, m, total.max(n))
        })
        .collect();
    rolled.sort_by(|a, b| a.0.cmp(&b.0));

    if !rolled.is_empty() {
        // One finding, not one per directory. The explanation is the same every
        // time and repeating it buries the list it is about.
        // Group by owning module before listing anything.
        //
        // Listing every directory reads fine on a handful and is unusable on a
        // real device: measured on an OP15, OnePlus_Dialer_Universal ships one
        // country-config file into each of 82 sibling directories under
        // /my_product/etc/extension, and naming them individually produced a
        // 6042-character finding that says the same thing 82 times. The module
        // is the actionable unit -- there is one decision to make about it, not
        // 82 -- so a module with more than a few directories is reported as its
        // common prefix and a count.
        // Key on (module, PARENT of the flagged directory), not on the module
        // alone. A module that owns 78 country dirs under one parent and three
        // more elsewhere has a longest-common-ancestor of "/", and "81
        // directories under /" tells the reader nothing. Clustering by parent
        // names the subtree each group actually sits in.
        let mut by_mod: HashMap<String, Vec<(&Path, usize)>> = HashMap::new();
        for (p, m, n) in &rolled {
            let parent = p.parent().unwrap_or(Path::new("/")).display();
            by_mod
                .entry(format!("{} under {}", m.join(", "), parent))
                .or_default()
                .push((p.as_path(), *n));
        }
        let mut groups: Vec<(String, Vec<(&Path, usize)>)> = by_mod.into_iter().collect();
        groups.sort_by(|a, b| a.0.cmp(&b.0));

        let list = groups
            .iter()
            .map(|(mods, dirs)| {
                let files: usize = dirs.iter().map(|(_, n)| n).sum();
                if dirs.len() <= 3 {
                    let names = dirs
                        .iter()
                        .map(|(p, n)| format!("{} ({n} file(s))", p.display()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("{mods}: {names}")
                } else {
                    // No common-ancestor walk here: the group key already carries
                    // the parent, so computing one was dead work.
                    format!("{mods}: {} directories ({files} file(s) total)", dirs.len())
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        // Info, not Warn. Creating a new directory under a ROM partition is one
        // of the commonest module shapes there is, and this fires on every one of
        // them -- a warning that common trains people to skip warnings. The
        // measured "injected inode band" check covers the same ground and now
        // passes correctly when a directory has no stock population to compare
        // against; inferring the hazard from directory SHAPE on top of that is the
        // infer-do-not-measure habit this tree deleted preflight.rs for.
        //
        // The partition-range assertion this used to make is also unsupported.
        // Measured on a 6.1 device against every regular file under /system (2,801
        // of them): stock inodes span 363..24,593,024 and 25 of our 27 sat inside
        // it, the two outliers 0.4% and 2.5% above the maximum -- and that maximum
        // is a floor, since directories and symlinks were not counted.
        f.push(Finding {
            level: Level::Info,
            check: "directory holds only injected files",
            // Two sentences. The oracle is what the reader needs -- a directory
            // of only-injected inodes clusters into a band the ROM never
            // allocates from -- and the caveats (how it compares against the
            // whole partition, which directories are excluded) are in the
            // comment above, where the next maintainer will look for them.
            detail: format!(
                "{list}. Injected files take inode numbers from a band the ROM never \
                 allocates, so a directory holding several of them and no stock file is \
                 one cluster that is entirely yours. Ship into a directory that already \
                 has stock content and it disappears."
            ),
        });
    }

    // Modules that cannot work here, named before the user goes hunting.
    //
    // All three fail SILENTLY today: the write lands nowhere, the mirror read
    // returns nothing, the image mount is simply a mount the engine never touches.
    // Each is shipped as a finding well before any attempt to support it, because
    // a wrong answer the user can see beats a wrong answer they cannot.
    //
    // The LEVEL is per kind, and the axis is not "can the user fix it" -- none of
    // the three is fixable in NoMount, and the only lever for any of them is to
    // remove the module. It is "does this change what the user believes about
    // their setup":
    //
    //   RomWrite     -- the feature they installed the module FOR does not work.
    //   MagiskMirror -- the module does nothing at all on KernelSU.
    //
    // Both contradict what the user thinks they have, so both stay loud. An
    // ImageBacked module, by contrast, works exactly as intended; the only trace
    // is a mount, and the device section's mount checks ALREADY report that mount
    // independently. So the finding explains a mount rather than breaking news --
    // `Verdict::Note`'s definition word for word, "worth printing, not worth
    // acting on, a standing observation about a working configuration".
    //
    // It was Warn, which put it on the "needs attention" axis (see check.rs) and
    // so promised an action that does not exist. A warning nobody can ever clear
    // is what teaches people to stop reading warnings. Reported from a CPH2649
    // whose three modules made the report permanently unhappy about a device that
    // was working correctly.
    //
    // Note this deliberately does NOT extend to the other unfixable finding,
    // "foreign mount in another namespace": that one contradicts the zero-mount
    // posture the same report otherwise claims, so it has news to break and stays
    // a warning.
    // How my_* is being served, and who chose it. A NOTE, not a warning.
    //
    // THE RULE THIS OBEYS: the Suite does not raise alarms about things a
    // detector cannot see. A marker under /data/adb is not an oracle; the Duck
    // Detector, Holmes and the rest read mounts, paths, xattrs and process
    // state, and this file is none of those. And the marker's EFFECT is fewer
    // mounts -- my_* served by injection instead of a real bind -- so it moves
    // the posture in the quiet direction. Warning about it made the WebUI say
    // "1 thing needs attention" on a device whose attention nothing needed.
    //
    // It was a Warn because the trial has a named failure (a leaf my_* injection
    // can trip zygote's FD allowlist at forkSystemServer). That is real, and it
    // is not the user's job: the bootloop guard disables the Suite after three
    // failed boots and writes incident.log, which is a MECHANISM, not an alert.
    // The place to read about the hazard is `mount::my_hookless_enabled`.
    //
    // What stays worth saying is plain fact: my_* adds no mounts here, and the
    // Suite did not write the marker -- so if the user did not either, a module
    // did, and it is the only way to find out which.
    if Path::new(crate::mount::MY_HOOKLESS_MARKER).exists() {
        let writers = my_hookless_writers();
        f.push(Finding {
            level: Level::Info,
            check: "my_* served by injection",
            detail: if writers.is_empty() {
                format!(
                    "my_* partitions are served by injection instead of a real bind, so they \
                     add no mounts. No installed module mentions the marker, so this is your \
                     own opt-in; remove {} to go back to binds.",
                    crate::mount::MY_HOOKLESS_MARKER
                )
            } else {
                format!(
                    "my_* partitions are served by injection instead of a real bind, so they \
                     add no mounts. The Suite never writes the marker — {} did, which is how a \
                     module keeps its own my_* content off the mount table. Remove {} to go \
                     back to binds; {}.",
                    writers
                        .iter()
                        .map(|(id, file)| format!("{id} ({file})"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    crate::mount::MY_HOOKLESS_MARKER,
                    marker_returns_when(
                        &writers.iter().map(|(_, f)| f.clone()).collect::<Vec<_>>()
                    )
                )
            },
        });
    }

    // A module that is switched ON, ships ROM content, and is served by nothing.
    //
    // This is the "installed and silently not applied" state, and it was
    // invisible: the WebUI's module list says "skipped" in small grey text and
    // no check mentioned it at all. Measured on an OP11, 2026-09-06 --
    // `OnePlus_Dialer_Universal` had shipped 146 files across five partitions and
    // served ZERO of them since 2026-09-01, because its OWN bootloop guard had
    // written a `skip_mount` and nothing ever clears one. Five days of a dialer
    // customisation quietly not applying, with the module listed as enabled.
    //
    // `skip_mount` is therefore NOT assumed to be deliberate. Plenty of modules
    // ship one on purpose (a self-mounter opting out), and for those this is a
    // one-line "yes, that is what you asked for" -- but the marker is a file, any
    // root script can write one, and a module's own guard doing it is exactly the
    // case nobody would look for. Naming who could have put it there is the whole
    // value of the finding.
    let served_modules: std::collections::HashSet<&str> =
        plan.iter().map(|e| e.module.as_str()).collect();
    if let Ok(rd) = std::fs::read_dir("/data/adb/modules") {
        let mut dirs: Vec<_> = rd.flatten().collect();
        dirs.sort_by_key(|d| d.file_name());
        for d in dirs {
            let mdir = d.path();
            let Some(id) = mdir.file_name().and_then(|n| n.to_str()) else { continue };
            if id == "meta-nomount" || !mdir.is_dir() {
                continue;
            }
            let markers: Vec<String> = ["disable", "remove", "skip_mount"]
                .iter()
                .filter(|m| mdir.join(m).exists())
                .map(|m| (*m).to_string())
                .collect();
            let Some(why) = unserved_reason(&markers, served_modules.contains(id)) else {
                continue;
            };
            let (n, parts) = module_rom_files(&mdir);
            if n == 0 {
                continue;
            }
            f.push(Finding {
                level: Level::Warn,
                check: "module content not served",
                detail: if why == "skip_mount" {
                    format!(
                        "{id} ships {n} file(s) under {} and is served by NOTHING: it carries a \
                         `skip_mount` marker, so the Suite leaves its tree alone. If you did not \
                         put that marker there, something else did -- a module's own bootloop \
                         guard writes one and never clears it, and the module then stays enabled \
                         and inert indefinitely. Delete /data/adb/modules/{id}/skip_mount to serve \
                         it, unless the module mounts its own content on purpose.",
                        parts.join(" ")
                    )
                } else {
                    format!(
                        "{id} ships {n} file(s) under {} and is served by NOTHING, with no \
                         disable/remove/skip_mount marker to explain it. That is the Suite's \
                         problem, not the module's: run `nomount plan` for the per-file refusal \
                         reasons.",
                        parts.join(" ")
                    )
                },
            });
        }
    }

    for (module, script, kind, hit) in scan_module_incompat() {
        f.push(Finding {
            level: kind.level(),
            check: kind.check(),
            detail: format!(
                "{module} ({script}): `{hit}`. {}{}",
                kind.explain(),
                reached_only_if_sourced(&script)
            ),
        });
    }

    // Two modules writing the same path: the plan is sorted and only the last is
    // applied, so the winner is stable -- but the loser's content is simply absent.
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
            // The names are hidden-app package names -- the same secret as the hide
            // list. When `nomount export` runs the check for shared storage it sets
            // NM_REDACT_HIDE_LIST=1, so print the count only there (health.rs owns
            // the destination decision; see M-S2). The test lives in blocklist.rs
            // because the device section has a second reader of it (the PM-open
            // probe's uid), and the export promises both.
            let names = if crate::blocklist::redact_hide_list() {
                "names redacted".to_string()
            } else {
                stale.join(", ")
            };
            f.push(Finding {
                level: Level::Info,
                check: "stale legacy blocklist entries",
                detail: format!(
                    "{} entry/entries in /data/adb/nomount/blocklist are hidden APPS ({}). They moved \
                 to `uidhide` and do nothing here. Remove them if you want that file to mean only \
                 \"skip this module\".",
                    stale.len(),
                    names
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
    //
    // This is the ONE manager setting still read, and it is read through
    // `ksud feature get`. The global "Umount modules by default" and the per-app
    // "umount modules" profiles were decoded out of ksud's private `.allowlist`
    // binary format, and that decode is gone: by its own argument neither can
    // hide anything the Suite serves, so all three findings were notes about
    // settings that do nothing here -- bought with a 784-byte record layout that
    // would rot to "unknown" on any ksud change and be believed until someone
    // noticed. The manager's own UI is where those two live and where they are
    // changed.
    //
    // A NOTE, not a warning, by the same rule that demoted the my_* marker: no
    // app can read a root manager's settings, and this one's effect here is
    // NOTHING -- the Suite serves no mounts, so there is nothing for the switch
    // to unmount. A finding that describes a setting doing nothing does not get
    // to put "1 thing needs attention" on the card. Worth saying once, because a
    // user who turned it on is expecting hiding they are not getting; not worth
    // an alarm.
    let kernel_umount = crate::manager::kernel_umount_enabled();
    if kernel_umount == Some(true) {
        f.push(Finding {
            level: Level::Info,
            check: "manager kernel umount ON",
            // CONDITIONAL, because the flat claim was FALSE. `serve_mode` returns
            // `Serve::Bind` for every my_* target unless the `my_hookless` marker
            // is set, and it is OFF BY DEFAULT -- so on a stock OnePlus setup with
            // any module shipping my_* content the Suite makes REAL BIND MOUNTS,
            // visible in every app's mountinfo naming /data/adb/modules, and the
            // manager's kernel-umount switch is exactly what would strip them from
            // an app's namespace. Telling that user the switch "does nothing here"
            // pointed them away from the one control that closes the loudest
            // oracle on their device.
            detail: {
                let binds = crate::bind::tracked().len();
                if binds == 0 {
                    "your manager's \"Kernel umount\" is ON. Nothing the Suite serves on this \
                     device is a mount, so it has nothing to unmount. Hide per app with \
                     `nomount uid block <pkg>`."
                        .to_string()
                } else {
                    format!(
                        "your manager's \"Kernel umount\" is ON, and this device has {binds} \
                         bind mount(s) of ours — my_* is served by a real bind unless the \
                         my_hookless trial is on. The switch DOES hide those from an app's \
                         mount table, and it is the only thing that does; it cannot touch the \
                         injections, which are not mounts."
                    )
                }
            },
        });
    }

    // ...and say so when we could NOT read it. The check above is silent both
    // when the switch is off and when ksud is missing, the exec failed, or its
    // output moved, and those render identically to a reader who then concludes
    // the switch is off. Written for whoever is looking at the card: name the
    // setting the way the manager's own UI names it, say what it does, say what
    // to do, and say the note is permanent so nobody re-reads it every boot
    // wondering what they missed.
    //
    // Only when a KernelSU-family manager is actually installed: a manager with
    // no state directory has nothing to fail at reading.
    // ...and a NOTE for the same reason, one step weaker again: this is the
    // UNKNOWN state of a switch that does nothing here. It was a warning, which
    // made "we could not read an inert setting" as loud as a live rule serving
    // the wrong bytes.
    //
    // The old text also said the switch "has broken root". That was true when su
    // arrived as a module overlay and anything stripping module content stripped
    // su with it; su is kernel sucompat now and entirely outside the Suite, so
    // the sentence outlived its cause. Say what is still true.
    if kernel_umount.is_none() && crate::manager::ksu_manager_present() {
        f.push(Finding {
            level: Level::Info,
            check: "manager kernel umount unknown",
            detail: "your manager's \"Kernel umount\" could not be read, so it is UNKNOWN \
                     rather than off. It does nothing here either way; NoMount never needs it."
                .to_string(),
        });
    }

    // ---- live checks (engine up) ------------------------------------------
    let nm = Nm::new();
    let engine = nm.version().ok();
    let live_ok = engine.is_some();
    // Apps hidden from the injections, and the live rules the PackageManager
    // advertises regardless -- the pair the opt-out check below is about.
    // An unreadable hide list is not an empty one. All three PM-published-opt-out
    // checks below are gated on `!hidden_apps.is_empty()`, so a read error
    // silently skipped every one of them and the report looked clean.
    let hidden_apps = match crate::blocklist::read() {
        Ok(v) => v,
        Err(e) => {
            f.push(Finding {
                level: Level::Unmeasured,
                check: "hide list not readable",
                detail: format!(
                    "the per-app hide list could not be read ({e:#}), so the checks that ask whether a hidden app is served consistently did not run."
                ),
            });
            Vec::new()
        }
    };
    let mut pm_rules = 0usize;
    // PM-published rules live WITHOUT the `(public)` flag, i.e. still subject to
    // per-UID hiding despite the PackageManager advertising them. Only meaningful
    // on an engine that reports flags (>= 17); see the finding below.
    let mut pm_rules_no_public: Vec<PathBuf> = Vec::new();
    // An engine that is not responding means NOTHING below was verified -- yet the
    // only trace used to be the header line `live: engine not responding`, which
    // is not part of the summary the WebUI chip and the manager card parse. On a
    // mountless device with a clean plan that produced `no problems found` /
    // `summary: 0 errors, 0 warnings` and a green "healthy" chip. `health.rs`
    // reports ENGINE DOWN for the same condition; the greener surface was winning.
    if !live_ok {
        // WARN, and named for what it is about: the plan section's own live
        // cross-checks. Whether the engine is up is the DEVICE section's verdict
        // ("engine responding"), measured there and reported once. This used to be
        // a second Error saying the same thing in different words, so a dead
        // engine produced two top-of-list failures and the reader had to work out
        // that they were one fact.
        f.push(Finding {
            level: Level::Unmeasured,
            check: "plan cross-checks did not run",
            detail: "the engine did not answer, so the checks that compare the plan against the \
                     live rules were skipped. Everything reported here is the plan alone. Run \
                     `nomount check --device` for the engine's own verdict."
                .to_string(),
        });
    }
    if live_ok {
        // `if let Ok(..)` with no else: an engine that answered `v` but would not
        // ENUMERATE left the live rule count at 0, printed `live: 0 rules`, and skipped the
        // partition-root, FD-allowlist, size-mismatch and all three PM-published
        // checks -- rendering identically to "the engine has zero rules".
        let listed = nm.list();
        if let Err(e) = &listed {
            f.push(Finding {
                level: Level::Error,
                check: "engine rule dump failed",
                detail: format!(
                    "the engine answered, but listing its rules failed ({e:#}). The live rule checks did \
             not run: `live: 0 rules` means \"could not enumerate\", not \"none\"."
                ),
            });
        }
        if let Ok(list) = listed {
            // Every row, whatever its kind: the partition-root check below has to
            // see whiteouts and virtual dirs too, which the pre-typed parser this
            // file used to carry dropped.
            let live = crate::nm::parse_list(&list);
            // The comparison the header line only ever hinted at. The two
            // exemption lists are read here, and an unreadable one is passed
            // through as None rather than as an empty set -- the same distinction
            // `reload` refuses to collapse before it prunes anything.
            let durable: Option<HashSet<PathBuf>> = crate::whiteout::read()
                .ok()
                .map(|v| v.into_iter().map(PathBuf::from).collect());
            let absorbed: Option<HashSet<PathBuf>> =
                crate::absorb::read_absorbed_targets().ok().map(|mut a| {
                    a.extend(crate::absorb::absorbed_tmpfs_targets());
                    a
                });
            f.extend(reconcile_plan_and_live(
                &plan,
                &live,
                durable.as_ref(),
                absorbed.as_ref(),
            ));
            for r in &live {
                let target = &r.target;
                // Broadened from is_rom_apk: the opt-out now covers a package's whole
                // codePath (the nativeLibraryDir .so too), so count that.
                // INJECT rules only. `is_pm_published` tests the path, and a
                // whiteout is added with `nm w` which never carries --public, so
                // every whiteout on a PM-advertised path counted here and landed
                // in pm_rules_no_public. A `.replace` on /product/app expands to
                // ~75 of them, so doctor warned that 75 rules "get ENOENT on a
                // path the PackageManager advertises" -- which is a whiteout's
                // entire purpose. Unactionable, permanently amber, and it
                // inflated pm_rules in two other messages. audit.rs's
                // live_targets() was fixed for exactly this; this copy was not.
                if r.kind == crate::nm::LiveKind::Inject
                    && crate::pmcache::is_pm_published(target)
                {
                    pm_rules += 1;
                    if !r.public {
                        pm_rules_no_public.push(target.clone());
                    }
                }
                // Partition-root check applies to every kind (a whiteout on a root
                // masks the whole partition just as an inject does).
                if is_partition_root(target) {
                    f.push(Finding {
                        level: Level::Error,
                        check: "partition-root rule live",
                        detail: match &r.source {
                            Some(s) => format!("{} is redirected wholesale -> {}", target.display(), s.display()),
                            None => format!("{} ({:?}) masks the whole partition", target.display(), r.kind),
                        },
                    });
                }
                // The zygote FD-allowlist trap. Overlay APKs are the dangerous case because
                // zygote preloads them; flag anything else on such a partition as a warning.
                //
                // INJECT rules only, for the same reason the `pm_rules` arm above is
                // gated: zygote's `FileDescriptorInfo::CreateFromFd` validates the
                // path behind an OPEN FD, and a whiteout has no file to open while a
                // virtual dir is a directory nobody preloads. Neither can reach the
                // trap this counts.
                //
                // It counted every kind, and said "injected file(s)" about the total.
                // Measured on an OP15, 2026-09-07: installing SAN (systemapp_nuker)
                // added exactly one my_stock entry -- a whiteout -- and the note went
                // from "1 injected file(s) on /my_stock" to "2". Two errors in one
                // line: a number that is not the number of injected files, and a
                // deletion described as a file.
                if let Some(part) = partition_of(target).filter(|_| fd_note_applies(r.kind)) {
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
                        }
                        // Everything else on such a partition is NOT reported. See
                        // the block that used to render it, below.
                    }
                }
                // NO size-mismatch finding here any more.
                //
                // It compared metadata(target).len() against metadata(source).len()
                // and raised a plan WARN. `health::drift_probe` asks the SAME
                // question in the device section, on every rule, and answers it
                // better: equal length proves nothing, so it also compares the
                // first 4 KiB of bytes -- the case that found it was two module
                // files of 18 bytes each ("NMT12_WINNER_IS_A" against
                // "..._IS_B"), which a size test calls identical.
                //
                // So the two fired together on one condition, with two severities
                // and two remedies, in two sections. That is the shape this tree
                // already removed once, when `check_no_foreign_rom_mount` and
                // `zero-mount posture` both claimed the same my_* binds: "two red
                // rows for one cause, one of them describing the opposite of what
                // happened."
                //
                // The device section owns it, which is also where it belongs by
                // this command's own contract: `--plan` is documented as static
                // and reading no running process, and what the engine is SERVING
                // right now is a measurement, not a property of the module set.
            }
        }
    }

    // A PM-published file is the one injection the system advertises to an app
    // that is hidden from us: the PackageManager scans those directories as
    // system_server (never blocked), registers what it finds, and names the whole
    // codePath to every app that asks. `Nm::add` therefore serves them with the
    // hiding opt-out.
    //
    // From engine v17 the client PRINTS the per-rule `(public)` flag, so we can
    // name the exact rules missing it rather than inferring from the version. A
    // PM-published rule live without the flag on a v17+ engine means the opt-out
    // did not take, and the hidden app gets ENOENT on a path the PM says exists
    // (Trusteer SIGSEGVs). The engine is bumped 17 -> 18 this cycle and v18 keeps
    // the flag behaviour, so this is `>= 17`, not `== 17`.
    let engine_v = engine.unwrap_or(0);
    if live_ok && !hidden_apps.is_empty() && engine_v >= 17 && !pm_rules_no_public.is_empty() {
        let shown: Vec<String> =
            pm_rules_no_public.iter().take(3).map(|t| t.display().to_string()).collect();
        let more = pm_rules_no_public.len().saturating_sub(shown.len());
        f.push(Finding {
            level: Level::Warn,
            check: "PM-published rule not opted out of hiding",
            detail: format!(
                "engine v{engine_v}: {} rule(s) Android registered are hidden from your {} hidden \
                 app(s), so those apps get \"not found\" for a file Android says exists. Re-run \
                 the mount pass. {}{}",
                pm_rules_no_public.len(),
                hidden_apps.len(),
                shown.join(", "),
                if more > 0 { format!(", and {more} more") } else { String::new() }
            ),
        });
    }

    // Fallback for engines that do NOT report the flag (< 17): infer from the
    // version. `Nm::add` opts these rules out, but that flag only exists from
    // engine v15, and an older one strips it with every other unknown bit. The
    // result is silent: the rule applies, the app still gets ENOENT on a path the
    // PM says exists. Say so instead.
    if live_ok && !hidden_apps.is_empty() && pm_rules > 0 && engine_v < 15 {
        f.push(Finding {
            level: Level::Warn,
            check: "engine predates the hiding opt-out",
            detail: format!(
                "engine v{engine_v} is too old to exempt registered apps from hiding, so your {} \
                 hidden app(s) get \"not found\" for {pm_rules} file(s) Android says exist. That \
                 crashes apps that walk the package list. Update the kernel.",
                hidden_apps.len()
            ),
        });
    }

    // v15 gave an ADDED PM-published file the opt-out but the kernel stripped it
    // again from any rule that turned out to SHADOW a stock file, on the reasoning
    // that the blocked reader is served the stock bytes and is therefore
    // consistent. It is not: the PackageManager parsed the MODULE's copy as
    // system_server and publishes that version and signature for the path, so a
    // blocked reader handed the stock bytes disagrees with what the PM advertises.
    // Only the kernel knows which rules shadow, so gate on the version rather than
    // trying to count them here.
    //
    // 15..18, not 15..17: v17 SET the bit and printed it, but nothing acted on it
    // -- nm_stock_for_caller() still decided with the raw blocked-uid test, so a
    // v17 engine is observationally identical to v16. Excluding 17 here while the
    // `>= 17` check above sees a fully-flagged rule list meant a v17 device passed
    // BOTH checks clean while a blocked reader was still served stock bytes for a
    // shadowed PM-published file -- the exact inconsistency both exist to catch.
    if live_ok && !hidden_apps.is_empty() && pm_rules > 0 && (15..18).contains(&engine_v) {
        f.push(Finding {
            level: Level::Warn,
            check: "engine strips the opt-out from a replaced PM-published file",
            detail: format!(
                "engine v{engine_v} serves stock bytes to your {} hidden app(s) for any rule that \
                 REPLACES a ROM file, while Android advertises the module's version for it. \
                 Rebuild the kernel from kbuild@hookless >= 17.",
                hidden_apps.len()
            ),
        });
    }

    // _ghost: is the cloak telling the truth on THIS kernel?
    //
    // Two failures, and they need opposite responses. OVER-REACH is ours and it
    // is the dangerous one: a path that a hidden caller can still see must never
    // be in the table, because ghosting it makes one path answer stat=OK and
    // chmod=ENOENT at once -- louder than the oracle it replaces, and visible
    // without a control path. Shipped that way in v1.3.55-.57 with 259 of 260
    // entries wrong. INEFFECTIVE is the kernel's: guards compiled in that do not
    // fire, which is exactly what an untested 6.6/6.1/5.15/5.10 build might do
    // and what no CI can rule out.
    //
    // Sampled, not exhaustive: each path costs a fork, and the table is built by
    // one predicate, so a systematic error shows up in the first few. The count
    // is reported so a clean verdict cannot be mistaken for a full sweep.
    if live_ok && engine_v >= 26 {
        // ...and an `Err` gets a row, exactly as the sibling `nm.list()` failure
        // twelve lines above does ("`live: 0 rules` means 'could not enumerate',
        // not 'none'"). This was a bare `if let Ok`, so an engine that answered
        // `v` but would not dump its ghost tables produced NO row at all -- while
        // the block below works hard to tell "both tables empty" apart from "not
        // compiled in", and then the outer match threw away the third state.
        if let Err(e) = nm.ghost_list() {
            f.push(Finding {
                level: Level::Unmeasured,
                check: "ghost cloak could not be read",
                detail: format!(
                    "the engine would not list its hidden paths ({e:#}), so the existence cloak was not tested on this kernel. This is not a pass."
                ),
            });
        }
        if let Ok(txt) = nm.ghost_list() {
            let (gpaths, guids) = parse_ghost_tables(&txt);
            if let (Some(&uid), false) = (guids.first(), gpaths.is_empty()) {
                const SAMPLE: usize = 16;
                // ATTEMPTED, not answered. `_ => {}` used to swallow Absent and
                // Unknown alike, so a run where every probe FAILED -- fork or
                // waitpid failing, or the child unable to drop privileges (exit 3),
                // all of which are whole-sample-systematic -- left visible and
                // leaked empty and printed "16 of N sampled: each looks exactly
                // like a path that never existed. Measured here, not assumed from
                // the build." Nothing had been measured at all, and the WebUI turns
                // that line into a green "Present and measured working here".
                let attempted = gpaths.len().min(SAMPLE);
                let mut visible: Vec<&PathBuf> = Vec::new();
                let mut leaked: Vec<&PathBuf> = Vec::new();
                let mut absent = 0usize;
                let mut unknown = 0usize;
                for p in gpaths.iter().take(SAMPLE) {
                    match ghost_seen_by(uid, p) {
                        GhostSeen::Visible => visible.push(p),
                        GhostSeen::XattrLeak => leaked.push(p),
                        GhostSeen::Absent => absent += 1,
                        GhostSeen::Unknown => unknown += 1,
                    }
                }
                let checked = attempted;
                let name = |v: &[&PathBuf]| -> String {
                    v.iter().take(3).map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
                };
                // `uid` here is the FIRST entry of the engine's _ghost uid table,
                // which service.sh populates from the hide list -- so printing it
                // names an app being hidden from, exactly like the PM-open probe's
                // appid and the stale-blocklist finding's package names. All three
                // land in `check.txt`, and `nomount export` writes that to shared
                // storage, where the same function withholds `uid_live.txt`, strips
                // the ` [UID: n]` suffix from `rules.txt` and drops `uidhide*`.
                //
                // This probe was added AFTER the gate and did not read it, so a
                // shared export published `to uid 10422` while its own closing note
                // promised "the check report's hide-list names were redacted" --
                // measured on OP15, against a uid that resolves to a package in
                // uidhide.cache. Third reader of `redact_hide_list()`; see the note
                // on that function for why the test has one home.
                let who = hidden_uid_label(uid, crate::blocklist::redact_hide_list());
                if !visible.is_empty() {
                    f.push(Finding {
                        level: Level::Error,
                        check: "ghost cloak over-reaches",
                        detail: format!(
                            "{} of {checked} sampled path(s) are still visible to {who} — they \
                 answer \"exists\" and \"does not exist\" at once, which is louder than the leak \
                 this closes. Re-run the mount pass: {}",
                            visible.len(),
                            name(&visible)
                        ),
                    });
                }
                if !leaked.is_empty() {
                    f.push(Finding {
                        level: Level::Warn,
                        check: "ghost cloak compiled in but not effective",
                        detail: format!(
                            "{} of {checked} sampled path(s) hide from `stat` but still leak their label — \
                 the guards are compiled in and not firing on this kernel: {}",
                            leaked.len(),
                            name(&leaked)
                        ),
                    });
                }
                if visible.is_empty() && leaked.is_empty() && absent == 0 {
                    // Nothing answered. Not a pass, and explicitly not the
                    // "measured here" claim.
                    f.push(Finding {
                        level: Level::Unmeasured,
                        check: "ghost cloak NOT verified",
                        detail: format!(
                            "none of the {attempted} sampled path(s) could be probed (the test process \
             could not run), so the cloak was not tested on this kernel — this is not a pass"
                        ),
                    });
                } else if visible.is_empty() && leaked.is_empty() {
                    f.push(Finding {
                        level: if unknown > 0 { Level::Warn } else { Level::Info },
                        check: if unknown > 0 {
                            "ghost cloak only partly verified"
                        } else {
                            "ghost cloak verified on this kernel"
                        },
                        detail: if unknown > 0 {
                            format!(
                                "{absent} of {attempted} sampled path(s) look exactly like a path that never \
             existed, to {who} — but {unknown} could not be probed, so this is not a complete answer"
                            )
                        } else {
                            format!(
                                "{absent} of {} hidden path(s) sampled: each looks exactly like a path that never \
             existed, to {who}. Measured here, not assumed from the build.",
                                gpaths.len()
                            )
                        },
                    });
                }
            } else {
                // The kernel answers an EMPTY, SUCCESSFUL dump both when _ghost
                // is not compiled in and when it is present with empty tables
                // (nomount.c: `if (!ghost_get_rule) return 0;`). This arm used
                // not to exist, so both cases produced no Finding at all and the
                // silence was indistinguishable from a pass -- while service.sh
                // logged the cloak as inert on the very same boot.
                f.push(Finding {
                    // Nothing injected anywhere means nothing for the cloak to
                    // guard, which is n/a. With rules live and the tables still
                    // empty, the cloak really is off and that stays amber.
                    level: if plan.iter().any(|e| e.kind == PlanKind::Inject) {
                        Level::Unmeasured
                    } else {
                        Level::NotApplicable
                    },
                    check: "ghost cloak not populated",
                    detail: format!(
                        "the engine returned {} hidden path(s) and {} hidden uid(s); both tables must be \
             non-empty for any guard to fire, so nothing was tested — a kernel built without _ghost \
             answers exactly the same way",
                        gpaths.len(),
                        guids.len()
                    ),
                });
            }
        }
    }

    // ---- isolated-process pools: the one DEFAULT that opens an oracle -------
    //
    // Once anything is hidden, nm_hide_isolated decides whether every app-zygote
    // (90000-98999) and platform-isolated (99000-99999) process also sees the
    // stock tree. The engine documents the trade in as many words:
    //
    //   "it is not free: while it is on, an UNBLOCKED app can compare its own
    //    view against its own isolated child's view and find the injection that
    //    way. (The blocked app itself sees no such divergence -- both of its
    //    views are stock.)"
    //
    // The default is 3, both pools. So on every device with a non-empty hide
    // list, ANY app that declares android:isolatedProcess="true" can prove
    // injection with two reads of one path -- no root, no control path, and no
    // knowledge of what is hidden. Nothing in this report said so, which made it
    // the only setting whose DEFAULT creates a detector-visible differential and
    // is invisible in the report meant to find exactly those.
    //
    // Info, not Warn: it is a policy choice with a real argument on both sides,
    // and the opposite setting hands a hidden app a way to read through its own
    // isolated helper. The reader needs to know it exists, not to be nagged.
    {
        let hidden_any = !crate::blocklist::cache_read().is_empty();
        let mode = crate::blocklist::hide_isolated();
        if hidden_any {
            f.push(Finding {
                level: if mode == 0 { Level::Warn } else { Level::Info },
                check: "isolated-process pools",
                detail: match mode {
                    0 => "hiding covers NEITHER isolated pool. A hidden app can read through its own isolated child and see every injection, which is the leak the pools exist to close. `nomount uid isolated both` unless you specifically want the other side of this trade."
                        .to_string(),
                    // Short on purpose. This fires on every device with a hide
                    // list, on every run, and the trade does not change between
                    // boots -- so the note has to state the oracle and stop. The
                    // full argument lives in the comment above and in the WebUI's
                    // Hiding tab, where the switch is.
                    3 => "hiding covers both isolated pools (the default): a hidden app cannot read through its own isolated child, but an UNBLOCKED app can tell its own view apart from its isolated child's and prove injection that way. `nomount uid isolated none` takes the other side of the trade."
                        .to_string(),
                    m => format!(
                        "hiding covers {} only. Same trade as the default, on one pool.",
                        if m == 1 { "the app-zygote pool" } else { "the platform pool" }
                    ),
                },
            });
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
    // The header that used to print here -- `{modules} modules planned | {injects}
    // injects ... | live: {live_count} rules` -- printed both halves of the
    // reconcile side by side and compared neither. On an OP15 it read `258
    // injects ... live: 261 rules` above a `0 errors, 0 warnings` summary. The
    // counts are facts now (returned below) and the comparison is a finding.

    // Any module-backed mount still standing is an app-visible detection surface:
    // it is the one thing the mountless posture exists to deny, and after absorb
    // has run the only ones left are those deliberately skipped. Report them, so
    // opting out of absorption is a visible trade rather than a silent one.
    // A mount left standing on purpose is an observation, not a warning: absorb is
    // never going to take it, so there is nothing to act on. Only a mount that
    // nothing declined is worth flagging — that one means absorb has not run or
    // could not do its job.
    // An UNREADABLE mount table is not "no module mounts", and this is the one
    // place in the report that could not tell the difference.
    //
    // `survey()` returns Err when /proc/self/mountinfo cannot be read, and
    // `unwrap_or_default()` turned that into an empty vec -- so EVERY mount
    // finding below (foreign mount absorb cannot take, module mount not absorbed
    // x3, module mount left by design x4) silently disappeared and the plan half
    // rendered exactly like a device with nothing mounted. `health.rs`'s
    // `count_mounts_split` was rewritten to avoid precisely this, with a comment
    // that says "(0, 0) said 'there are no module mounts' for a question that was
    // never asked" -- and the same substitution was still live here.
    let surveyed = crate::absorb::survey();
    if let Err(e) = &surveyed {
        f.push(Finding {
            level: Level::Unmeasured,
            check: "mount table not readable",
            detail: format!(
                "the mount table could not be read ({e:#}), so NO mount check ran. This is not \"no mounts\": a module mount left standing is visible to any app that reads its own /proc/self/mountinfo."
            ),
        });
    }
    for s in surveyed.unwrap_or_default() {
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
                "{} (from {}) is mounted in {} but not here, so absorb cannot see or unmount \
                 it. It was replicated with nsenter, and apps can see it.",
                e.mount.target.display(),
                e.mount.source.display(),
                e.seen_in
            ),
        });
    }

    // NOT REPORTED. The per-partition tally ended in the word "fine", and a row
    // that says "fine" is not a finding.
    //
    // Its history is a warning about itself: it began as one Warn per file, which
    // buried real findings under ~85 identical lines, so it was rolled up to one
    // Info per partition -- three rows on any OnePlus, on every run, forever,
    // saying nothing happened. The rollup treated the symptom. Nothing reads this:
    // it is a boot-safety property, no detector sees it, and there is no action
    // behind it.
    //
    // The DANGEROUS case is untouched and stays an Error, per file: an overlay APK
    // on a partition zygote's FD allowlist does not cover aborts forkSystemServer.
    // That one names a file, predicts a bootloop, and the fix is the reader's. The
    // tally is still computed because the Error arm shares its walk; if the count
    // is ever wanted, `nomount plan` lists every target with its partition.
    let mut holes: Vec<(&str, Vec<&Path>)> = holes.into_iter().collect();
    holes.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(b.0)));
    for (module, targets) in &holes {
        let shown: Vec<String> = targets.iter().take(3).map(|t| t.display().to_string()).collect();
        let more = targets.len().saturating_sub(shown.len());
        f.push(Finding {
            level: Level::Info,
            check: "whiteout leaves a measurable hole",
            detail: format!(
                "{module}: {} path(s) the engine cannot fully mask — their folder spans several \
                 blocks, so its size still counts the hidden entry. Applied anyway; declining \
                 would silently neuter the module. {}{}",
                targets.len(),
                shown.join(", "),
                if more > 0 { format!(", and {more} more") } else { String::new() }
            ),
        });
    }

    for (marker, module, count) in expansions_by_marker(&plan) {
        let Some(level) = expansion_level(count) else { continue };
        f.push(Finding {
            level,
            check: "wide replacement expansion",
            detail: format!(
                "{module}: {} expands to {count} hides, one per ROM entry it does not ship. \
                 Correct, but a lot from one marker — narrow it if it was meant to cover less.",
                marker.display()
            ),
        });
    }

    // Sorted here so the plan rows arrive in a stable order; the report sorts
    // the combined list again by verdict.
    f.sort_by(|a, b| a.level.cmp(&b.level).then(a.check.cmp(b.check)));

    // The counts that used to be a header line nobody could parse reliably --
    // `service.sh` scraped "summary: N errors, M warnings" out of the prose with
    // a sed expression. They are facts about the module set, so they travel with
    // the rest of the facts.
    let facts: Vec<crate::check::Fact> = vec![
        ("modules".to_string(), modules.to_string()),
        ("plan_injects".to_string(), injects.to_string()),
        ("plan_whiteouts".to_string(), whiteouts.to_string()),
        ("plan_binds".to_string(), binds.to_string()),
        ("plan_blocklisted".to_string(), skipped.to_string()),
        // NOT the manager's kernel_umount: the device section's fingerprint
        // already carries it as `manager_umount`, and two keys holding one value
        // is how a reader ends up asking which of them is current.
    ];

    Ok((to_checks(f), facts))
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::nm::LiveKind;

    /// The three incompatibilities are not equally loud, and the axis is not
    /// fixability -- none of them is fixable in NoMount.
    ///
    /// A CPH2649 carrying three such modules read "3 things need attention" on a
    /// device that was working correctly, because ImageBacked sat on the attention
    /// axis while offering no action. It works as intended and its only trace, a
    /// mount, is reported independently by the device section.
    #[test]
    fn only_the_silently_broken_kinds_are_loud() {
        // Contradict what the user believes they have: the module is not doing its job.
        assert_eq!(Incompat::RomWrite.level(), Level::Warn);
        assert_eq!(Incompat::MagiskMirror.level(), Level::Warn);
        // Works as intended; the finding explains a mount rather than breaking news.
        assert_eq!(Incompat::ImageBacked.level(), Level::Info);
        // And Info must land off the "attention" axis, or the change is cosmetic:
        // that axis is what the WebUI counts as "N things need attention".
        assert_eq!(verdict_of(&Level::Info).severity(), "info");
        assert_eq!(verdict_of(&Level::Warn).severity(), "attention");
    }

    /// The exact line that produced a false "image-backed or chroot module" on a
    /// OnePlus CPH2649 running v1.3.122. `command -v` ASKS WHETHER nsenter exists.
    #[test]
    fn a_capability_probe_is_not_an_image_backed_module() {
        assert_eq!(
            classify_incompat_line("if command -v nsenter >/dev/null 2>&1 \\"),
            None,
            "probing for a tool must not be reported as using it"
        );
        for probe in [
            "command -v losetup >/dev/null",
            "which nsenter >/dev/null 2>&1",
            "type -p unshare",
            "hash chroot 2>/dev/null",
            "if ! command -v losetup; then return; fi",
        ] {
            assert_eq!(classify_incompat_line(probe), None, "probe reported as use: {probe}");
        }
    }

    /// The five entry scripts are not where the mounts always are.
    ///
    /// MoveCertificate (1947 stars) sources its whole boot path out of
    /// `sh/compatible.sh`, so every one of its bind and nsenter lines sat in a
    /// file no lint ever opened. Real line, from post-fs-data.sh:11.
    #[test]
    fn a_sourced_helper_is_followed() {
        assert_eq!(sourced_scripts(". $MODDIR/sh/compatible.sh"), vec!["sh/compatible.sh"]);
        assert_eq!(sourced_scripts("source ${MODPATH}/util_functions.sh"), vec!["util_functions.sh"]);
        assert_eq!(sourced_scripts(r#"sh "$MODDIR/rmlwk.sh" --update-hosts"#), vec!["rmlwk.sh"]);
        // Same helper named by two entry points is one entry.
        assert_eq!(
            sourced_scripts(". $MODDIR/a.sh
source $MODPATH/a.sh"),
            vec!["a.sh"]
        );
    }

    /// The reference must not be able to walk the scanner out of the module, and
    /// must not fire on prose or on a word that merely ends in the keyword.
    #[test]
    fn sourced_scripts_stays_inside_the_module() {
        for quiet in [
            ". /system/etc/somewhere.sh",       // absolute, not module-relative
            ". $MODDIR/../../etc/passwd",       // traversal
            "# . $MODDIR/commented.sh",         // comment
            "wish $MODDIR/notakeyword.sh",      // `sh ` inside another word
            "echo 'nothing to source here'",
        ] {
            assert!(sourced_scripts(quiet).is_empty(), "should not follow: {quiet}");
        }
    }

    /// A module that bind-mounts its own content over the ROM is the family
    /// absorb exists for, and it was completely silent at plan time: `plan` reads
    /// the LIVE mount table, so a module that has not run yet has no mount to
    /// see. Reading its scripts is the only way to say it in advance.
    ///
    /// Lines are real, taken off Re-Malwack (445 stars) and bindhosts (1390) as
    /// staged on an OP15 on 2026-09-05.
    #[test]
    fn a_module_that_binds_over_the_rom_is_named() {
        for real in [
            // bindhosts: literal destination.
            r#"mount --bind "$MODDIR/system/etc/hosts" /system/etc/hosts"#,
            "mount -o bind $MODDIR/hosts /system/etc/hosts",
            "mount -t overlay overlay -o lowerdir=/system/etc:$MODDIR/etc /system/etc",
            "mount --rbind $MODDIR/fonts /system/fonts",
        ] {
            assert_eq!(
                classify_incompat_line(real),
                Some(Incompat::SelfMount),
                "missed a real self-mount: {real}"
            );
        }
    }

    /// Re-Malwack binds THROUGH a variable, so the mount line alone carries no
    /// ROM path. This is the shape that made the whole family invisible.
    #[test]
    fn a_bind_through_a_variable_is_resolved() {
        let script = concat!(
            "#!/system/bin/sh
",
            "system_hosts=\"/system/etc/hosts\"
",
            "hosts_file=\"$MODDIR/system/etc/hosts\"
",
            "mount --bind \"$hosts_file\" \"$system_hosts\" || {
",
        );
        let vars = rom_path_vars(script);
        assert_eq!(vars.get("system_hosts").map(String::as_str), Some("/system/etc/hosts"));
        // $hosts_file starts with $MODDIR, not a ROM path, so it is NOT collected.
        assert!(!vars.contains_key("hosts_file"), "a module-tree path must not be taken for a ROM path");

        let line = r#"mount --bind "$hosts_file" "$system_hosts" || {"#;
        assert_eq!(classify_incompat_line(line), None, "precondition: unresolved, it is invisible");
        assert_eq!(
            classify_incompat_line(&expand_rom_vars(line, &vars)),
            Some(Incompat::SelfMount),
            "resolved, Re-Malwack's real bind must be named"
        );
    }

    /// Longest-name-first, or `$hosts` eats the front of `$hosts_file`.
    #[test]
    fn overlapping_variable_names_expand_longest_first() {
        let vars = rom_path_vars("hosts=/system/etc/hosts
hosts_file=/system/etc/hosts.d/x
");
        assert_eq!(
            expand_rom_vars("mount --bind $hosts_file /tmp/x", &vars),
            "mount --bind /system/etc/hosts.d/x /tmp/x"
        );
    }

    /// The FD-allowlist tally counts injected FILES, and says so in its own text.
    ///
    /// It counted every live row, whatever its kind. Measured on an OP15,
    /// 2026-09-07: installing SAN (systemapp_nuker) added exactly one `/my_stock`
    /// entry -- a WHITEOUT -- and the note went from "1 injected file(s) on
    /// /my_stock" to "2". A whiteout has no fd for zygote to validate and a
    /// virtual dir is a directory nothing preloads; neither can reach the trap.
    #[test]
    fn the_fd_allowlist_tally_counts_only_injects() {
        assert!(fd_note_applies(crate::nm::LiveKind::Inject));
        assert!(
            !fd_note_applies(crate::nm::LiveKind::Whiteout),
            "a whiteout is a deletion, not an injected file"
        );
        assert!(
            !fd_note_applies(crate::nm::LiveKind::VirtualDir),
            "a virtual dir is a directory the engine made, not an injected file"
        );
    }

    /// A layout-convergence symlink is not shipped content.
    ///
    /// `system/product -> ../product` is what every OPlus-shaped module carries so
    /// the classic and auto_mount layouts converge, and `serve_mode` refuses its
    /// target as a bare partition root -- so it is never served. Counting it both
    /// doubled the total and attributed it to a partition the module ships
    /// nothing on. Measured on an OP15, 2026-09-07: SAN's two whiteouts were
    /// reported as "ships 4 file(s) under system(2) my_stock(1) product(1)".
    ///
    /// A symlink to a FILE still counts: `plan_tree` treats it as a leaf and
    /// injects it like any other entry.
    #[test]
    fn a_convergence_symlink_is_not_counted_as_shipped_content() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        // The real content: <mod>/product/app/Foo, one entry.
        std::fs::create_dir_all(root.join("product/app")).unwrap();
        std::fs::write(root.join("product/app/Foo"), b"x").unwrap();
        // The convergence link the installer leaves behind, and a leaf symlink,
        // which IS content.
        std::fs::create_dir_all(root.join("system")).unwrap();
        symlink("../product", root.join("system/product")).unwrap();
        symlink("Foo", root.join("product/app/Bar")).unwrap();

        assert_eq!(
            count_files(&root.join("product"), 0),
            2,
            "one file plus one leaf symlink"
        );
        assert_eq!(
            count_files(&root.join("system"), 0),
            0,
            "a symlink to a directory is the convergence link, not shipped content"
        );
    }

    /// A dangling link is content the module meant to ship, so it still counts --
    /// `source_resolves` is what reports it as unservable, and silently dropping
    /// it here would hide the module from the "content not served" check
    /// entirely.
    #[test]
    fn a_dangling_symlink_still_counts_as_shipped_content() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("product")).unwrap();
        symlink("nowhere", d.path().join("product/Gone")).unwrap();
        assert_eq!(count_files(&d.path().join("product"), 0), 1);
    }

    /// Evidence found in a SOURCED helper is conditional, and must not be stated
    /// as fact.
    ///
    /// Measured on an OP15, 2026-09-07: SAN (systemapp_nuker) v2.2.2 installs at
    /// `mounting_mode=2`, where its `post-fs-data.sh` never reaches the
    /// `. $MODDIR/mountify.sh` in the `mounting_mode=1` arm -- and the report said
    /// flatly that the module "mounts its own content over a ROM path" and that
    /// absorb "unmounts it, four times per boot". The device measured zero
    /// foreign mounts the whole time.
    #[test]
    fn a_hit_inside_a_sourced_helper_is_marked_conditional() {
        for entry in ENTRY_SCRIPTS {
            assert_eq!(
                reached_only_if_sourced(entry),
                "",
                "{entry} is run by the manager; nothing is conditional about it"
            );
        }
        for helper in ["mountify.sh", "sh/compatible.sh", "lib/mount.sh"] {
            assert!(
                reached_only_if_sourced(helper).contains("SOURCES"),
                "{helper} is only reached through a `.`, and the report has to say so"
            );
        }
    }

    /// The kernel-umount note must depend on whether we actually made binds.
    ///
    /// It said flatly "It does nothing here — injections are not mounts, so there
    /// is nothing to unmount", and that is false on the hardware this project
    /// targets: `serve_mode` returns `Serve::Bind` for every `my_*` target unless
    /// the `my_hookless` marker is set, and the marker is OFF BY DEFAULT. A stock
    /// OnePlus setup with any module shipping `my_*` content therefore carries
    /// real bind mounts naming `/data/adb/modules` in every app's mountinfo — and
    /// the manager's kernel-umount switch is the ONE control that removes them
    /// from an app's namespace. The Suite was pointing users away from it.
    ///
    /// Pinned on the branch, not the wording: what matters is that zero binds and
    /// some binds do not produce the same sentence.
    #[test]
    fn the_kernel_umount_note_depends_on_whether_binds_exist() {
        let src = include_str!("doctor.rs");
        let at = src
            .find("check: \"manager kernel umount ON\",")
            .expect("finding gone or renamed");
        let block = &src[at..at + 1600.min(src.len() - at)];
        assert!(
            block.contains("crate::bind::tracked()"),
            "the note must read the live bind record, not assert that there are none"
        );
        assert!(
            block.contains("hide those") || block.contains("DOES hide"),
            "with binds present it must say the switch would hide them"
        );
    }

    /// THE RULE: the Suite warns about what a detector can see, or about the
    /// user's own modules not working. Nothing else gets to be amber.
    ///
    /// Nothing that reads this device -- the Duck Detector, Holmes, the RASP
    /// families -- can see a file under `/data/adb` or a root manager's settings.
    /// Both subjects below are exactly that, and both are ALSO inert or quieting
    /// here: `my_hookless` removes 85 mounts by serving my_* through injection,
    /// and the manager's kernel-umount switch has nothing to unmount because the
    /// Suite serves no mounts. Warning about either put "1 thing needs attention"
    /// on the card of a device that needed none, which is how a reader learns to
    /// skip the badge -- and the badge is the only thing carrying the findings
    /// that DO matter.
    ///
    /// Hazards handled by a mechanism are not alerts either: the bootloop guard
    /// recovers a bad my_* trial on its own and writes `incident.log`. That
    /// belongs in a doc comment at `mount::my_hookless_enabled`, not in the
    /// user's face.
    ///
    /// Deliberately NOT extended to the rest: a rule that is planned and not
    /// live, a module serving nothing, a target claimed twice, a PM-published
    /// path answering ENOENT to a hidden app, the ghost cloak over-reaching, a
    /// foreign mount over the ROM -- each is either read by a detector or is the
    /// user's own content silently not working. Those stay loud.
    ///
    /// Pinned by reading this file, because the level is chosen at the
    /// construction site and there is no smaller unit to test. Re-promote one and
    /// this fails, with the paragraphs above as the reason.
    #[test]
    fn findings_no_detector_can_see_are_notes() {
        let src = include_str!("doctor.rs");
        for name in [
            "my_* served by injection",
            "manager kernel umount ON",
            "manager kernel umount unknown",
        ] {
            let at = src
                .find(&format!("check: \"{name}\","))
                .unwrap_or_else(|| panic!("{name}: finding gone or renamed -- keep the rule with it"));
            let before = &src[at.saturating_sub(200)..at];
            assert!(
                before.contains("level: Level::Info,"),
                "{name} is invisible to every detector and changes nothing an app can \
                 observe; it must not be a warning"
            );
        }
    }

    /// "Delete the marker" is only actionable if the report says when it comes
    /// back, and that depends on WHICH script writes it.
    ///
    /// The text was a fixed sentence -- "or it returns on the next boot" --
    /// which is true on an OP11, where `OnePlus_Dialer_Universal` writes the
    /// marker from `post-fs-data.sh`, and false on an OP15 running a different
    /// build of the same module, where the only writer is `stage_overrides.sh`
    /// and its only caller is that module's `action.sh`. There, deleting the
    /// marker holds until the user taps ▶, and the advice was wrong about the
    /// one fact the reader needs in order to act on it.
    #[test]
    fn when_the_my_hookless_marker_comes_back_depends_on_the_writer() {
        assert!(
            marker_returns_when(&["post-fs-data.sh".into()]).contains("next boot"),
            "a boot script really does re-create it every boot"
        );
        assert!(
            marker_returns_when(&["service.sh".into(), "stage_overrides.sh".into()])
                .contains("next boot"),
            "ANY boot script among the writers means it comes back at boot"
        );
        let helper = marker_returns_when(&["stage_overrides.sh".into()]);
        assert!(
            !helper.contains("next boot"),
            "an action helper must not be described as a boot script: {helper}"
        );
        assert!(
            helper.contains("action button"),
            "say what does bring it back instead: {helper}"
        );
    }

    /// A module switched ON whose content reaches nothing.
    ///
    /// The `skip_mount` row is the OP11 case: `OnePlus_Dialer_Universal` shipped
    /// 146 files and served zero for five days, because its OWN bootloop guard
    /// had written a `skip_mount` that nothing ever clears — while the manager
    /// still listed it as enabled.
    #[test]
    fn a_module_that_ships_content_and_serves_nothing_is_named() {
        assert_eq!(unserved_reason(&["skip_mount".into()], false), Some("skip_mount"));
        // No marker at all and still nothing served: that one is ours, not the
        // module's, and must not read the same way.
        assert_eq!(unserved_reason(&[], false), Some("none"));
    }

    /// The user turning a module OFF is not a finding — content not being served
    /// is the entire point — and neither is a module that IS being served.
    #[test]
    fn a_disabled_or_served_module_is_not_a_finding() {
        assert_eq!(unserved_reason(&["disable".into()], false), None);
        assert_eq!(unserved_reason(&["remove".into()], false), None);
        assert_eq!(unserved_reason(&[], true), None);
        assert_eq!(unserved_reason(&["skip_mount".into()], true), None);
        // remove wins even alongside skip_mount: it is on its way out.
        assert_eq!(unserved_reason(&["skip_mount".into(), "remove".into()], false), None);
    }

    /// The `my_*` partitions, which this whole chain could not see.
    ///
    /// `PARTS` was five names matched as `/{p}/`, and `/my_product/` does not
    /// contain `/product/` -- so on an OPlus ROM, the family this project
    /// targets, every incompat arm was blind to eleven partitions at once.
    ///
    /// The first line is real, off an OP11 (CPH2449) on 2026-09-06:
    /// `Bootanimation/post-fs-data.sh:5`. It was the ONLY self-mounting module on
    /// that device, and `nomount check --plan` reported nothing at all.
    #[test]
    fn my_partitions_are_not_invisible() {
        assert_eq!(
            classify_incompat_line(
                "mount --bind $MODDIR/my_product/media/bootanimation/ /my_product/media/bootanimation/"
            ),
            Some(Incompat::SelfMount),
            "the real OP11 line that went unreported"
        );
        // The other arms were blind in the same way.
        assert_eq!(
            classify_incompat_line("cp /data/x /my_stock/etc/foo.xml"),
            Some(Incompat::RomWrite)
        );
        assert_eq!(
            classify_incompat_line("rm -rf /my_region/app/Bar"),
            Some(Incompat::RomWrite)
        );
        assert_eq!(
            classify_incompat_line("mount -o rw,remount /my_bigball"),
            Some(Incompat::RomWrite)
        );
        // ...and through a variable, the Re-Malwack shape on a my_* path.
        let vars = rom_path_vars("boot_dir=\"/my_product/media/bootanimation\"\n");
        assert_eq!(vars.get("boot_dir").map(String::as_str), Some("/my_product/media/bootanimation"));
    }

    /// Widening the list must not make `/system_ext/` match `system`, or a
    /// partition NAME inside a longer word match at all. The needle is `/{p}/`,
    /// and these are the pairs where that matters now that `my_product` and
    /// `product` are both in the list.
    #[test]
    fn a_wider_partition_list_does_not_over_match() {
        for quiet in [
            "mount --bind /data/x /systemfoo/y",
            "mount --bind /data/x /my_productfoo/y",
            "cp /data/x /notsystem/y",
            "mount --bind $MODDIR/my_product/a $MODDIR/my_product/b",
        ] {
            assert_eq!(classify_incompat_line(quiet), None, "over-counted: {quiet}");
        }
        // `/system_ext/` is its own partition and matches as itself, not via `system`.
        assert_eq!(
            classify_incompat_line("mount --bind $MODDIR/x /system_ext/etc/y"),
            Some(Incompat::SelfMount)
        );
    }

    /// Every way this arm could over-count, on the same evidence the arms above
    /// were narrowed on.
    #[test]
    fn self_mount_does_not_over_count() {
        for quiet in [
            // Prose. Re-Malwack's own scripts are full of it.
            r#"ui_print "- Setting up mount hosts...""#,
            r#"echo "failed to mount $hosts_file to $system_hosts""#,
            "# mount IDs start with 500k or 2b",
            // Removing a mount is not making one.
            "umount /system/etc/hosts",
            "mount --bind /dev/null /system/etc/hosts && umount /system/etc/hosts",
            // Not over the ROM: the module's own tree, or /data.
            "mount --bind $MODDIR/a $MODDIR/b",
            "mount -o bind /data/adb/foo /data/adb/bar",
            // A bare partition name is not a path INTO the partition.
            "mount --bind /data/x /systemfoo/y",
        ] {
            assert_eq!(classify_incompat_line(quiet), None, "over-counted: {quiet}");
        }
    }

    /// ORDER: an nsenter-replicated bind stays ImageBacked.
    ///
    /// absorb says of that shape that it "cannot see or unmount (replicated with
    /// nsenter)". Retagging it as a self-mount would promise absorb handles a
    /// mount absorb has explicitly said it cannot -- the softening the note on
    /// AutoSystemBoost says not to make.
    #[test]
    fn an_nsenter_replicated_bind_stays_image_backed() {
        assert_eq!(
            classify_incompat_line("nsenter -t 1 -m -- mount --bind $MODDIR/etc /system/etc"),
            Some(Incompat::ImageBacked)
        );
        assert_eq!(
            classify_incompat_line(
                "/system/bin/nsenter --mount=/proc/$zp/ns/mnt -- /bin/mount --rbind $SYS_CERT /system/etc/security/cacerts"
            ),
            Some(Incompat::ImageBacked)
        );
    }

    /// The two genuine reports from that same device must still fire -- the fix
    /// must not buy quiet by going blind.
    #[test]
    fn real_image_backed_modules_are_still_named() {
        assert_eq!(
            classify_incompat_line("mount -o loop $MODDIR/so.img /data/adb/tmp/so_mount"),
            Some(Incompat::ImageBacked)
        );
        assert_eq!(
            classify_incompat_line("LOOP_DEV=\"$(/system/bin/losetup -sf \"$MODFILEMOUNTED\")\""),
            Some(Incompat::ImageBacked)
        );
        for real in ["chroot /data/local/tmp/rootfs sh", "nsenter --mount=/proc/1/ns/mnt sh", "mkfs.ext4 img"] {
            assert_eq!(classify_incompat_line(real), Some(Incompat::ImageBacked), "missed: {real}");
        }
    }

    /// Probe AND use on one line is still a use -- the probe expression is removed,
    /// the line is not skipped.
    #[test]
    fn probing_then_using_on_one_line_still_counts() {
        assert_eq!(
            classify_incompat_line("command -v losetup >/dev/null && losetup -sf $IMG"),
            Some(Incompat::ImageBacked)
        );
    }

    /// Every `explain()` arm is ONE line, because check.rs renders it as one
    /// (`       measured: <detail>`).
    ///
    /// `SelfMount` shipped with five literal `\n` escapes where its three
    /// siblings use `\` continuations, so it printed a five-line blob with
    /// seventeen spaces of indent on each continuation. The difference is one
    /// character in the source and invisible on review, which is exactly what a
    /// test is for.
    #[test]
    fn no_explanation_carries_a_raw_newline() {
        for k in [
            Incompat::RomWrite,
            Incompat::MagiskMirror,
            Incompat::ImageBacked,
            Incompat::SelfMount,
        ] {
            assert!(
                !k.explain().contains('\n'),
                "{:?}.explain() carries a raw newline -- use a `\\` continuation, not `\\n`",
                k
            );
            assert!(!k.check().contains('\n'), "{k:?}.check() carries a raw newline");
            // ...and the continuation must not leave a run of padding behind
            // either, which is the other half of what `\n` produced here.
            assert!(!k.explain().contains("   "), "{k:?}.explain() carries collapsed indentation");
        }
    }

    /// Deleting ROM content is the loudest thing the RomWrite arm reports, and the
    /// commonest way to write it -- at the start of a line -- was invisible: the
    /// classifier runs on a TRIMMED line and the pattern was `" rm "` with a
    /// leading space. Both spellings, and the `set_perm` guard the spaces were
    /// there for, in one test.
    #[test]
    fn rm_is_seen_at_the_start_of_a_line_and_after_a_word() {
        assert_eq!(
            classify_incompat_line("rm -rf /system/app/Foo"),
            Some(Incompat::RomWrite),
            "a line that BEGINS with rm was the miss"
        );
        assert_eq!(
            classify_incompat_line("su -c rm -rf /system/app/Foo"),
            Some(Incompat::RomWrite)
        );
        // The reason the spaces were there in the first place: `rm ` is a
        // substring of `perm `, and anchoring at the start cannot revive that.
        assert_eq!(classify_incompat_line("set_perm /system/bin/foo 0 0 0755"), None);
        assert_eq!(classify_incompat_line("perm /system/bin/foo"), None);
        // Removing something that is not in the ROM is still not a ROM write.
        assert_eq!(classify_incompat_line("rm -rf /data/adb/foo"), None);
    }

    /// The two precision fixes this chain already carried, pinned now that they are
    /// reachable: `rm ` inside `set_perm`, and mirror boilerplate.
    #[test]
    fn the_older_precision_fixes_still_hold() {
        assert_eq!(classify_incompat_line("set_perm /system/bin/foo 0 0 0755"), None);
        // Reading a stock file to seed a module copy is not a ROM write.
        assert_eq!(
            classify_incompat_line("cp /system/etc/hosts $MODPATH/system/etc/hosts"),
            None
        );
        // Writing INTO the ROM is.
        assert_eq!(
            classify_incompat_line("cp /data/x /system/etc/hosts"),
            Some(Incompat::RomWrite)
        );
    }

    /// A BACKUP out of the ROM is a read, whatever it copies into.
    ///
    /// Real line, HyperUnlocked utils.sh:311, found over the 116 most-starred
    /// modules. The old guard only recognised `$MODPATH`/`$MODDIR` as a
    /// destination, so copying ROM content anywhere ELSE -- here /data -- was
    /// reported as writing INTO a ROM partition.
    #[test]
    fn copying_out_of_the_rom_is_not_a_rom_write() {
        assert_eq!(
            classify_incompat_line(
                r#"su -c "cp -r /system/system/etc/device_features/* /data/adb/HyperUnlocked/bakxml/""#
            ),
            None
        );
        assert_eq!(classify_incompat_line("cp -r /product/etc/x /data/local/tmp/"), None);
        // ...and the destination case still fires, including through a variable
        // the caller resolved (AlwaysTrustUserCerts service.sh:79).
        assert_eq!(
            classify_incompat_line("cp $MODDIR/system/etc/security/cacerts/* /system/etc/security/cacerts/"),
            Some(Incompat::RomWrite)
        );
        // The remount arm is independent of any destination test.
        assert_eq!(
            classify_incompat_line("mount -o rw,remount -t auto /system || mount /system;"),
            Some(Incompat::RomWrite)
        );
    }

    fn wo(module: &str, marker: &str, target: &str) -> PlanEntry {
        PlanEntry {
            module: module.to_string(),
            target: PathBuf::from(target),
            source: PathBuf::from(marker),
            kind: PlanKind::Whiteout,
        }
    }

    /// Whiteouts are grouped by the marker that produced them, so one `.replace`
    /// reads as one wide expansion rather than N unrelated rules -- and an inject
    /// sharing the plan is not counted at all.
    #[test]
    fn expansions_are_grouped_by_their_marker() {
        let mut plan = vec![
            wo("m", "/data/adb/modules/m/system/etc/x/.replace", "/system/etc/x/a"),
            wo("m", "/data/adb/modules/m/system/etc/x/.replace", "/system/etc/x/b"),
            wo("m", "/data/adb/modules/m/system/etc/x/.replace", "/system/etc/x/c"),
            // a 0:0 char device is its own source: always a group of one
            wo("m", "/data/adb/modules/m/system/app/Foo", "/system/app/Foo"),
        ];
        plan.push(PlanEntry {
            module: "m".into(),
            target: PathBuf::from("/system/etc/x/mine.xml"),
            source: PathBuf::from("/data/adb/modules/m/system/etc/x/mine.xml"),
            kind: PlanKind::Inject,
        });

        let got = expansions_by_marker(&plan);
        assert_eq!(got.len(), 2, "one .replace group + one char device");
        // widest first
        assert_eq!(got[0].2, 3);
        assert!(got[0].0.ends_with(".replace"));
        assert_eq!(got[1].2, 1);
    }

    fn inj(module: &str, target: &str, source: &str) -> PlanEntry {
        PlanEntry {
            module: module.to_string(),
            target: PathBuf::from(target),
            source: PathBuf::from(source),
            kind: PlanKind::Inject,
        }
    }

    /// The gap this check closes. On an OP15 doctor printed
    /// `258 injects ... live: 261 rules` and then `0 errors, 0 warnings`: it read
    /// the plan, it read the live rules, and it never compared them.
    #[test]
    fn a_plan_and_a_rule_set_that_disagree_are_a_finding() {
        let plan = vec![
            inj("m", "/system/etc/a", "/data/adb/modules/m/system/etc/a"),
            inj("m", "/system/etc/served-by-nobody", "/data/adb/modules/m/system/etc/x"),
        ];
        let live = crate::nm::parse_list(
            "/system/etc/a -> /data/adb/modules/m/system/etc/a
             /system/etc/stray -> /data/adb/modules/gone/system/etc/stray
",
        );
        let empty = HashSet::new();
        let f = reconcile_plan_and_live(&plan, &live, Some(&empty), Some(&empty));
        let checks: Vec<&str> = f.iter().map(|x| x.check).collect();
        assert!(checks.contains(&"planned rule not live"), "{checks:?}");
        assert!(checks.contains(&"live rule the plan cannot account for"), "{checks:?}");
        assert!(!checks.contains(&"live rule disagrees with the plan"), "{checks:?}");
    }

    /// The three exemptions reload's prune pass makes, made here too. Without
    /// them every durable whiteout, every absorbed rule and every per-UID rule on
    /// a healthy device reads as unaccounted-for.
    #[test]
    fn durable_absorbed_and_per_uid_rules_are_not_unexplained() {
        let plan = vec![inj("m", "/system/etc/a", "/data/adb/modules/m/system/etc/a")];
        let live = crate::nm::parse_list(
            "/system/etc/a -> /data/adb/modules/m/system/etc/a
             /system/etc/hidden (whiteout)
             /product/app/X/X.apk -> /data/adb/rvhc/x.apk
             /system/etc/b -> /data/adb/modules/m/system/etc/b [UID: 10123]
             /system/etc/nmt (virtual dir)
",
        );
        let durable: HashSet<PathBuf> = [PathBuf::from("/system/etc/hidden")].into_iter().collect();
        let absorbed: HashSet<PathBuf> =
            [PathBuf::from("/product/app/X/X.apk")].into_iter().collect();
        let f = reconcile_plan_and_live(&plan, &live, Some(&durable), Some(&absorbed));
        assert!(f.is_empty(), "{:?}", f.iter().map(|x| x.detail.as_str()).collect::<Vec<_>>());
    }

    /// A source that moved between modules is the dangerous shape: the rule count
    /// still matches, so nothing that only counts could ever see it.
    #[test]
    fn a_live_rule_naming_another_source_is_an_error() {
        let plan = vec![inj("winner", "/system/etc/a", "/data/adb/modules/winner/system/etc/a")];
        let live = crate::nm::parse_list("/system/etc/a -> /data/adb/modules/loser/system/etc/a
");
        let empty = HashSet::new();
        let f = reconcile_plan_and_live(&plan, &live, Some(&empty), Some(&empty));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].check, "live rule disagrees with the plan");
        assert_eq!(f[0].level, Level::Error);
    }

    /// An unreadable exemption list must not turn every whiteout on the device
    /// into an "unaccounted-for" rule.
    #[test]
    fn an_unreadable_exemption_list_reports_nothing_extra() {
        let plan: Vec<PlanEntry> = Vec::new();
        let live = crate::nm::parse_list("/system/etc/hidden (whiteout)
");
        let f = reconcile_plan_and_live(&plan, &live, None, None);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].check, "live rules not fully accounted for");
        assert_eq!(f[0].level, Level::Info);
    }

    /// A report, never a cap: the levels escalate but nothing is ever withheld.
    /// Calibrated on a stock OP15 (~258 live rules): /system/app is 15 entries,
    /// /product/app 75, /system/fonts 224.
    #[test]
    fn expansion_levels_escalate_but_never_refuse() {
        assert_eq!(expansion_level(1), None);
        assert_eq!(expansion_level(15), None); // .replace on /system/app
        assert_eq!(expansion_level(49), None);
        assert_eq!(expansion_level(75), Some(Level::Info)); // /product/app
        assert_eq!(expansion_level(199), Some(Level::Info));
        assert_eq!(expansion_level(224), Some(Level::Warn)); // /system/fonts
    }

    /// A shipped image is reported MODULE-RELATIVE, as its doc promises.
    ///
    /// It returned the absolute path, which repeats the
    /// /data/adb/modules/<id>/ prefix the finding already carries.
    #[test]
    fn a_shipped_image_is_named_relative_to_its_module() {
        let base = std::env::temp_dir().join("nm-doctor-img-test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("common")).unwrap();
        std::fs::write(base.join("common/rootfs.img"), b"x").unwrap();
        assert_eq!(
            find_shipped_image(&base, &base, 0).as_deref(),
            Some("common/rootfs.img")
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    /// No two checks in one report may share an id.
    ///
    /// The plan side emits a check once per offending entity, so the same `check`
    /// string arrives many times -- measured on an OP11 with a clean setup: six
    /// plan checks, three distinct ids. `Check::id` is what the WebUI puts in
    /// `id="chk-..."` and what an acceptance would key on, and `audit.rs` asserts
    /// this same property for the device checks.
    #[test]
    fn plan_findings_never_share_an_id() {
        let f = vec![
            Finding {
                level: Level::Info,
                check: "module mount left by design",
                detail: "/product/app/A.apk <- /data/adb/modules/m/a — m is a hook framework".into(),
            },
            Finding {
                level: Level::Info,
                check: "module mount left by design",
                detail: "/product/app/B.apk <- /data/adb/modules/m/b — m is a hook framework".into(),
            },
            Finding {
                level: Level::Info,
                check: "whiteout leaves a measurable hole",
                detail: "mod_a: 3 path(s) the engine cannot fully mask".into(),
            },
            Finding {
                level: Level::Info,
                check: "whiteout leaves a measurable hole",
                detail: "mod_b: 9 path(s) the engine cannot fully mask".into(),
            },
            // A detail that OPENS WITH A COUNT. No shipping plan check does
            // today -- the one that did was the per-partition FD tally, dropped
            // because a row ending in "fine" is not a finding -- but the skip is
            // a property of `subject_of`, not of that check, and an id keyed on a
            // number would change every time the count did.
            Finding {
                level: Level::Info,
                check: "no such partition",
                detail: "7 rule(s) target /mi_ext which does not exist".into(),
            },
            // Same check AND same subject: the counter is the backstop.
            Finding {
                level: Level::Warn,
                check: "target claimed twice",
                detail: "/system/etc/x <- a, b".into(),
            },
            Finding {
                level: Level::Warn,
                check: "target claimed twice",
                detail: "/system/etc/x <- c, d".into(),
            },
        ];
        let n = f.len();
        let checks = to_checks(f);
        assert_eq!(checks.len(), n);
        let mut ids: Vec<&str> = checks.iter().map(|c| c.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "two plan checks share an id: {ids:?}");
        // The id still says what it is about, rather than being a bare counter.
        assert!(
            checks[0].id.starts_with("module-mount-left-by-design-product-app-a"),
            "id should carry its subject, got {}",
            checks[0].id
        );
        // Two findings of the same check are told apart by their subject.
        assert_eq!(checks[2].id, "whiteout-leaves-a-measurable-hole-mod-a");
        assert_eq!(checks[3].id, "whiteout-leaves-a-measurable-hole-mod-b");
        // ...and a detail that opens with a COUNT keys on the first PATH, never
        // on the number, so the id survives the count changing.
        assert_eq!(checks[4].id, "no-such-partition-mi-ext");
        // ...and the display name is untouched by the disambiguation.
        assert_eq!(checks[0].name, "module mount left by design");
        assert_eq!(checks[1].name, "module mount left by design");
    }

    /// The subject is the first token, which is where every repeatable plan
    /// finding puts the thing it is about.
    #[test]
    fn a_findings_subject_is_the_head_of_its_detail() {
        let f = |d: &str| Finding { level: Level::Info, check: "c", detail: d.to_string() };
        assert_eq!(subject_of(&f("/product/app/X.apk <- /data/adb/m")), Some("/product/app/X.apk"));
        assert_eq!(subject_of(&f("OxygenCustomizer: 4 path(s) ...")), Some("OxygenCustomizer"));
        // A count is not a subject: the partition is. `not-fd-allowlisted-83`
        // was unique and moved whenever the module gained a file.
        assert_eq!(subject_of(&f("3 injected file(s) on /my_product")), Some("/my_product"));
        assert_eq!(
            subject_of(&f("9 injected file(s) on /my_stock -- zygote does not preload these")),
            Some("/my_stock")
        );
        // Nothing usable at all -- the counter alone keeps it unique.
        assert_eq!(subject_of(&f("12 of 16 sampled look absent to uid 10471")), None);
        assert_eq!(subject_of(&f("")), None);
    }

    /// The ghost-cloak probe is the THIRD reader of the hide list in a report that
    /// `nomount export` writes to shared storage, and it was the one that did not
    /// read the gate: a shared export carried "to uid 10422" -- an appid that
    /// resolves through `uidhide.cache` to an installed package -- while the
    /// export's own closing note said the report's hide-list names were redacted.
    /// Measured on OP15 before the fix.
    ///
    /// The point of the assertion is not the wording but that the NUMBER cannot
    /// survive redaction, since that is the whole secret.
    /// Named for what it ACTUALLY covers. It was
    /// `redaction_covers_every_hide_list_reader`, which it never did and could not:
    /// `hidden_uid_label` is private to this module, so the third reader -- the
    /// PM-open probe in audit.rs, with its own copy of the decision -- was outside
    /// its reach the whole time. That reader is pinned by
    /// `audit::tests::redaction_covers_the_pm_open_probe`; see
    /// [`crate::blocklist::redact_hide_list`] for the per-reader rule.
    #[test]
    fn redaction_covers_the_doctor_readers() {
        // Private destination: the appid, which is what makes the finding useful.
        assert_eq!(hidden_uid_label(10422, false), "hidden uid 10422");
        // Shared destination: nothing that identifies the app, and above all not
        // the digits -- PackageManager.getNameForUid() reverses those.
        let redacted = hidden_uid_label(10422, true);
        assert_eq!(redacted, "a hidden app");
        assert!(!redacted.contains("10422"), "the appid must not survive redaction");
        // ...for any uid, not just the one that was measured leaking.
        for uid in [10000u32, 10384, 10471, 1_010_471, 99_999] {
            assert!(
                !hidden_uid_label(uid, true).contains(&uid.to_string()),
                "uid {uid} leaked through redaction"
            );
        }
    }

    #[test]
    fn partition_of_extracts_top_level() {
        assert_eq!(partition_of(Path::new("/product/overlay/x.apk")).as_deref(), Some("product"));
        assert_eq!(partition_of(Path::new("/system/etc/y.xml")).as_deref(), Some("system"));
        assert_eq!(partition_of(Path::new("/vendor/lib/z.so")).as_deref(), Some("vendor"));
        assert_eq!(partition_of(Path::new("/")), None);
    }

    /// Kept after the local copy was deleted, because it is this file's callers
    /// that depend on the answer -- and `/` is the case the local copy got wrong.
    #[test]
    fn is_partition_root_only_for_bare_roots() {
        assert!(is_partition_root(Path::new("/product")));
        assert!(is_partition_root(Path::new("/system")));
        assert!(is_partition_root(Path::new("/")), "the filesystem root is one too");
        assert!(!is_partition_root(Path::new("/product/overlay")));
        assert!(!is_partition_root(Path::new("/product/overlay/x.apk")));
    }

    /// The parser itself, and its suffix-peeling, now live with the client that
    /// produces the text (`nm::parse_list`) -- see its tests. What this file still
    /// owns is the reading of those rows, exercised by the checks above.
    #[test]
    fn parse_live_still_yields_the_rows_the_checks_read() {
        let v = crate::nm::parse_list(
            "/product/x.apk -> /data/adb/modules/M/product/x.apk (public)\n\
             /system/y (whiteout)\n",
        );
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].target, PathBuf::from("/product/x.apk"));
        assert_eq!(v[0].source.as_deref(), Some(Path::new("/data/adb/modules/M/product/x.apk")));
        assert_eq!(v[0].kind, LiveKind::Inject);
        assert!(v[0].public);
        assert_eq!(v[1].kind, LiveKind::Whiteout);
        assert_eq!(v[1].source, None);
    }
}
