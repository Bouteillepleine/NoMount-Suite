//! Runtime health: the regression canary that would have caught the d_drop bug
//! on the first boot instead of a three-hour hunt.
//!
//! The plan section of `nomount check` lints what the module set WOULD do. This
//! module measures the running system: is the engine live, are the injected files
//! still byte-consistent, and — the Narcissus canary — does a normal app see the
//! same filesystem as root? A per-UID divergence for an *unblocked* app is
//! exactly the class of kernel regression (d_drop, dcache poisoning) that a
//! self-consistency detector flags.
//!
//! Two things come out of one [`gather`]: the flat key=value FACTS that
//! `health.txt`, `snapshot` and `verify` are built on, and the [`Check`]s those
//! facts imply. They used to be one and the same, which is why this module's
//! answers were stringly typed -- `consistency` was "ok" | "mismatch:<path>(root=A
//! app=B)" | "unchecked" | "unchecked:probe-uid-hidden", four states encoded as
//! prefixes of one string because the field had to be both the verdict and the
//! evidence at once. Now the verdict is a `Verdict` and the string is evidence.
//!
//! `snapshot` freezes a known-good fingerprint; `verify` diffs live-vs-snapshot
//! and names what drifted. `export` dumps diagnostics for sharing.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

use crate::check::{slug, Check, Section, Verdict};
use crate::nm::Nm;

const NM_DIR: &str = "/data/adb/nomount";
const SNAPSHOT: &str = "/data/adb/nomount/snapshot.txt";

/// One line-based `key=value` fingerprint of the live system. Field order is
/// stable so a textual diff reads cleanly.
pub struct Fingerprint {
    version: String,
    uname: String,
    engine: String, // "vN" or "down"
    rules: usize,
    whiteouts: usize,
    /// `None` = the mount table could not be read. Rendered `unknown`, never 0.
    mounts: Option<usize>,
    blocked: String, // count, or "unknown" when the engine could not be asked
    consistency: String, // "ok" | "mismatch:<path>(root=A app=B)" | "unchecked"
    /// Does the served path match the source its own rule names?
    /// "ok" | "drift:<path>(rule=<src> ...)" | "unchecked". Separate from
    /// `consistency` because they fail independently: a target can be perfectly
    /// consistent between root and an app and still serve another module's bytes.
    served_matches_rule: String,
    guard: String,       // "armed" | "tripped"
    /// Module mounts that are NOT left by design, i.e. actual leaks. Carried
    /// separately so the card can stop calling an expected hook-framework bind a
    /// warning.
    mounts_foreign: Option<usize>,
    /// The root manager's `kernel_umount`: "on" | "off" | "unknown".
    ///
    /// Carried in the fingerprint so the manager's state travels with every
    /// diagnostic anyone pastes into a bug report -- it cannot hide anything the
    /// Suite serves (injections are not mounts) and it has broken root on this
    /// hardware before, so "is that switch on?" was a question every report used
    /// to need asking. "unknown" means ksud could not be asked, not that it is
    /// off. The SEPARATE global "umount modules by default" has no read path at
    /// all and is deliberately not guessed at here; see manager.rs.
    manager_umount: String,
}

impl Fingerprint {
    /// The flat key=value document `health.txt` and `snapshot.txt` are made of.
    ///
    /// Field order is stable so a textual diff reads cleanly, and the KEYS are
    /// unchanged from when this rendered its own text: `service.sh` reads
    /// `consistency` and `verdict` out of health.txt, and `verify` diffs a
    /// snapshot taken by an older build against a fingerprint taken by this one.
    /// Only the RENDERER moved -- to `check::Report::fingerprint_text`, which is
    /// now the single one.
    pub fn facts(&self) -> Vec<crate::check::Fact> {
        let unk = |v: Option<usize>| v.map_or_else(|| "unknown".to_string(), |n| n.to_string());
        [
            ("version", self.version.clone()),
            ("uname", self.uname.clone()),
            ("engine", self.engine.clone()),
            ("rules", self.rules.to_string()),
            ("whiteouts", self.whiteouts.to_string()),
            ("mounts", unk(self.mounts)),
            ("mounts_foreign", unk(self.mounts_foreign)),
            ("blocked", self.blocked.clone()),
            ("consistency", self.consistency.clone()),
            ("served_matches_rule", self.served_matches_rule.clone()),
            ("guard", self.guard.clone()),
            ("manager_umount", self.manager_umount.clone()),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
    }

    /// The verdicts those facts imply, as ordinary checks.
    ///
    /// Every state below was already being expressed -- as a string prefix, in a
    /// prose `verdict=` ladder, and again as a boolean in the JSON arm. Three
    /// encodings of one answer, and the WebUI had to know all three. The engine's
    /// own liveness is deliberately NOT one of them: `audit::check_engine_live`
    /// already asks it, in the same report, and two rows disagreeing about whether
    /// the engine is up is worse than either row alone.
    pub fn checks(&self) -> Vec<Check> {
        let mk = |name: &'static str, v: Verdict, ev: String| {
            Check::new(Section::Device, slug(name), name, v, ev)
        };
        let mut out = Vec::new();

        // NOTHING TO TEST vs DID NOT RUN. Both are honest, and the report has a
        // word for each -- N/A and UNMEASURED -- but the two probes below said
        // UNMEASURED for both. With zero rules live there IS no injected file and
        // never will be, so the amber row and its remedy ("the boot pass runs
        // before any app has opened an injected file -- run them now") were both
        // wrong: running them again cannot change the answer. Reported from an
        // OP15 whose five modules are all script-only, where zero rules is the
        // correct result and the card still read "not fully measured".
        // ...and only when the engine ANSWERED. `gather` reads the rule list with
        // unwrap_or_default(), so a driver that is down yields zero rules exactly
        // as a device with nothing to inject does -- and this would then report
        // "Nothing to test" for two probes on a device that could not be asked.
        // That is the one substitution this file exists to prevent, made in the
        // reassuring direction. `engine` is "vN" when the driver replied and
        // "down" when it did not.
        let nothing_to_serve = self.rules == 0 && self.engine != "down";

        // The Narcissus canary. "unchecked:probe-uid-hidden" is a legitimate
        // can't-check BY DESIGN -- shell is on the hide list, so the divergence
        // this would report is the feature doing exactly what was asked -- while a
        // bare "unchecked" means it sampled no injected file at all, which is the
        // honesty rule's own state.
        out.push(match self.consistency.as_str() {
            "ok" => mk("per-UID consistency canary", Verdict::Pass, self.consistency.clone())
                .meaning(
                    "A normal app sees the same bytes at an injected path as root does, which is \
                     what stops an app spotting the injection by diffing its own view.",
                ),
            "unchecked:probe-uid-hidden" => mk(
                "per-UID consistency canary",
                Verdict::NotApplicable,
                self.consistency.clone(),
            )
            .meaning(
                "The probe uid (shell) is itself on your hide list, so a divergence here would \
                 be the hiding working. Nothing to test.",
            ),
            // ...and when the hide list itself could not be read. `gather` used to
            // default that to "shell is not hidden", so a genuinely hidden shell
            // got ENOENT at every sampled path and the canary rendered a red
            // d_drop-class FAIL for a question it never established the answer to.
            "unchecked:probe-uid-unknown" => mk(
                "per-UID consistency canary",
                Verdict::Unmeasured,
                self.consistency.clone(),
            )
            .meaning(
                "The engine would not say which uids are hidden, so it is not known whether the \
                 probe uid (shell) is itself on the hide list — a divergence would be \
                 unreadable either way, so this was not tested.",
            ),
            // The probe HARNESS, not the device. `app_size` returns an empty
            // string both when the app really cannot see the file and when `su`
            // cannot be spawned, `stat` is not on the child's PATH, or SELinux
            // denies the domain `su <uid> -c` lands in -- and an empty string
            // compared against a real size is a mismatch, which rendered a red
            // "kernel regression" row and pointed the reader at a kernel rebuild
            // for a shell problem.
            "unchecked:probe-unavailable" => mk(
                "per-UID consistency canary",
                Verdict::Unmeasured,
                self.consistency.clone(),
            )
            .meaning(
                "The unprivileged probe could not run at all (`su 2000 -c stat` returned nothing \
                 for a stock ROM file), so nothing was compared and this was not tested.",
            ),
            // The engine ANSWERED `version` but would not dump its rules, so the
            // rule set below is empty for a reason that has nothing to do with the
            // module set. doctor.rs says the same thing about the same failure:
            // "`live: 0 rules` means could not enumerate, not none".
            "unchecked:engine-list-failed" => mk(
                "per-UID consistency canary",
                Verdict::Unmeasured,
                self.consistency.clone(),
            )
            .meaning(
                "The engine would not list its rules, so no injected path could be sampled. \
                 This was not tested — it is not \"nothing to test\".",
            ),
            "unchecked" if nothing_to_serve => mk(
                "per-UID consistency canary",
                Verdict::NotApplicable,
                self.consistency.clone(),
            )
            .meaning(
                "No module here provides files to inject, so there is no injected path for an \
                 app and root to disagree about. Nothing to test.",
            ),
            "unchecked" => mk("per-UID consistency canary", Verdict::Unmeasured, self.consistency.clone())
                .meaning("No injected file could be sampled, so this was not tested."),
            other => mk("per-UID consistency canary", Verdict::Fail, other.to_string())
                .meaning(
                    "A normal app sees something different at an injected path than root does. \
                     That is the d_drop-class kernel regression this canary exists to catch.",
                )
                .oracle(
                    "an app can diff its own view of an injected path against another uid's and \
                     see the injection",
                )
                .owner("the kernel engine"),
        });

        // Does what is SERVED match the source the rule names? Fails independently
        // of the canary: root and an app can agree perfectly while the bytes come
        // from a module the rule does not name.
        out.push(match self.served_matches_rule.as_str() {
            "ok" => mk("served bytes match the rule", Verdict::Pass, self.served_matches_rule.clone())
                .meaning("Every injected path serves the bytes its own rule names."),
            // Same distinction as the canary above: an engine that answered
            // `version` and then refused the rule dump leaves `rules == 0`, which
            // is indistinguishable from a device with nothing to inject unless
            // `gather` says which it was.
            "unchecked:engine-list-failed" => mk(
                "served bytes match the rule",
                Verdict::Unmeasured,
                self.served_matches_rule.clone(),
            )
            .meaning(
                "The engine would not list its rules, so there was nothing to compare against. \
                 This was not tested — it is not \"there are no rules\".",
            ),
            "unchecked" if nothing_to_serve => mk(
                "served bytes match the rule",
                Verdict::NotApplicable,
                self.served_matches_rule.clone(),
            )
            .meaning("There are no rules, so there are no served bytes to compare. Nothing to test."),
            "unchecked" => mk(
                "served bytes match the rule",
                Verdict::Unmeasured,
                self.served_matches_rule.clone(),
            )
            .meaning("No rule had a comparable file at both ends, so this was not tested."),
            // Two causes, and naming only the first misdiagnosed a real device.
            // Measured on an OP11: ONE rule named the target, no second rule and
            // no bind left in the mount table, yet the path served the stock file
            // -- and a verbatim `nm add` of the same pair fixed it instantly. The
            // rule was in the table but INERT, because it was registered while a
            // module's own `mount --bind` still owned the dentry. So say both, and
            // give the remedy that is actually safe: re-asserting a my_* rule at
            // RUNTIME has rebooted a device (see absorb.rs), so the fix is to
            // remove the owning module's bind and let the next boot register the
            // rule with nothing shadowing it -- not to re-add it live.
            other => mk("served bytes match the rule", Verdict::Fail, other.to_string())
                .meaning(
                    "A path serves content its own rule does not name. Either two rules hit one \
                     target, or the rule was registered while another module's `mount --bind` \
                     owned that path and never took effect. A bind made at post-fs-data is \
                     already handled: the pre-zygote absorb pass drops it and re-asserts the \
                     rule underneath, so this points at a bind that appeared AFTER boot -- \
                     absorb leaves those alone on my_*, because re-asserting there on a live \
                     system has rebooted a device. Delete that bind from the owning module \
                     and reboot.",
                )
                .owner("the mount pass"),
        });

        // The kill switch. Not an oracle -- nobody detects you by it -- but with it
        // tripped nothing is being served at all, which is the question every other
        // row is implicitly answering.
        out.push(if self.guard == "armed" {
            mk("boot guard armed", Verdict::Pass, self.guard.clone())
                .meaning("The Suite is enabled; no boot-failure guard has tripped.")
        } else {
            mk("boot guard armed", Verdict::Fail, self.guard.clone())
                .meaning(
                    "The boot guard has tripped, so NOTHING is being injected. Delete \
                     /data/adb/nomount/disabled once you know why, and reboot.",
                )
                .owner("a previous boot")
        });

        out
    }
}

fn read_cmd(prog: &str, args: &[&str]) -> String {
    Command::new(prog)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Size a normal (non-root) app sees for `path`, via `su <uid> -c stat`. Empty
/// string on any failure (which, for an injected path, is itself a divergence).
fn app_size(uid: u32, path: &str) -> String {
    // Single-quoted: `path` is a rule TARGET read off the engine, handed to a
    // shell. A ROM (or a module writing into one) carrying a name like `x; id`
    // would otherwise run it. Same quoting whiteout.rs::app_can_see uses.
    let quoted = format!("'{}'", path.replace('\'', "'\\''"));
    let out = Command::new("su")
        .args([&uid.to_string(), "-c", &format!("stat -c %s {quoted} 2>/dev/null")])
        .output();
    out.ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// How many mounts are backed by module content.
///
/// This used to grep mountinfo for the literal `/data/adb/modules`, which NEVER
/// matches: field 4 is the mount's root WITHIN ITS FILESYSTEM, so a bind out of a
/// module reads `/adb/modules/<id>/…` against the device `/data` lives on. The
/// count was therefore a constant zero, and `mounts=0` in the fingerprint (and on
/// the manager card, and in the WebUI) claimed a clean posture on a device that
/// had real module mounts. Resolve sources properly instead -- absorb already
/// knows how.
/// (total, by_design) module mounts.
///
/// A hook framework's bind is one absorb deliberately never takes over, so
/// counting it the same as a leak made the card contradict itself: it read
/// "⚠ 1 module mount(s)" and "fully mountless" in the same sentence, with no way
/// for a reader to tell the expected one from a real leak.
/// `None` when the mount table could not be read. `(0, 0)` said "there are no
/// module mounts" for a question that was never asked -- and `service.sh` reads
/// `mounts_foreign` straight off this, so an unreadable mountinfo rendered the
/// manager card as "0 mounts ... fully mountless". That is the same constant-zero
/// defect the doc above records, reintroduced through the error path.
fn count_mounts_split() -> Option<(usize, usize)> {
    let Ok(body) = fs::read_to_string("/proc/self/mountinfo") else { return None };
    let rows = crate::absorb::parse_mountinfo(&body);
    let roots = crate::absorb::fs_roots(&rows);
    // The binds WE made, from the record that settles authorship (binds.list).
    // Without this, `by_design` meant "a hook framework's bind" alone, so every
    // my_* bind the Suite creates itself counted as foreign -- and `mounts_foreign`
    // is what service.sh renders on the manager card. `audit::check_zero_mount`
    // learned to ask the same question and now grades an all-ours set as a NOTE,
    // which left the two surfaces of one report disagreeing about the same mounts:
    // the findings list said "the SUITE made these itself" while the card said
    // "N foreign mount(s) present". Same source of truth for both.
    // ...and an UNREADABLE record is not an empty one. `tracked()` is infallible,
    // so a read error made `ours` empty, every bind the Suite made itself counted
    // as foreign, and the card read "⚠ N foreign mount(s)" -- blaming a module
    // that did nothing, with advice that cannot help. `None` is the honest answer
    // and this function already means "could not measure" by it.
    let Ok(tracked) = crate::bind::tracked_result() else { return None };
    let ours: std::collections::HashSet<std::path::PathBuf> =
        tracked.into_iter().map(|(t, _)| t).collect();
    let (mut total, mut by_design) = (0usize, 0usize);
    for r in &rows {
        let Some(src) = crate::absorb::source_of(r, &roots) else { continue };
        // /data/adb, not /data/adb/modules: a module may bind from anywhere under
        // /data/adb, and the narrower test made the count a constant zero for one
        // that does. Issue #14: a YouTube module binds /data/adb/rvhc/<apk> over the
        // installed APK, so the card and the Modules pane both said "mountless" on a
        // device holding a live root-managed mount.
        if !src.starts_with("/data/adb") {
            continue;
        }
        total += 1;
        // Two ways a module mount is expected rather than leaked: a hook
        // framework's bind, which absorb never takes over, and one of ours, which
        // is how a my_* target is served unless the `my_hookless` opt-in is set.
        if ours.contains(&r.target)
            || crate::absorb::module_dir_of(&src)
                .is_some_and(|d| crate::absorb::is_hook_framework(&d))
        {
            by_design += 1;
        }
    }
    Some((total, by_design))
}

/// The unprivileged uid the consistency canary probes as (`shell`).
const PROBE_UID: u32 = 2000;

/// The Narcissus canary: sample a few injected files and confirm a normal app
/// (uid 2000, `shell`) sees the same size as root. A divergence for an unblocked
/// app is the d_drop-class regression this whole module exists to catch early.
///
/// If shell itself is on the hide list the probe is meaningless: the divergence it
/// would report is the feature doing exactly what was asked. Say so, rather than
/// stamping a permanent "per-UID inconsistency" on the manager card.
///
/// `probe_uid_hidden` is `None` when the engine would not say. That is a third
/// state, not a `false`: defaulting it to "shell is not hidden" ran the canary
/// against a shell that may well be hidden, got ENOENT for every sampled path,
/// and reported the d_drop-class FAIL this exists to catch.
fn consistency_probe(rules: &[crate::nm::LiveRule], probe_uid_hidden: Option<bool>) -> String {
    match probe_uid_hidden {
        Some(true) => return "unchecked:probe-uid-hidden".to_string(),
        None => return "unchecked:probe-uid-unknown".to_string(),
        Some(false) => {}
    }
    // Sampling first-6-in-hash-order could sit entirely on one partition served by
    // one module, and a d_drop-class regression can be confined to a single
    // partition. Stratify by (partition, owning module) and take round-robin across
    // buckets, so the sample spans the rule set. Budget bounds the `su` calls.
    const BUDGET: usize = 18;
    let mut buckets: std::collections::BTreeMap<(String, String), Vec<&Path>> =
        std::collections::BTreeMap::new();
    for rule in rules.iter() {
        // Injects only: a whiteout or a virtual dir has no source and no size to
        // compare, and the probe below reads both ends as files.
        let Some(src) = rule.source.as_deref() else { continue };
        let partition = rule
            .target
            .components()
            .nth(1)
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .unwrap_or_default();
        let module = crate::absorb::module_dir_of(src)
            .and_then(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_default();
        buckets.entry((partition, module)).or_default().push(rule.target.as_path());
    }
    let mut sample: Vec<&Path> = Vec::new();
    'outer: for i in 0.. {
        let mut progressed = false;
        for targets in buckets.values() {
            if let Some(t) = targets.get(i) {
                sample.push(t);
                progressed = true;
                if sample.len() >= BUDGET {
                    break 'outer;
                }
            }
        }
        if !progressed {
            break;
        }
    }

    if sample.is_empty() {
        return "unchecked".to_string();
    }
    // CONTROL, before anything is believed. `app_size` returns an empty string for
    // two entirely different events -- the app really got ENOENT at an injected
    // path (the regression) and the probe harness could not run at all (`su` not
    // spawnable, `stat` off the child's PATH, an SELinux denial in the domain
    // `su <uid> -c` lands in). The loop below compares that empty string against a
    // real size, calls it `app=ENOENT`, and `checks()` renders Verdict::Fail with
    // `.owner("the kernel engine")` -- a kernel rebuild proposed for a shell
    // problem. `ghost.rs` records the same class of wrong answer from the same
    // mechanism. /system/build.prop is stock, never injected, and readable by
    // shell on every device this ships to, so an empty answer for IT is the
    // harness, not the device.
    if app_size(PROBE_UID, "/system/build.prop").is_empty() {
        return "unchecked:probe-unavailable".to_string();
    }

    // Injected regular files only (skip virtual dirs / whiteouts which have no size).
    let mut checked = 0;
    for target in sample {
        let root = fs::metadata(target).ok().map(|m| m.len().to_string());
        let Some(root_sz) = root else { continue };
        let Some(target) = target.to_str() else { continue };
        checked += 1;
        let app_sz = app_size(PROBE_UID, target);
        if app_sz != root_sz {
            return format!("mismatch:{target}(root={root_sz} app={})",
                if app_sz.is_empty() { "ENOENT" } else { &app_sz });
        }
    }
    if checked == 0 {
        "unchecked".to_string()
    } else {
        "ok".to_string()
    }
}

/// How much of a file to compare when sizes match. Two module files that
/// collide on one target are very often the same length -- the case that found
/// this compared "NMT12_WINNER_IS_A" against "NMT12_WINNER_IS_B", both 18
/// bytes -- so a size-only check would have reported agreement during the exact
/// failure it exists to catch.
const DRIFT_BYTES: usize = 4096;

fn head(path: &str, n: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut f = fs::File::open(path).ok()?;
    let mut buf = vec![0u8; n];
    let mut got = 0;
    while got < n {
        match f.read(&mut buf[got..]) {
            Ok(0) => break,
            Ok(k) => got += k,
            Err(_) => return None,
        }
    }
    buf.truncate(got);
    Some(buf)
}

/// Does what the engine SERVES at each target match the source its own rule
/// names?
///
/// [`consistency_probe`] answers a different question -- whether root and an
/// unprivileged app see the same thing at a path -- and both can agree perfectly
/// while the bytes come from the wrong module entirely. That is not
/// hypothetical: applying two rules to one target leaves the table naming the
/// second source and the filesystem serving the first, and every existing check
/// called that healthy.
///
/// Compares the served path against the rule's source directly. Reading the
/// target goes through the engine, reading the source does not, so a
/// disagreement is exactly the drift being looked for.
fn drift_probe(rules: &[crate::nm::LiveRule]) -> String {
    // Every rule, not a sample. `consistency_probe` samples because each check
    // costs a `su` spawn; this one is two stats and two 4 KiB reads, so on a
    // 262-rule device it is roughly a thousand syscalls -- cheap enough that
    // sampling only buys blind spots. It bought one: a first pass capped at 24
    // stratified nothing, and the contested target that motivated the check sat
    // outside the window, so the probe reported ok on a device that was visibly
    // serving the wrong module's bytes. The cap below is a runaway guard, not a
    // budget.
    const CAP: usize = 20_000;
    let mut checked = 0;
    for rule in rules.iter().take(CAP) {
        // Virtual dirs and whiteouts carry no source and have no bytes to
        // compare. `source` is typed here rather than string-sliced, which is
        // what keeps `(public)` and `[UID: N]` rules in the sample instead of
        // silently dropping every PM-published path.
        let Some(source) = rule.source.as_deref() else { continue };
        let target = rule.target.as_path();
        let Ok(sm) = fs::metadata(source) else { continue };
        if !sm.is_file() {
            continue;
        }
        let Ok(tm) = fs::metadata(target) else { continue };
        if !tm.is_file() {
            continue;
        }
        let (target, source) = (target.display(), source.display());
        checked += 1;
        if tm.len() != sm.len() {
            return format!("drift:{target}(rule={source} size {} vs {})", tm.len(), sm.len());
        }
        // Equal length proves nothing; compare the bytes.
        let (ta, sa) = (target.to_string(), source.to_string());
        let (Some(a), Some(b)) = (head(&ta, DRIFT_BYTES), head(&sa, DRIFT_BYTES)) else {
            continue;
        };
        if a != b {
            return format!("drift:{target}(rule={source} bytes differ)");
        }
    }
    if checked == 0 {
        "unchecked".to_string()
    } else {
        "ok".to_string()
    }
}

pub fn gather() -> Fingerprint {
    let nm = Nm::new();
    let engine = nm.version().map(|v| format!("v{v}")).unwrap_or_else(|_| "down".into());
    // Keep the Result. `unwrap_or_default()` here made an engine that answers
    // `version` but refuses the rule dump (EPERM, ENOBUFS on a 260-rule device, a
    // client/ABI mismatch) indistinguishable from a device with nothing to inject:
    // `rules == 0` with `engine == "vN"`, and both device probes then rendered N/A
    // with the sentences "No module here provides files to inject" and "There are
    // no rules" -- statements of fact about the module set, produced by a question
    // that could not be asked. `blocked`, twenty lines below, already refuses the
    // same substitution.
    let listed = nm.list();
    let list = listed.as_deref().unwrap_or("").to_string();
    // [`crate::nm::parse_list`], not a local split. The copy that used to live
    // here was the FOURTH reader of this text and the last one still wrong: it
    // split on the FIRST ` -> `, so a target containing one was truncated, and it
    // peeled neither ` (public)` nor ` [UID: N]`, so both suffixes landed inside
    // the source path -- every `fs::metadata(source)` in the probes below then
    // failed silently and skipped exactly the PM-published and per-UID rules.
    let live_rules = crate::nm::parse_list(&list);
    let rules = live_rules.iter().filter(|r| r.kind == crate::nm::LiveKind::Inject).count();
    let whiteouts = live_rules.iter().filter(|r| r.kind == crate::nm::LiveKind::Whiteout).count();
    // Distinguish "nothing hidden" from "couldn't ask": `nm l u` fails loudly on
    // EPERM / engine-down, and reporting that as 0 hidden reads as a working
    // feature with an empty list.
    let live = nm.uid_list_live();
    let blocked = match &live {
        Ok(v) => v.len().to_string(),
        Err(_) => "unknown".to_string(),
    };
    // `None` when the engine would not answer -- NOT `false`. Defaulting to "shell
    // is not hidden" ran the canary against a shell that may well be hidden, which
    // yields ENOENT at every sampled path and renders the red d_drop FAIL. Same
    // reasoning as `blocked` three lines above, and as `whiteout.rs`'s
    // `.unwrap_or(true) // cannot ask -> do not silently drop the candidate`.
    let probe_hidden = live
        .as_ref()
        .map(|v| v.iter().any(|u| crate::blocklist::appid(*u) == PROBE_UID))
        .ok();
    // One reader of the marker, in mount.rs, so the fingerprint and the gate in
    // `main` can never disagree about whether the Suite is parked.
    let guard = if crate::mount::guard_tripped() { "tripped" } else { "armed" };
    let split = count_mounts_split();
    Fingerprint {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uname: read_cmd("uname", &["-r"]),
        engine,
        rules,
        whiteouts,
        mounts: split.map(|(t, _)| t),
        mounts_foreign: split.map(|(t, d)| t - d),
        blocked,
        // Both probes read `live_rules`, so an unreadable rule dump has to reach
        // them as its own state rather than as an empty rule set.
        consistency: if listed.is_err() {
            "unchecked:engine-list-failed".to_string()
        } else {
            consistency_probe(&live_rules, probe_hidden)
        },
        served_matches_rule: if listed.is_err() {
            "unchecked:engine-list-failed".to_string()
        } else {
            drift_probe(&live_rules)
        },
        guard: guard.to_string(),
        manager_umount: match crate::manager::kernel_umount_enabled() {
            Some(true) => "on".to_string(),
            Some(false) => "off".to_string(),
            None => "unknown".to_string(),
        },
    }
}

/// `nomount snapshot` — freeze the current fingerprint as the known-good baseline.
///
/// Kept, where `posture` and `plan` were not. It answers a question `check`
/// structurally cannot: not "is this device healthy now" but "has anything moved
/// since the boot I was happy with", which needs a baseline the user chose. Both
/// this and `verify` render through [`crate::check::Report`], so the file they
/// write and diff is the same fingerprint the report carries.
pub fn run_snapshot() -> Result<()> {
    let body = fingerprint_text()?;
    crate::statefile::write_atomic(SNAPSHOT, &body).context("write snapshot.txt")?;
    print!("{body}");
    println!("snapshot saved to {SNAPSHOT}");
    Ok(())
}

/// The live fingerprint as `health.txt`/`snapshot.txt` text, stamped.
///
/// One producer for both verbs and for `check --write`; the three used to build
/// the same document three times.
fn fingerprint_text() -> Result<String> {
    let r = crate::check::build(false, true)?;
    let mut body = r.fingerprint_text();
    let _ = writeln!(body, "ts={}", r.ts);
    Ok(body)
}

/// `nomount verify` — diff the live fingerprint against the saved snapshot and
/// name every field that drifted. No snapshot yet -> tell the user to take one.
pub fn run_verify() -> Result<()> {
    let saved = match fs::read_to_string(SNAPSHOT) {
        Ok(s) => s,
        Err(_) => {
            println!("no snapshot yet — run `nomount snapshot` on a known-good boot first");
            return Ok(());
        }
    };
    let live = fingerprint_text()?;
    let lines = drift_lines(&saved, &live);
    for l in &lines {
        println!("{l}");
    }
    if lines.is_empty() {
        println!("verify: live matches snapshot (no drift)");
    } else {
        println!("verify: {} field(s) drifted from snapshot", lines.len());
    }
    Ok(())
}

/// Every field that moved between two fingerprints, as the lines `verify` prints.
///
/// Pure, and separated from [`run_verify`] for the reason the redaction labels in
/// audit.rs/doctor.rs are: the verb around it does I/O and prints, so the
/// COMPARISON -- the only part that can be wrong -- was untestable, and `verify`
/// shipped with nothing proving it detects anything at all. It could only ever be
/// observed agreeing with a snapshot taken seconds earlier.
///
/// Both directions, deliberately. The original walked the LIVE fields and looked
/// each one up in the snapshot, so a field the snapshot had and live did NOT was
/// never examined and silently counted as no drift. Nothing on the device path
/// reaches that today -- `Fingerprint::facts()` emits a fixed twelve-key array, so
/// the two sides always carry the same keys -- but the case it misses is exactly a
/// Suite upgrade that renames or drops a fingerprint field, i.e. the moment a
/// stale baseline most needs to say so rather than report a clean bill.
///
/// `ts` is excluded on both sides: it moves on every single call by construction,
/// so including it would make every verify report drift.
fn drift_lines(saved: &str, live: &str) -> Vec<String> {
    let kv = |txt: &str| -> Vec<(String, String)> {
        txt.lines()
            .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
            .filter(|(k, _)| k != "ts")
            .collect()
    };
    let (sv, lv) = (kv(saved), kv(live));
    let find = |set: &[(String, String)], key: &str| -> Option<String> {
        set.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    };
    let mut out = Vec::new();
    // Live order first, so the common case reads in the order the report prints.
    for (k, lval) in &lv {
        let sval = find(&sv, k).unwrap_or_else(|| "<absent>".to_string());
        if &sval != lval {
            out.push(format!("DRIFT {k}: snapshot={sval} -> live={lval}"));
        }
    }
    // Then anything the snapshot had that live no longer emits at all.
    for (k, sval) in &sv {
        if find(&lv, k).is_none() {
            out.push(format!("DRIFT {k}: snapshot={sval} -> live=<absent>"));
        }
    }
    out
}

/// Every root under which a destination is readable by any app holding a storage
/// permission — i.e. every place the hide list must not be written.
///
/// One list, so the two tests in [`is_shared_storage`] cannot drift apart.
const SHARED_ROOTS: &[&str] = &[
    "/sdcard",
    "/storage",
    "/mnt/sdcard",
    "/data/media",
    "/mnt/user",
    "/mnt/runtime",
    "/mnt/androidwritable",
    "/mnt/pass_through",
    // Adopted storage and the raw sdcardfs/FUSE source view. Both are shared
    // volumes reachable by any app holding a storage permission, and both are
    // paths a root shell types by hand -- which is how /data/media/0 got onto
    // this list in the first place.
    "/mnt/media_rw",
    "/mnt/expand",
];

/// Is `p` inside a shared volume?
///
/// `Path::starts_with`, never `str::starts_with`: it compares whole components,
/// so `/data/media0` is not under `/data/media`, and it normalises a `//` root,
/// so `//sdcard/Download` is under `/sdcard`. The caller resolves symlinks and
/// `..` before asking, and asks about the literal path too.
fn is_shared_storage(p: &Path) -> bool {
    SHARED_ROOTS.iter().any(|r| p.starts_with(r))
}

/// Why the export destination's PARENT cannot hold a new directory, or `None`
/// when nothing is in the way (including when it simply does not exist yet --
/// `create_dir_all` makes that case).
///
/// This exists because `create_dir_all` reports the wrong thing for the DEFAULT
/// destination. Measured on an OP15, 2026-09-07, from `adb shell su`:
///
///     $ nomount export /sdcard/Download
///     Error: create /sdcard/Download/nm-diag-20260907-074812
///     Caused by: File exists (os error 17)
///
/// `/sdcard` is a symlink to `/storage/self/primary`, which does not resolve in
/// the mount namespace an adb-launched `su` gets. `create_dir_all` fails on the
/// leaf with ENOENT, walks up, reaches `mkdir("/sdcard")` -- which answers
/// EEXIST, because the SYMLINK is there -- then asks `/sdcard`.is_dir(), which
/// follows the link into nothing and says false, so it surfaces EEXIST and
/// attributes it to the leaf. The reader is told a directory that has never
/// existed already does, and goes looking for a stale export to delete.
///
/// That is the commonest way anyone runs this command: `/sdcard/Download` is the
/// default, and collecting a bug report from `adb shell su` is what the command
/// is for. The WebUI is unaffected -- it runs where the namespace is right.
fn base_unusable(base: &Path) -> Option<String> {
    // Walk UP, the way create_dir_all does. The obstacle is almost never the path
    // that was typed: the user passes `/sdcard/Download` and it is `/sdcard`, one
    // level above, that does not resolve. A first version of this checked only the
    // base itself and the device answered it immediately -- exporting to
    // `/data/local/tmp/danglingbase/Download` still produced the bare
    // "File exists" this function exists to replace.
    for p in base.ancestors() {
        if p.as_os_str().is_empty() {
            continue;
        }
        // The first real directory on the way up ends it: everything below is
        // absent, which is exactly what create_dir_all is for.
        if p.is_dir() {
            return None;
        }
        // read_link BEFORE exists(): `exists()` follows symlinks, so a dangling
        // one answers false there and would be misread as "not created yet".
        if let Ok(t) = fs::read_link(p) {
            return Some(format!(
                "{} is a symlink to {}, and that path does not resolve here. On Android \
                 /sdcard points into the per-user storage namespace, which a root shell \
                 started by `su` from adb does not always share -- mkdir then answers \
                 EEXIST for the symlink itself, which reads as \"File exists\" for a \
                 directory that does not exist. Pass a real path instead: \
                 nomount export /data/local/tmp",
                p.display(),
                t.display()
            ));
        }
        if p.exists() {
            return Some(format!("{} exists and is not a directory", p.display()));
        }
        // Absent, and not a dangling link: keep walking up.
    }
    None
}

/// `nomount export [dir]` — dump diagnostics to a timestamped, stealth-named
/// folder (default under /sdcard/Download) for sharing. Best-effort per file.
pub fn run_export(dir: Option<String>) -> Result<()> {
    let ts = read_cmd("date", &["+%Y%m%d-%H%M%S"]);
    // `read_cmd` answers "" on any spawn failure, and an empty stamp collapses
    // every export into the single directory `<base>/nm-diag-` -- which
    // create_dir_all then happily reuses, so the second run overwrites the first
    // file-for-file with no warning. Epoch seconds are not pretty but they are
    // unique, which is the only property the name has to have.
    let ts = if ts.is_empty() {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            .to_string()
    } else {
        ts
    };
    let base = dir.unwrap_or_else(|| "/sdcard/Download".to_string());
    let out = format!("{base}/nm-diag-{ts}");
    // Ask about the BASE before creating the leaf, so the error names the real
    // obstacle. See `base_unusable`: without this, the default destination
    // produced "create /sdcard/Download/nm-diag-… Caused by: File exists" for a
    // directory that does not exist and never did.
    if let Some(why) = base_unusable(Path::new(&base)) {
        anyhow::bail!("cannot export to {base}: {why}");
    }
    fs::create_dir_all(&out).with_context(|| format!("create {out}"))?;

    let nm = Nm::new();
    // An export that silently omits a file is worse than one that fails loudly:
    // the whole point is handing someone a complete picture, and a missing
    // section reads as "the tool had nothing to say" rather than "the write
    // failed". Shared storage is exactly where writes DO fail (permissions,
    // full volume, a scanner deleting flagged files).
    // Plain `fs::write`, deliberately -- the ONE writer in this crate that is not
    // `statefile::write_atomic`. These files are a fresh timestamped dump, not
    // state: nothing reads them back, there is no previous version a half-write
    // could destroy, and the destination is usually the FUSE view of shared
    // storage, where a temp-then-rename buys nothing and adds a second way to fail.
    let write = |name: &str, content: &str| {
        if let Err(e) = fs::write(format!("{out}/{name}"), content) {
            eprintln!("nomount: export: could not write {name}: {e} — this diagnostic is INCOMPLETE");
        }
    };

    // RESOLVED, and matched on path COMPONENTS. Both halves were wrong, and the
    // consequence of either is the whole secret this guard exists to keep.
    //
    // The list itself was patched by hand once already: /data/media/0 is the REAL
    // backing store of /sdcard on A11+ and the path a root shell naturally types,
    // so `nomount export /data/media/0/Download` read as PRIVATE and wrote
    // `uidhide`, `uidhide.cache` and `spoof.conf` -- the files that name exactly
    // which detectors are being hidden from -- into storage any app with a storage
    // permission can read. Adding that one spelling did not close the hole,
    // because the test was `String::starts_with` on the caller's raw argument:
    //
    //   `//sdcard/Download`                  -- "//s" vs "/sd", no match
    //   `/data/local/../media/0/Download`    -- no match, and resolves to the store
    //   a symlink pointing anywhere at all   -- no match
    //
    // and, in the other direction, `/data/media0/…` matched `/data/media` because
    // a raw prefix has no notion of a path boundary.
    //
    // So resolve first (the directory exists by now -- create_dir_all is above),
    // and compare with `Path::starts_with`, which is component-wise and normalises
    // a `//` root. Both the resolved and the literal form are tested and EITHER
    // matching means shared: canonicalize can fail, and "could not tell" has to
    // fall to the private-withholding side, never away from it.
    let resolved = fs::canonicalize(&out).unwrap_or_else(|_| PathBuf::from(&out));
    let shared = is_shared_storage(&resolved) || is_shared_storage(Path::new(&out));

    // The fingerprint, under its own name. The full report goes in check.txt
    // below; this file is the flat key=value form a bug report is skimmed for.
    // ...and a FAILED build says so. `unwrap_or_default()` wrote a zero-byte
    // fingerprint.txt, which is exactly the silence the `write` closure above
    // refuses: a missing section reads as "the tool had nothing to say".
    //
    // Written AFTER `shared` is known, because it carries `served_matches_rule=`,
    // which on a drifting device names the served path -- and for an absorbed
    // patched APK that is /data/app/~~x/com.pkg-y/base.apk, i.e. which app on this
    // phone has a patched APK. Same filter as the on-disk health.txt below.
    let fingerprint = fingerprint_text().unwrap_or_else(|e| format!("(fingerprint failed: {e:#})\n"));
    let fingerprint =
        if shared { redact_for_shared("health.txt", &fingerprint) } else { fingerprint };
    write("fingerprint.txt", &fingerprint);
    // On shared storage the ` [UID: n]` suffix on a per-UID rule names an appid we
    // are hiding from -- the same secret as the hide list -- so strip it there.
    let rules = nm.list().unwrap_or_else(|e| format!("(nm list failed: {e})"));
    let rules = if shared {
        rules
            .lines()
            .map(|l| l.split(" [UID:").next().unwrap_or(l).trim_end())
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        rules
    };
    write("rules.txt", &rules);
    // The live hidden set is the same secret as the hide list itself -- it names
    // the appids you are hiding from -- so it obeys the same rule. It used to be
    // written unconditionally, which handed exactly that to shared storage on
    // every WebUI export (the default destination is /sdcard/Download).
    if !shared {
        // Name the failure. `unwrap_or_default()` wrote the literal `[]`, which on
        // the destination the tool tells you to use for the full picture reads as
        // "nothing is hidden right now" -- the single most misleading line a bug
        // report titled "hiding is not working" could carry. `rules.txt` sixteen
        // lines above already does it this way.
        write(
            "uid_live.txt",
            &match nm.uid_list_live() {
                Ok(v) => format!("{v:?}"),
                Err(e) => format!("(nm uid list failed: {e:#})"),
            },
        );
    }
    let self_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "nomount".to_string());
    // Two checks name something off the hide list, and NM_REDACT_HIDE_LIST tells
    // both to withhold it for a shared destination: the plan section's "stale
    // legacy blocklist entries" finding prints hidden package names (M-S2 in
    // doctor.rs), and the device section's PM-open probe prints the appid it
    // dropped to (audit.rs). The second one was NOT gated, so this function
    // withheld `uid_live.txt` and stripped the ` [UID: n]` suffixes from
    // rules.txt and then published the same secret in check.txt -- with the note
    // below claiming otherwise. Both read `blocklist::redact_hide_list()` now, so
    // a third reader cannot be added without finding the test.
    //
    // Re-EXECs rather than calling `check::build` in-process, and deliberately:
    // several device checks fork and drop privileges, and one of them has already
    // been the reason this ran in a child. The subprocess also keeps a panic or a
    // hang inside a probe from taking the export with it.
    //
    // No shell. The old form built `NM_REDACT_HIDE_LIST=1 '<self_exe>' doctor`
    // and handed it to `sh -c`, with `self_exe` dropped into single quotes but
    // NOT escaped -- while two other call sites in this crate (`app_size` above
    // and `whiteout::app_can_see`) correctly escape the same way. Running the
    // binary from a path containing a quote was all it took, and the shell was
    // only ever there to set one environment variable. `Command::env` does that
    // without a shell at all, so there is nothing left to quote.
    let mut checker = Command::new(&self_exe);
    checker.arg("check");
    if shared {
        checker.env("NM_REDACT_HIDE_LIST", "1");
    }
    let check_out = checker
        .output()
        .map(|o| {
            let mut t = String::from_utf8_lossy(&o.stdout).into_owned();
            t.push_str(&String::from_utf8_lossy(&o.stderr));
            t
        })
        .unwrap_or_else(|e| format!("could not run {self_exe} check: {e}"));
    write("check.txt", &check_out);
    // `2>/dev/null || true` collapsed "the engine logged nothing" and "dmesg is
    // restricted" into the same empty file. kernel.dmesg_restrict=1 is the default
    // on production Android and SELinux denies syslog_read in plenty of contexts,
    // so the commonest cause of that empty file is a permission -- and the reader
    // concludes the kernel driver printed nothing at all, which is the most
    // alarming reading available. Keep the grep, drop the swallow, and say both.
    let dmesg = read_cmd("sh", &["-c", "dmesg 2>&1 | grep -i nomount"]);
    write(
        "dmesg-nomount.txt",
        if dmesg.is_empty() {
            "(no nomount lines — or dmesg is restricted on this device; check `sysctl kernel.dmesg_restrict`)\n"
        } else {
            &dmesg
        },
    );
    // Same rule: an empty mountinfo.txt in a bundle whose whole subject is often
    // the mount table reads as "there are no mounts".
    write(
        "mountinfo.txt",
        &fs::read_to_string("/proc/self/mountinfo")
            .unwrap_or_else(|e| format!("(could not read /proc/self/mountinfo: {e})\n")),
    );
    write("uname.txt", &read_cmd("uname", &["-a"]));

    // Shared storage is readable by any app holding a storage permission, and the
    // point of an export is to hand it to someone. `uidhide` names the apps you are
    // hiding FROM -- publishing it there tells a detector exactly that -- its
    // `.cache` spells out the resolved appid for each, and `spoof.conf` describes
    // what is being spoofed. They go only to a destination that is not shared
    // storage; the diagnostics that matter for a bug report do not include any.
    //
    // `boot.log` is on this list, and it used NOT to be. It was added to the
    // bundle because the bug-report template asks for it by name, on the
    // justification that it "carries counts and paths, never package names". The
    // code disproves that: `module/service.sh` and `module/uidwatch.sh` both
    // capture `nomount uid apply`'s STDERR (`_bl=$(… 2>&1)`) into `nmlog`, and
    // `cli/handlers.rs` prints hide-list entries there --
    // "nomount: *.settings matches com.android.settings (appid 1000, below the app
    // range) …" was reproduced on an OP15 on 2026-09-08 with one glob in the hide
    // list. The project already treats the file as a secret on-device
    // (`module/lib.sh` chmods it 0600); copying it to /sdcard/Download downgrades
    // a deliberately root-only file to any-app-readable. Line-by-line filtering is
    // not an option here -- the leak surface is unbounded prose.
    const PRIVATE: &[&str] =
        &["uidhide", "uidhide.cache", "uidhide.conf", "spoof.conf", "boot.log"];
    // `blocklist` is NOT on it, and is filtered instead. `blocklist::migrate_legacy`
    // COPIES hide-list entries out of it into `uidhide` by explicit design (deleting
    // an entry that really is a module id would let a self-mounting module inject
    // and break boot), and nothing ever prunes the original -- so on any device
    // upgraded from a pre-split Suite the file still holds hidden-app package names.
    // doctor.rs knows this and redacts them ("Measured on OP15 2026-08-21: four
    // package names still there"); this loop published the raw file next to the
    // redacted report. What is left after the filter -- ids of modules that are
    // actually installed -- is the file's only remaining meaning, so it is worth
    // keeping rather than withholding wholesale.
    let mut withheld: Vec<&str> = Vec::new();
    for f in [
        "uidhide", "uidhide.cache", "uidhide.conf", "blocklist", "spoof.conf",
        "incident.log", "health.txt", "snapshot.txt", "boot.log",
    ] {
        let src = format!("{NM_DIR}/{f}");
        if shared && PRIVATE.contains(&f) {
            // Name only what was actually there. `PRIVATE` is a constant, and
            // printing it whole announced four withheld files on a device that has
            // never hidden an app -- then told the reader to re-run to a private
            // path "to include them in full", where they would get nothing.
            if Path::new(&src).exists() {
                withheld.push(f);
            }
            continue;
        }
        if let Ok(c) = fs::read_to_string(&src) {
            let c = if shared { redact_for_shared(f, &c) } else { c };
            write(f, &c);
        }
    }
    println!("exported to {out}");
    if shared {
        // Name only files that were actually there. `PRIVATE.join(", ")` was
        // printed unconditionally, so a device that has never hidden an app was
        // told four files had been withheld and to re-run to a private path "to
        // include them in full" -- where it would get nothing. The rest of the
        // sentence is true on every shared destination: the UID-suffix strip, the
        // NM_REDACT_HIDE_LIST run and the filters below are unconditional there.
        let left_out = if withheld.is_empty() {
            String::new()
        } else {
            format!("{} left out — they name the apps you are hiding from. ", withheld.join(", "))
        };
        println!(
            "note: {left_out}{out} is shared storage, readable by any app with a storage \
             permission, so the hide list was kept out of it: rules.txt UID suffixes, the \
             check report's hide-list names, any package name left in blocklist and any \
             /data/app path in the fingerprint were redacted in place. Pass a private path \
             for the unredacted bundle: nomount export /data/adb/nomount"
        );
    }
    Ok(())
}

/// One exported state file, filtered for a SHARED destination.
///
/// The `PRIVATE` list withholds whole files; this handles the two that are worth
/// keeping once the secret is taken out of them.
///
/// `blocklist` keeps only the lines that name an INSTALLED module -- everything
/// else in that file is a copied hide-list entry (see `blocklist::migrate_legacy`,
/// which copies and never prunes). Over-dropping is the safe direction here: a
/// stale id for a module that has since been uninstalled is worth less than the
/// certainty that no package name survives.
///
/// `health.txt`/`snapshot.txt` keep everything except an absorbed APK's path.
/// `drift_probe` renders a failing rule as `drift:/data/app/~~x/com.pkg-y/base.apk(…)`,
/// so the `served_matches_rule=` and `consistency=` lines can name which app on
/// this phone has a patched APK -- the same class of secret as the hide list, and
/// it only appears on an already-unhealthy device, i.e. exactly when an export is
/// being collected.
fn redact_for_shared(name: &str, body: &str) -> String {
    let keep_installed = |l: &&str| -> bool {
        let t = l.trim();
        t.is_empty()
            || t.starts_with('#')
            || Path::new(crate::mount::MODULES_DIR).join(t).is_dir()
    };
    // A rebuilt document keeps its trailing newline: these are text files someone
    // will `cat`, and `lines().join("\n")` silently eats it.
    let rejoin = |v: Vec<String>| -> String {
        let mut s = v.join("\n");
        if body.ends_with('\n') && !s.is_empty() {
            s.push('\n');
        }
        s
    };
    match name {
        "blocklist" => {
            rejoin(body.lines().filter(keep_installed).map(str::to_string).collect())
        }
        // Untouched byte-for-byte when there is nothing to take out, which is the
        // healthy device: `served_matches_rule=ok` carries no path at all.
        "health.txt" | "snapshot.txt" if body.contains("/data/app/") => {
            rejoin(body.lines().map(redact_app_paths).collect())
        }
        _ => body.to_string(),
    }
}

/// One `key=value` fingerprint line with any `/data/app/…` path blanked.
///
/// Pure and separate so the digits-must-not-survive rule can be tested without a
/// device. Kept deliberately blunt: it does not try to parse the drift string, it
/// replaces every whitespace-delimited token that starts with `/data/app/`.
fn redact_app_paths(line: &str) -> String {
    if !line.contains("/data/app/") {
        return line.to_string();
    }
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(i) = rest.find("/data/app/") {
        out.push_str(&rest[..i]);
        out.push_str("/data/app/<redacted>");
        // To the end of this token: the path is embedded in `drift:<t>(rule=<s> …)`,
        // so stop at the first character that cannot be inside a path here.
        let tail = &rest[i..];
        let end = tail.find([' ', '(', ')', ',']).unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The export destination's parent, judged in the three states that matter.
    ///
    /// The dangling-symlink row is the DEFAULT destination on the commonest
    /// invocation. Measured on an OP15, 2026-09-07, from `adb shell su`:
    /// `/sdcard` is a symlink to `/storage/self/primary`, which does not resolve
    /// in that shell's mount namespace, so `create_dir_all` walked up to
    /// `mkdir("/sdcard")`, got EEXIST for the symlink, found `is_dir()` false and
    /// surfaced "create /sdcard/Download/nm-diag-… Caused by: File exists" -- for
    /// a directory that has never existed. The reader goes looking for a stale
    /// export to delete.
    #[test]
    fn an_unresolvable_export_base_is_named_instead_of_reported_as_existing() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();

        // A real directory: nothing in the way.
        assert_eq!(base_unusable(d.path()), None);

        // Absent, and not a link: create_dir_all builds the whole chain.
        assert_eq!(base_unusable(&d.path().join("not/here/yet")), None);

        // The /sdcard case -- and it has to be caught through the path the user
        // actually types, which names the link's CHILD. Checking only the base was
        // the first attempt, and the phone refused it on the spot: exporting to
        // `<dangling>/Download` still produced the bare "File exists".
        let dangling = d.path().join("sdcard");
        symlink("/storage/self/primary", &dangling).unwrap();
        let why = base_unusable(&dangling.join("Download"))
            .expect("a dangling ANCESTOR must be refused, not just a dangling base");
        assert!(why.contains("symlink"), "must name the symlink: {why}");
        assert!(
            why.contains("/storage/self/primary"),
            "must name where it points: {why}"
        );
        assert!(
            why.contains("sdcard") && !why.contains("Download"),
            "must name the ancestor that is the obstacle, not the path typed: {why}"
        );
        // Same link, asked about directly.
        assert!(base_unusable(&dangling).is_some());
        // It may quote the misleading errno -- it SHOULD, that is the string the
        // reader arrived with -- but only while explaining it away.
        assert!(
            why.contains("does not resolve") && why.contains("does not exist"),
            "must explain the EEXIST rather than restate it: {why}"
        );

        // Something that is not a directory at all.
        let f = d.path().join("afile");
        fs::write(&f, b"x").unwrap();
        assert!(base_unusable(&f).is_some_and(|w| w.contains("not a directory")));
    }

    /// `verify` had NO test proving it detects anything: the comparison lived
    /// inside a function that reads a file and prints, so the only observation
    /// ever made of it was "agrees with a snapshot taken seconds ago". These pin
    /// the four outcomes that matter.
    ///
    /// A changed VALUE is the everyday case -- a module installed, an app hidden,
    /// the guard disarmed.
    #[test]
    fn drift_names_a_changed_field() {
        let saved = "engine=v30\nrules=257\nblocked=19\nts=1\n";
        let live = "engine=v30\nrules=260\nblocked=19\nts=2\n";
        let d = drift_lines(saved, live);
        assert_eq!(d, vec!["DRIFT rules: snapshot=257 -> live=260"]);
    }

    /// `ts` moves on every call by construction. If it counted, every verify on
    /// an untouched device would report drift and the verb would be worthless.
    #[test]
    fn drift_ignores_the_timestamp() {
        let saved = "engine=v30\nrules=257\nts=1788327280\n";
        let live = "engine=v30\nrules=257\nts=1788399999\n";
        assert!(drift_lines(saved, live).is_empty(), "ts must not count as drift");
    }

    /// A field the LIVE fingerprint gained. Already worked; pinned so it keeps
    /// working alongside the fix below.
    #[test]
    fn drift_reports_a_field_only_live_has() {
        let saved = "engine=v30\n";
        let live = "engine=v30\nguard=armed\n";
        assert_eq!(drift_lines(saved, live), vec!["DRIFT guard: snapshot=<absent> -> live=armed"]);
    }

    /// A field the SNAPSHOT has and live no longer emits. This is the one the
    /// original missed entirely: it walked live's fields and looked each up in the
    /// snapshot, so a key that vanished from live was never visited and `verify`
    /// printed a clean bill. The scenario is a Suite upgrade that drops or renames
    /// a fingerprint field, which is precisely when a stale baseline must speak up.
    #[test]
    fn drift_reports_a_field_the_snapshot_had_and_live_lost() {
        let saved = "engine=v30\nmanager_umount=off\n";
        let live = "engine=v30\n";
        assert_eq!(
            drift_lines(saved, live),
            vec!["DRIFT manager_umount: snapshot=off -> live=<absent>"],
            "a field disappearing from the fingerprint must not read as no-drift"
        );
    }

    /// Identical inputs are the pass case, and it must survive key REORDERING --
    /// the comparison is by key, not by line position.
    #[test]
    fn drift_is_empty_for_the_same_fingerprint_in_any_order() {
        let saved = "engine=v30\nrules=257\nguard=armed\nts=1\n";
        let live = "guard=armed\nts=9\nengine=v30\nrules=257\n";
        assert!(drift_lines(saved, live).is_empty());
    }

    /// Several fields at once, both directions in one comparison.
    #[test]
    fn drift_reports_every_moved_field_not_just_the_first() {
        let saved = "engine=v30\nrules=257\nmanager_umount=off\n";
        let live = "engine=v31\nrules=260\nguard=armed\n";
        let d = drift_lines(saved, live);
        assert_eq!(d.len(), 4, "expected 2 changed + 1 gained + 1 lost, got {d:?}");
        assert!(d.iter().any(|l| l.contains("engine") && l.contains("v30") && l.contains("v31")));
        assert!(d.iter().any(|l| l.contains("manager_umount") && l.contains("<absent>")));
        assert!(d.iter().any(|l| l.contains("guard") && l.contains("<absent>")));
    }

    fn fp(engine: &str, rules: usize) -> Fingerprint {
        Fingerprint {
            version: "test".into(),
            uname: "test".into(),
            engine: engine.into(),
            rules,
            whiteouts: 0,
            mounts: Some(0),
            blocked: "0".into(),
            consistency: "unchecked".into(),
            served_matches_rule: "unchecked".into(),
            guard: "armed".into(),
            mounts_foreign: Some(0),
            manager_umount: "off".into(),
        }
    }

    /// The verdict TAG, not the enum: `Verdict` deliberately derives only what
    /// its ordering needs, and a test is not a reason to widen a production type.
    fn verdict_of(fp: &Fingerprint, id: &str) -> &'static str {
        fp.checks()
            .into_iter()
            .find(|c| c.id == crate::check::slug(id))
            .unwrap_or_else(|| panic!("no check named {id}"))
            .verdict
            .tag()
    }

    /// The spellings a raw `String::starts_with` on the caller's argument could
    /// not see. Each one publishes `uidhide` — the list of apps being hidden
    /// from — to storage any app with a storage permission can read.
    #[test]
    fn every_spelling_of_shared_storage_is_recognised() {
        for p in [
            "/sdcard/Download/nm-diag-1",
            "//sdcard/Download/nm-diag-1",          // "//s" vs "/sd" under str::starts_with
            "/storage/emulated/0/Download/nm-diag-1", // what /sdcard resolves to
            "/data/media/0/Download/nm-diag-1",
            "/mnt/user/0/emulated/0/x",
            "/mnt/media_rw/ABCD-1234/x",
            "/mnt/expand/abcd/user/0/x",
        ] {
            assert!(is_shared_storage(Path::new(p)), "{p} is shared storage");
        }
    }

    /// ...and the other direction: a raw prefix has no notion of a path boundary,
    /// so it called `/data/media0` shared. Withholding the hide list from a
    /// private destination is not harmless — it is the destination the export
    /// tells you to pass when you want the full picture.
    #[test]
    fn private_destinations_are_not_mistaken_for_shared_ones() {
        for p in [
            "/data/adb/nomount/nm-diag-1",
            "/data/local/tmp/nm-diag-1",
            "/data/media0/x",   // NOT under /data/media
            "/storagex/x",      // NOT under /storage
            "/mnt/vendor/persist/x",
        ] {
            assert!(!is_shared_storage(Path::new(p)), "{p} is not shared storage");
        }
    }

    /// "Nothing to test" is only honest while the engine is ANSWERING.
    ///
    /// `gather` reads the rule list with unwrap_or_default, so a driver that is
    /// down produces zero rules exactly as a device with nothing to inject does.
    /// Both probes then reported N/A -- a measured "there is nothing here" --
    /// for a question that could not be put at all.
    #[test]
    fn zero_rules_is_only_not_applicable_when_the_engine_answered() {
        let up = fp("v26", 0);
        assert_eq!(verdict_of(&up, "per-UID consistency canary"), "N/A");
        assert_eq!(verdict_of(&up, "served bytes match the rule"), "N/A");

        let down = fp("down", 0);
        assert_eq!(verdict_of(&down, "per-UID consistency canary"), "UNMEASURED");
        assert_eq!(verdict_of(&down, "served bytes match the rule"), "UNMEASURED");

        // With rules live, an unchecked probe is unmeasured either way.
        let serving = fp("v26", 12);
        assert_eq!(verdict_of(&serving, "per-UID consistency canary"), "UNMEASURED");

        // ...and the third state the test did not have: the engine ANSWERED
        // `version` and then refused the rule dump. `rules` is 0 and `engine` is a
        // version, which is exactly the shape of a device with nothing to inject --
        // so without its own probe string both rows rendered N/A and asserted "No
        // module here provides files to inject" / "There are no rules" about a
        // module set nobody managed to look at.
        let mut mute = fp("v30", 0);
        mute.consistency = "unchecked:engine-list-failed".into();
        mute.served_matches_rule = "unchecked:engine-list-failed".into();
        assert_eq!(verdict_of(&mute, "per-UID consistency canary"), "UNMEASURED");
        assert_eq!(verdict_of(&mute, "served bytes match the rule"), "UNMEASURED");

        // The probe harness failing is not the device failing. `su`/`stat`
        // unavailable used to render `mismatch:…(app=ENOENT)` -> FAIL, owned by
        // "the kernel engine", i.e. a kernel rebuild proposed for a shell problem.
        let mut noprobe = fp("v30", 12);
        noprobe.consistency = "unchecked:probe-unavailable".into();
        assert_eq!(verdict_of(&noprobe, "per-UID consistency canary"), "UNMEASURED");
        noprobe.consistency = "unchecked:probe-uid-unknown".into();
        assert_eq!(verdict_of(&noprobe, "per-UID consistency canary"), "UNMEASURED");

        // And a real divergence still fails, loudly. The four can't-tell states
        // above must not have swallowed the one thing this canary exists for.
        let mut bad = fp("v30", 12);
        bad.consistency = "mismatch:/system/etc/x(root=12 app=ENOENT)".into();
        assert_eq!(verdict_of(&bad, "per-UID consistency canary"), "FAIL");
    }

    /// The export's shared-storage filter, on the two files that keep their place
    /// in the bundle once the secret is taken out of them.
    ///
    /// `blocklist` is the one measured on a device: `blocklist::migrate_legacy`
    /// COPIES hide-list entries into `uidhide` and nothing ever prunes the
    /// original, so on an upgraded device it still holds package names -- which
    /// doctor.rs redacts in `check.txt` while this loop published the raw file
    /// beside it.
    #[test]
    fn a_shared_export_filters_the_files_it_still_includes() {
        // No module directory exists under /data/adb/modules in a test, so every
        // bare name is dropped -- which is the safe direction and what the
        // upgraded-device case looks like.
        let body = "# a comment\n\ncom.example.bank\nsome_module_id\n";
        let got = redact_for_shared("blocklist", body);
        assert!(!got.contains("com.example.bank"), "a package name must not survive: {got:?}");
        assert!(got.contains("# a comment"), "comments are diagnostic, keep them: {got:?}");
        // A private destination is not filtered at all -- the caller does not call
        // this there, which is the whole point of passing a private path.

        // Files with no rule of their own pass through byte-for-byte.
        assert_eq!(redact_for_shared("incident.log", body), body);
    }

    /// An absorbed patched APK's path names which app on this phone is patched.
    /// It reaches `health.txt` (and `fingerprint.txt`) through
    /// `served_matches_rule=drift:<target>(rule=<source> …)`, and only on an
    /// already-unhealthy device -- i.e. exactly when an export is collected.
    #[test]
    fn a_shared_export_keeps_data_app_paths_out_of_the_fingerprint() {
        let line = "served_matches_rule=drift:/data/app/~~aB1/com.mybank.app-x9/base.apk\
                    (rule=/data/adb/modules/M/x size 10 vs 12)";
        let got = redact_app_paths(line);
        assert!(!got.contains("com.mybank.app"), "the package must not survive: {got}");
        assert!(!got.contains("~~aB1"), "nor the install directory: {got}");
        // The finding is still readable: the key, the verb and the rule source stay.
        assert!(got.starts_with("served_matches_rule=drift:/data/app/<redacted>"), "{got}");
        assert!(got.contains("/data/adb/modules/M/x"), "the module source is not a secret: {got}");
        assert!(got.contains("size 10 vs 12"), "{got}");

        // Untouched when there is nothing to redact -- including the ordinary
        // healthy value, which must survive verbatim or `verify` would report
        // drift on every export.
        assert_eq!(redact_app_paths("served_matches_rule=ok"), "served_matches_rule=ok");
        assert_eq!(redact_app_paths("rules=257"), "rules=257");

        // ...and it is applied through the file filter, not only by hand.
        let doc = "rules=257\nserved_matches_rule=drift:/data/app/com.x-1/base.apk (bytes differ)\n";
        assert!(!redact_for_shared("health.txt", doc).contains("com.x-1"));
        assert!(redact_for_shared("health.txt", doc).contains("rules=257"));
    }

    /// The three shapes this module's own parser got wrong before it was deleted.
    ///
    /// It split on the FIRST ` -> `, so a target containing one lost its tail and
    /// gained a source that does not exist; and it peeled neither ` (public)` nor
    /// ` [UID: N]`, so those suffixes ended up inside the source path. Every
    /// consumer here reads `source` off the filesystem -- `drift_probe` stats and
    /// hashes it, `consistency_probe` derives the owning module from it -- so a
    /// mangled source silently dropped exactly the PM-published and per-UID rules
    /// from both probes and still reported "ok".
    #[test]
    fn the_shared_parser_survives_the_three_shapes_the_local_one_mangled() {
        let list = "/system/etc/a -> b -> /data/adb/modules/M/system/etc/ab\n\
                    /product/overlay/F.apk -> /data/adb/modules/M/product/overlay/F.apk (public)\n\
                    /system/lib64/libx.so -> /data/adb/modules/M/system/lib64/libx.so [UID: 10123]\n\
                    /system/etc/gone (whiteout)\n\
                    /system/etc/vdir (virtual dir)\n";
        let live = crate::nm::parse_list(list);
        let injects: Vec<_> =
            live.iter().filter(|r| r.kind == crate::nm::LiveKind::Inject).collect();
        assert_eq!(injects.len(), 3, "the fingerprint's `rules` count");

        // Split on the LAST arrow: the target keeps its embedded ` -> `.
        assert_eq!(injects[0].target, Path::new("/system/etc/a -> b"));
        assert_eq!(
            injects[0].source.as_deref(),
            Some(Path::new("/data/adb/modules/M/system/etc/ab"))
        );

        // ` (public)` peeled off the source, not folded into it.
        assert_eq!(
            injects[1].source.as_deref(),
            Some(Path::new("/data/adb/modules/M/product/overlay/F.apk"))
        );
        assert!(injects[1].public);

        // ` [UID: N]` likewise, and the uid is kept.
        assert_eq!(
            injects[2].source.as_deref(),
            Some(Path::new("/data/adb/modules/M/system/lib64/libx.so"))
        );
        assert_eq!(injects[2].uid, 10123);

        // And the fingerprint's `whiteouts` count still sees only the whiteout.
        assert_eq!(
            live.iter().filter(|r| r.kind == crate::nm::LiveKind::Whiteout).count(),
            1
        );
    }
}
