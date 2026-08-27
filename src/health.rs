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
use std::path::Path;
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
                     owned that path and never took effect. Check whether a module binds the \
                     same path from its post-fs-data.sh: if one does, delete that bind and \
                     reboot, and the rule will serve it with nothing shadowing it.",
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
        if crate::absorb::module_dir_of(&src)
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
fn consistency_probe(rules: &[(String, String)], probe_uid_hidden: bool) -> String {
    if probe_uid_hidden {
        return "unchecked:probe-uid-hidden".to_string();
    }
    // Sampling first-6-in-hash-order could sit entirely on one partition served by
    // one module, and a d_drop-class regression can be confined to a single
    // partition. Stratify by (partition, owning module) and take round-robin across
    // buckets, so the sample spans the rule set. Budget bounds the `su` calls.
    const BUDGET: usize = 18;
    let mut buckets: std::collections::BTreeMap<(String, String), Vec<&str>> =
        std::collections::BTreeMap::new();
    for (target, src) in rules.iter() {
        let partition = target
            .trim_start_matches('/')
            .split('/')
            .next()
            .unwrap_or("")
            .to_string();
        let module = crate::absorb::module_dir_of(Path::new(src))
            .and_then(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_default();
        buckets.entry((partition, module)).or_default().push(target.as_str());
    }
    let mut sample: Vec<&str> = Vec::new();
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

    // Injected regular files only (skip virtual dirs / whiteouts which have no size).
    let mut checked = 0;
    for target in sample {
        let root = fs::metadata(target).ok().map(|m| m.len().to_string());
        let Some(root_sz) = root else { continue };
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

fn parse_rules(list: &str) -> Vec<(String, String)> {
    list.lines()
        .filter_map(|l| l.split_once(" -> ").map(|(t, s)| (t.trim().to_string(), s.trim().to_string())))
        .collect()
}

pub fn gather() -> Fingerprint {
    let nm = Nm::new();
    let engine = nm.version().map(|v| format!("v{v}")).unwrap_or_else(|_| "down".into());
    let list = nm.list().unwrap_or_default();
    let rules = parse_rules(&list);
    let whiteouts = list.lines().filter(|l| l.contains("(whiteout)")).count();
    // Distinguish "nothing hidden" from "couldn't ask": `nm l u` fails loudly on
    // EPERM / engine-down, and reporting that as 0 hidden reads as a working
    // feature with an empty list.
    let live = nm.uid_list_live();
    let blocked = match &live {
        Ok(v) => v.len().to_string(),
        Err(_) => "unknown".to_string(),
    };
    let probe_hidden = live
        .as_ref()
        .map(|v| v.iter().any(|u| crate::blocklist::appid(*u) == PROBE_UID))
        .unwrap_or(false);
    let guard = if Path::new("/data/adb/nomount/disabled").exists() {
        "tripped"
    } else {
        "armed"
    };
    let split = count_mounts_split();
    Fingerprint {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uname: read_cmd("uname", &["-r"]),
        engine,
        rules: rules.len(),
        whiteouts,
        mounts: split.map(|(t, _)| t),
        mounts_foreign: split.map(|(t, d)| t - d),
        blocked,
        consistency: consistency_probe(&rules, probe_hidden),
        served_matches_rule: drift_probe(&crate::nm::parse_list(&list)),
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
    fs::create_dir_all(NM_DIR).ok();
    fs::write(SNAPSHOT, &body).context("write snapshot.txt")?;
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

    // Parse both into key->value and compare (ignore ts).
    let kv = |txt: &str| -> Vec<(String, String)> {
        txt.lines()
            .filter_map(|l| l.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
            .filter(|(k, _)| k != "ts")
            .collect()
    };
    let (sv, lv) = (kv(&saved), kv(&live));
    let mut drift = 0;
    for (k, lval) in &lv {
        let sval = sv.iter().find(|(sk, _)| sk == k).map(|(_, v)| v.as_str()).unwrap_or("<absent>");
        if sval != lval {
            println!("DRIFT {k}: snapshot={sval} -> live={lval}");
            drift += 1;
        }
    }
    if drift == 0 {
        println!("verify: live matches snapshot (no drift)");
    } else {
        println!("verify: {drift} field(s) drifted from snapshot");
    }
    Ok(())
}

/// `nomount export [dir]` — dump diagnostics to a timestamped, stealth-named
/// folder (default under /sdcard/Download) for sharing. Best-effort per file.
pub fn run_export(dir: Option<String>) -> Result<()> {
    let ts = read_cmd("date", &["+%Y%m%d-%H%M%S"]);
    let base = dir.unwrap_or_else(|| "/sdcard/Download".to_string());
    let out = format!("{base}/nm-diag-{ts}");
    fs::create_dir_all(&out).with_context(|| format!("create {out}"))?;

    let nm = Nm::new();
    // An export that silently omits a file is worse than one that fails loudly:
    // the whole point is handing someone a complete picture, and a missing
    // section reads as "the tool had nothing to say" rather than "the write
    // failed". Shared storage is exactly where writes DO fail (permissions,
    // full volume, a scanner deleting flagged files).
    let write = |name: &str, content: &str| {
        if let Err(e) = fs::write(format!("{out}/{name}"), content) {
            eprintln!("nomount: export: could not write {name}: {e} — this diagnostic is INCOMPLETE");
        }
    };

    // The fingerprint, under its own name. The full report goes in check.txt
    // below; this file is the flat key=value form a bug report is skimmed for.
    write("fingerprint.txt", &fingerprint_text().unwrap_or_default());
    // /data/media/0 is the REAL backing store of /sdcard on A11+, and it is the
    // path a root shell naturally types -- so `nomount export /data/media/0/Download`
    // failed this test, skipped the PRIVATE guard below, and wrote `uidhide`,
    // `uidhide.cache` and `spoof.conf` -- files that name exactly which detectors
    // are being hidden from -- into storage any app with a storage permission can
    // read. The /mnt/user and /mnt/runtime views are the same store by other names.
    let shared = [
        "/sdcard",
        "/storage",
        "/mnt/sdcard",
        "/data/media",
        "/mnt/user",
        "/mnt/runtime",
        "/mnt/androidwritable",
        "/mnt/pass_through",
    ]
    .iter()
    .any(|p| out.starts_with(p));
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
        write("uid_live.txt", &format!("{:?}", nm.uid_list_live().unwrap_or_default()));
    }
    let self_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "nomount".to_string());
    // The plan section's "stale legacy blocklist entries" finding prints hidden
    // package names verbatim; NM_REDACT_HIDE_LIST tells it to withhold them for a
    // shared destination (see M-S2 in doctor.rs).
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
    write("dmesg-nomount.txt", &read_cmd("sh", &["-c", "dmesg | grep -i nomount 2>/dev/null || true"]));
    write("mountinfo.txt", &fs::read_to_string("/proc/self/mountinfo").unwrap_or_default());
    write("uname.txt", &read_cmd("uname", &["-a"]));

    // Shared storage is readable by any app holding a storage permission, and the
    // point of an export is to hand it to someone. `uidhide` names the apps you are
    // hiding FROM -- publishing it there tells a detector exactly that -- its
    // `.cache` spells out the resolved appid for each, and `spoof.conf` describes
    // what is being spoofed. They go only to a destination that is not shared
    // storage; the diagnostics that matter for a bug report do not include any.
    //
    // NB: `blocklist` is no longer one of them. It used to hold the hide list and
    // is now only module ids to skip injecting, so it is ordinary diagnostic data
    // -- but the secret moved with the content, and the guard has to move with it.
    const PRIVATE: &[&str] = &["uidhide", "uidhide.cache", "uidhide.conf", "spoof.conf"];
    for f in [
        "uidhide", "uidhide.cache", "uidhide.conf", "blocklist", "spoof.conf", "spoof.log",
        "incident.log", "health.txt", "snapshot.txt",
    ] {
        if shared && PRIVATE.contains(&f) {
            continue;
        }
        if let Ok(c) = fs::read_to_string(format!("{NM_DIR}/{f}")) {
            write(f, &c);
        }
    }
    println!("exported to {out}");
    if shared {
        // Name what was ACTUALLY withheld: the PRIVATE set (uidhide*, spoof.conf) --
        // NOT blocklist, which is now only module ids to skip and is included. The
        // rules.txt UID suffixes and doctor's hide-list names were redacted in place.
        println!(
            "note: {} were left out — {out} is shared storage, readable by any app with a \
             storage permission, and they name the apps you are hiding from (rules.txt UID \
             suffixes and doctor's hide-list names were redacted). Pass a private path to \
             include them in full: nomount export /data/adb/nomount",
            PRIVATE.join(", ")
        );
    }
    Ok(())
}
