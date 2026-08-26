//! Runtime health: the regression canary that would have caught the d_drop bug
//! on the first boot instead of a three-hour hunt.
//!
//! `doctor` lints the *plan* before a reboot. This module checks the *running*
//! system: is the engine live, are the injected files still byte-consistent, and
//! — the Narcissus canary — does a normal app see the same filesystem as root?
//! A per-UID divergence for an *unblocked* app is exactly the class of kernel
//! regression (d_drop, dcache poisoning) that a self-consistency detector flags.
//!
//! `snapshot` freezes a known-good fingerprint; `verify` diffs live-vs-snapshot
//! and names what drifted. `export` dumps diagnostics for sharing.

use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::nm::Nm;

const NM_DIR: &str = "/data/adb/nomount";
const SNAPSHOT: &str = "/data/adb/nomount/snapshot.txt";
const HEALTH: &str = "/data/adb/nomount/health.txt";

/// One line-based `key=value` fingerprint of the live system. Field order is
/// stable so a textual diff reads cleanly.
struct Fingerprint {
    version: String,
    uname: String,
    engine: String, // "vN" or "down"
    rules: usize,
    whiteouts: usize,
    /// `None` = the mount table could not be read. Rendered `unknown`, never 0.
    mounts: Option<usize>,
    blocked: String, // count, or "unknown" when the engine could not be asked
    consistency: String, // "ok" | "mismatch:<path>(root=A app=B)" | "unchecked"
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
    fn to_text(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "version={}", self.version);
        let _ = writeln!(s, "uname={}", self.uname);
        let _ = writeln!(s, "engine={}", self.engine);
        let _ = writeln!(s, "rules={}", self.rules);
        let _ = writeln!(s, "whiteouts={}", self.whiteouts);
        let unk = |v: Option<usize>| v.map_or_else(|| "unknown".to_string(), |n| n.to_string());
        let _ = writeln!(s, "mounts={}", unk(self.mounts));
        let _ = writeln!(s, "mounts_foreign={}", unk(self.mounts_foreign));
        let _ = writeln!(s, "blocked={}", self.blocked);
        let _ = writeln!(s, "consistency={}", self.consistency);
        let _ = writeln!(s, "guard={}", self.guard);
        let _ = writeln!(s, "manager_umount={}", self.manager_umount);
        s
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

fn parse_rules(list: &str) -> Vec<(String, String)> {
    list.lines()
        .filter_map(|l| l.split_once(" -> ").map(|(t, s)| (t.trim().to_string(), s.trim().to_string())))
        .collect()
}

fn gather() -> Fingerprint {
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
        guard: guard.to_string(),
        manager_umount: match crate::manager::kernel_umount_enabled() {
            Some(true) => "on".to_string(),
            Some(false) => "off".to_string(),
            None => "unknown".to_string(),
        },
    }
}

/// `nomount selfcheck [--write]` — runtime health, human-readable. With `--write`
/// it also persists to health.txt (service.sh calls this at boot_completed).
/// Exit is non-zero when the consistency canary or guard indicates trouble.
pub fn run_selfcheck(write: bool, json: bool) -> Result<()> {
    let fp = gather();
    let ok_guard = fp.guard == "armed";
    let ok_engine = fp.engine != "down";
    let mismatch = fp.consistency.starts_with("mismatch");
    // A bare "unchecked" means the canary could sample no injected file at all
    // (every target failed to stat, or there were none): it is NOT a pass and NOT
    // a hard failure -- a third, honest state. "unchecked:probe-uid-hidden" is a
    // legitimate can't-check by design and stays healthy.
    let unverified = fp.consistency == "unchecked";

    if !json {
        print!("{}", fp.to_text());
    }
    let verdict = if mismatch {
        "PER-UID INCONSISTENCY (injection visible to a normal app differently than root)"
    } else if !ok_engine {
        "ENGINE DOWN"
    } else if !ok_guard {
        "GUARD TRIPPED"
    } else if unverified {
        "unverified (consistency canary sampled no injected file)"
    } else {
        "healthy"
    };
    if json {
        use crate::json::J;
        // The fingerprint is already a flat key=value document, so it maps
        // straight onto an object -- no second description of the same fields to
        // drift from the first.
        let mut fields: Vec<(String, String)> = Vec::new();
        for line in fp.to_text().lines() {
            if let Some((k, v)) = line.split_once('=') {
                fields.push((k.to_string(), v.to_string()));
            }
        }
        let doc = J::Obj(vec![
            ("kind", J::s("selfcheck")),
            ("verdict", J::s(verdict)),
            // The states the caller actually branches on, as booleans. The WebUI
            // used to regex `verdict=(.+)` and ladder on prose.
            ("healthy", J::Bool(!mismatch && ok_engine && ok_guard && !unverified)),
            ("engine_up", J::Bool(ok_engine)),
            ("guard_armed", J::Bool(ok_guard)),
            ("consistency_mismatch", J::Bool(mismatch)),
            ("consistency_unverified", J::Bool(unverified)),
            (
                "fields",
                J::Arr(
                    fields
                        .iter()
                        .map(|(k, v)| J::Obj(vec![("key", J::s(k)), ("value", J::s(v))]))
                        .collect(),
                ),
            ),
        ]);
        println!("{}", doc.render());
    } else {
        println!("verdict={verdict}");
    }

    if write {
        fs::create_dir_all(NM_DIR).ok();
        let mut body = fp.to_text();
        let _ = writeln!(body, "verdict={verdict}");
        let _ = writeln!(body, "ts={}", read_cmd("date", &["+%s"]));
        fs::write(HEALTH, body).context("write health.txt")?;
    }

    // "unverified" is not a pass but not an abort-boot failure either: only a real
    // inconsistency, a down engine, or a tripped guard exits non-zero.
    if mismatch || !ok_engine || !ok_guard {
        std::process::exit(1);
    }
    Ok(())
}

/// `nomount snapshot` — freeze the current fingerprint as the known-good baseline.
pub fn run_snapshot() -> Result<()> {
    let fp = gather();
    fs::create_dir_all(NM_DIR).ok();
    let mut body = fp.to_text();
    let _ = writeln!(body, "ts={}", read_cmd("date", &["+%s"]));
    fs::write(SNAPSHOT, &body).context("write snapshot.txt")?;
    print!("{body}");
    println!("snapshot saved to {SNAPSHOT}");
    Ok(())
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
    let live = gather().to_text();

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

    write("selfcheck.txt", &{
        let fp = gather();
        fp.to_text()
    });
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
    // doctor's "stale legacy blocklist entries" finding prints hidden package
    // names verbatim; NM_REDACT_HIDE_LIST tells it to withhold them for a shared
    // destination (see M-S2 in doctor.rs).
    // No shell. The old form built `NM_REDACT_HIDE_LIST=1 '<self_exe>' doctor`
    // and handed it to `sh -c`, with `self_exe` dropped into single quotes but
    // NOT escaped -- while two other call sites in this crate (`app_size` above
    // and `whiteout::app_can_see`) correctly escape the same way. Running the
    // binary from a path containing a quote was all it took, and the shell was
    // only ever there to set one environment variable. `Command::env` does that
    // without a shell at all, so there is nothing left to quote.
    let mut doctor = Command::new(&self_exe);
    doctor.arg("doctor");
    if shared {
        doctor.env("NM_REDACT_HIDE_LIST", "1");
    }
    let doctor_out = doctor
        .output()
        .map(|o| {
            let mut t = String::from_utf8_lossy(&o.stdout).into_owned();
            t.push_str(&String::from_utf8_lossy(&o.stderr));
            t
        })
        .unwrap_or_else(|e| format!("could not run {self_exe} doctor: {e}"));
    write("doctor.txt", &doctor_out);
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
