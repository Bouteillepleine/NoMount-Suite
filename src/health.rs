//! Runtime health: the regression canary that would have caught the d_drop bug on the

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

use crate::check::{slug, Check, Section, Verdict};
use crate::nm::Nm;

const NM_DIR: &str = "/data/adb/nomount";
const SNAPSHOT: &str = "/data/adb/nomount/snapshot.txt";

/// One line-based `key=value` fingerprint of the live system
pub struct Fingerprint {
    version: String,
    uname: String,
    engine: String,
    rules: Option<usize>,
    whiteouts: Option<usize>,
    mounts: Option<usize>,
    blocked: String,
    consistency: String,
    served_matches_rule: String,
    guard: String,
    mounts_foreign: Option<usize>,
    manager_umount: String,
}

impl Fingerprint {
    /// The flat key=value document `health.txt` and `snapshot.txt` are made of
    pub fn facts(&self) -> Vec<crate::check::Fact> {
        let unk = |v: Option<usize>| v.map_or_else(|| "unknown".to_string(), |n| n.to_string());
        [
            ("version", self.version.clone()),
            ("uname", self.uname.clone()),
            ("engine", self.engine.clone()),
            ("rules", unk(self.rules)),
            ("whiteouts", unk(self.whiteouts)),
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

    /// The verdicts those facts imply, as ordinary checks
    pub fn checks(&self) -> Vec<Check> {
        let mk = |name: &'static str, v: Verdict, ev: String| {
            Check::new(Section::Device, slug(name), name, v, ev)
        };
        let mut out = Vec::new();

        let nothing_to_serve = self.rules == Some(0) && self.engine != "down";

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
            "unchecked:probe-uid-unknown" => mk(
                "per-UID consistency canary",
                Verdict::Unmeasured,
                self.consistency.clone(),
            )
            .meaning(
                "The engine would not say which uids are hidden, so it is not known whether the \
                 probe uid (shell) is itself on the hide list - a divergence would be \
                 unreadable either way, so this was not tested.",
            ),
            "unchecked:probe-unavailable" => mk(
                "per-UID consistency canary",
                Verdict::Unmeasured,
                self.consistency.clone(),
            )
            .meaning(
                "The unprivileged probe could not run at all (`su 2000 -c stat` returned nothing \
                 for a stock ROM file), so nothing was compared and this was not tested.",
            ),
            "unchecked:engine-list-failed" => mk(
                "per-UID consistency canary",
                Verdict::Unmeasured,
                self.consistency.clone(),
            )
            .meaning(
                "The engine would not list its rules, so no injected path could be sampled. \
                 This was not tested - it is not \"nothing to test\".",
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

        out.push(match self.served_matches_rule.as_str() {
            "ok" => mk("served bytes match the rule", Verdict::Pass, self.served_matches_rule.clone())
                .meaning("Every injected path serves the bytes its own rule names."),
            "unchecked:engine-list-failed" => mk(
                "served bytes match the rule",
                Verdict::Unmeasured,
                self.served_matches_rule.clone(),
            )
            .meaning(
                "The engine would not list its rules, so there was nothing to compare against. \
                 This was not tested - it is not \"there are no rules\".",
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
            other => mk("served bytes match the rule", Verdict::Fail, other.to_string())
                .meaning(
                    "A path serves content its own rule does not name. Either two rules hit one \
                     target, or the rule was registered while another module's `mount --bind` \
                     owned that path and never took effect. The post-boot absorb pass drops \
                     such a bind and re-asserts the rule underneath - and the pre-zygote pass \
                     does it before zygote when the my_hookless trial is on - so seeing this \
                     after boot means absorb could not take it. On my_* it never will: \
                     re-asserting there on a live system has rebooted a device. Delete that \
                     bind from the owning module and reboot.",
                )
                .owner("the mount pass"),
        });

        out.push(if self.guard == "armed" {
            mk("boot guard armed", Verdict::Pass, self.guard.clone())
                .meaning("The Suite is enabled; no boot-failure guard has tripped.")
        } else {
            mk("boot guard armed", Verdict::Fail, self.guard.clone())
                .meaning(
                    "The boot guard has tripped, so nothing is being injected. Delete \
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

fn app_size(uid: u32, path: &str) -> String {
    let quoted = format!("'{}'", path.replace('\'', "'\\''"));
    let out = Command::new("su")
        .args([&uid.to_string(), "-c", &format!("stat -c %s {quoted} 2>/dev/null")])
        .output();
    out.ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

fn count_mounts_split() -> Option<(usize, usize)> {
    let Ok(body) = fs::read_to_string("/proc/self/mountinfo") else { return None };
    let rows = crate::absorb::parse_mountinfo(&body);
    let roots = crate::absorb::fs_roots(&rows);
    let Ok(tracked) = crate::bind::tracked_result() else { return None };
    let ours: std::collections::HashSet<std::path::PathBuf> =
        tracked.into_iter().map(|(t, _)| t).collect();
    let (mut total, mut by_design) = (0usize, 0usize);
    for r in &rows {
        let Some(src) = crate::absorb::source_of(r, &roots) else { continue };
        if !src.starts_with("/data/adb") {
            continue;
        }
        total += 1;
        if ours.contains(&r.target)
            || crate::absorb::module_dir_of(&src)
                .is_some_and(|d| crate::absorb::is_hook_framework(&d))
        {
            by_design += 1;
        }
    }
    Some((total, by_design))
}

const PROBE_UID: u32 = 2000;

fn consistency_probe(rules: &[crate::nm::LiveRule], probe_uid_hidden: Option<bool>) -> String {
    match probe_uid_hidden {
        Some(true) => return "unchecked:probe-uid-hidden".to_string(),
        None => return "unchecked:probe-uid-unknown".to_string(),
        Some(false) => {}
    }
    const BUDGET: usize = 18;
    let mut buckets: std::collections::BTreeMap<(String, String), Vec<&Path>> =
        std::collections::BTreeMap::new();
    for rule in rules.iter() {
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
    if app_size(PROBE_UID, "/system/build.prop").is_empty() {
        return "unchecked:probe-unavailable".to_string();
    }

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

fn drift_probe(rules: &[crate::nm::LiveRule]) -> String {
    const CAP: usize = 20_000;
    let comparable = rules.iter().filter(|r| r.uid == 0).count();
    let mut checked = 0;
    for rule in rules.iter().filter(|r| r.uid == 0).take(CAP) {
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
    } else if comparable > CAP {
        format!("unchecked:over-cap({checked} of {comparable})")
    } else {
        "ok".to_string()
    }
}

pub fn gather() -> Fingerprint {
    let nm = Nm::new();
    let engine = nm.version().map(|v| format!("v{v}")).unwrap_or_else(|_| "down".into());
    let listed = nm.list();
    let list = listed.as_deref().unwrap_or("").to_string();
    let live_rules = crate::nm::parse_list(&list);
    let counted = |k: crate::nm::LiveKind| -> Option<usize> {
        listed.as_ref().ok().map(|_| live_rules.iter().filter(|r| r.kind == k).count())
    };
    let rules = counted(crate::nm::LiveKind::Inject);
    let whiteouts = counted(crate::nm::LiveKind::Whiteout);
    let live = nm.uid_list_live();
    let blocked = match &live {
        Ok(v) => v.len().to_string(),
        Err(_) => "unknown".to_string(),
    };
    let probe_hidden = live
        .as_ref()
        .map(|v| v.iter().any(|u| crate::blocklist::appid(*u) == PROBE_UID))
        .ok();
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

/// `nomount snapshot` - freeze the current fingerprint as the known-good baseline
pub fn run_snapshot() -> Result<()> {
    let body = fingerprint_text()?;
    crate::statefile::write_atomic(SNAPSHOT, &body).context("write snapshot.txt")?;
    print!("{body}");
    println!("snapshot saved to {SNAPSHOT}");
    Ok(())
}

fn fingerprint_text() -> Result<String> {
    let r = crate::check::build(false, true)?;
    let mut body = r.fingerprint_text();
    let _ = writeln!(body, "ts={}", r.ts);
    Ok(body)
}

/// `nomount verify` - diff the live fingerprint against the saved snapshot and name every
/// field that moved, so drift since the last known-good boot is visible rather than implied.
pub fn run_verify() -> Result<()> {
    let saved = match fs::read_to_string(SNAPSHOT) {
        Ok(s) => s,
        Err(_) => {
            println!("no snapshot yet - run `nomount snapshot` on a known-good boot first");
            return Ok(());
        }
    };
    let live = fingerprint_text()?;
    if let Some(note) = version_context(&saved, &live) {
        println!("{note}");
    }
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
    for (k, lval) in &lv {
        let sval = find(&sv, k).unwrap_or_else(|| "<absent>".to_string());
        if &sval != lval && !is_version_context(k, &sval, lval) {
            out.push(format!("DRIFT {k}: snapshot={sval} -> live={lval}"));
        }
    }
    for (k, sval) in &sv {
        if find(&lv, k).is_none() && !is_version_context(k, sval, "<absent>") {
            out.push(format!("DRIFT {k}: snapshot={sval} -> live=<absent>"));
        }
    }
    out
}

fn is_version_context(key: &str, sval: &str, lval: &str) -> bool {
    let version_shaped = |v: &str| {
        v.strip_prefix('v').is_some_and(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
    };
    let parts = |v: &str| -> Option<Vec<u64>> {
        let v = v.trim().trim_start_matches('v');
        if v.is_empty() {
            return None;
        }
        v.split('.').map(|p| p.parse::<u64>().ok()).collect()
    };
    let moved_forward = |a: &str, b: &str| -> bool {
        match (parts(a), parts(b)) {
            (Some(x), Some(y)) => y >= x,
            _ => false,
        }
    };
    match key {
        "version" => moved_forward(sval, lval),
        "engine" => version_shaped(sval) && version_shaped(lval) && moved_forward(sval, lval),
        _ => false,
    }
}

fn version_context(saved: &str, live: &str) -> Option<String> {
    let get = |txt: &str, key: &str| -> Option<String> {
        txt.lines()
            .filter_map(|l| l.split_once('='))
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.to_string())
    };
    let moved = |key: &str| -> Option<(String, String)> {
        let (s, l) = (get(saved, key)?, get(live, key)?);
        (s != l && is_version_context(key, &s, &l)).then_some((s, l))
    };
    let mut parts = Vec::new();
    if let Some((s, l)) = moved("version") {
        parts.push(format!("Suite {s} (now {l})"));
    }
    if let Some((s, l)) = moved("engine") {
        parts.push(format!("engine {s} (now {l})"));
    }
    if parts.is_empty() {
        return None;
    }
    Some(format!(
        "note: this snapshot was taken on {} - that is just an update you made, nothing is \
         wrong with it. Everything else was compared across it.",
        parts.join(" and ")
    ))
}

/// Every root under which a destination is readable by any app holding a storage
pub(crate) const SHARED_ROOTS: &[&str] = &[
    "/sdcard",
    "/storage",
    "/mnt/sdcard",
    "/data/media",
    "/mnt/user",
    "/mnt/runtime",
    "/mnt/androidwritable",
    "/mnt/pass_through",
    "/mnt/media_rw",
    "/mnt/expand",
];

/// Is `p` inside a shared volume?
pub(crate) fn is_shared_storage(p: &Path) -> bool {
    SHARED_ROOTS.iter().any(|r| p.starts_with(r))
}

fn base_unusable(base: &Path) -> Option<String> {
    for p in base.ancestors() {
        if p.as_os_str().is_empty() {
            continue;
        }
        if p.is_dir() {
            return None;
        }
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
    }
    None
}

/// `nomount export [dir]` - dump diagnostics to a timestamped, stealth-named folder
pub fn run_export(dir: Option<String>) -> Result<()> {
    let ts = read_cmd("date", &["+%Y%m%d-%H%M%S"]);
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
    if let Some(why) = base_unusable(Path::new(&base)) {
        anyhow::bail!("cannot export to {base}: {why}");
    }
    fs::create_dir_all(&out).with_context(|| format!("create {out}"))?;

    let nm = Nm::new();
    let write = |name: &str, content: &str| {
        if let Err(e) = fs::write(format!("{out}/{name}"), content) {
            eprintln!("nomount: export: could not write {name}: {e} - this diagnostic is incomplete");
        }
    };

    let resolved = fs::canonicalize(&out).unwrap_or_else(|_| PathBuf::from(&out));
    let shared = is_shared_storage(&resolved) || is_shared_storage(Path::new(&out));

    let fingerprint = fingerprint_text().unwrap_or_else(|e| format!("(fingerprint failed: {e:#})\n"));
    let fingerprint =
        if shared { redact_for_shared("health.txt", &fingerprint) } else { fingerprint };
    write("fingerprint.txt", &fingerprint);
    let rules = nm.list().unwrap_or_else(|e| format!("(nm list failed: {e})"));
    let rules = if shared { redact_rules_for_shared(&rules) } else { rules };
    write("rules.txt", &rules);
    if !shared {
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
    let check_out = if shared { redact_app_paths_doc(&check_out) } else { check_out };
    write("check.txt", &check_out);
    let dmesg = read_cmd("sh", &["-c", "dmesg 2>&1 | grep -i nomount"]);
    let mut withheld: Vec<&str> = Vec::new();
    let (dmesg_body, dmesg_withheld) = dmesg_section(shared, &dmesg);
    write("dmesg-nomount.txt", &dmesg_body);
    if dmesg_withheld {
        withheld.push("dmesg-nomount.txt");
    }
    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .unwrap_or_else(|e| format!("(could not read /proc/self/mountinfo: {e})\n"));
    let mountinfo = if shared { redact_app_paths_doc(&mountinfo) } else { mountinfo };
    write("mountinfo.txt", &mountinfo);
    write("uname.txt", &read_cmd("uname", &["-a"]));

    const PRIVATE: &[&str] =
        &["uidhide", "uidhide.cache", "uidhide.conf", "spoof.conf", "boot.log"];
    for f in [
        "uidhide", "uidhide.cache", "uidhide.conf", "blocklist", "spoof.conf",
        "incident.log", "health.txt", "snapshot.txt", "boot.log",
    ] {
        let src = format!("{NM_DIR}/{f}");
        if shared && PRIVATE.contains(&f) {
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
        let left_out = if withheld.is_empty() {
            String::new()
        } else {
            format!(
                "{} left out - they can name the apps you are hiding from. ",
                withheld.join(", ")
            )
        };
        println!(
            "note: {left_out}{out} is shared storage, readable by any app with a storage \
             permission, so the hide list was kept out of it: rules.txt UID suffixes, the \
             check report's hide-list names, any package name left in blocklist and any \
             /data/app path in the fingerprint, the rule list, the check report and \
             mountinfo were redacted in place. Pass a private path for the unredacted \
             bundle: nomount export /data/adb/nomount"
        );
    }
    Ok(())
}

fn dmesg_section(shared: bool, dmesg: &str) -> (String, bool) {
    if shared && !dmesg.is_empty() {
        return (
            "(left out - the kernel ring carries the Suite's own boot log, which can name the \
             apps you are hiding from. For this file, re-run to a private path: \
             nomount export /data/adb/nomount)\n"
                .to_string(),
            true,
        );
    }
    if dmesg.is_empty() {
        return (
            "(no nomount lines - or dmesg is restricted on this device; check `sysctl \
             kernel.dmesg_restrict`)\n"
                .to_string(),
            false,
        );
    }
    (dmesg.to_string(), false)
}

fn redact_rules_for_shared(rules: &str) -> String {
    rules
        .lines()
        .map(|l| l.split(" [UID:").next().unwrap_or(l).trim_end())
        .map(redact_app_paths)
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_for_shared(name: &str, body: &str) -> String {
    let keep_installed = |l: &&str| -> bool {
        let t = l.trim();
        t.is_empty()
            || t.starts_with('#')
            || Path::new(crate::mount::MODULES_DIR).join(t).is_dir()
    };
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
        _ => redact_app_paths_doc(body),
    }
}

fn redact_app_paths_doc(body: &str) -> String {
    if !body.contains("/data/app/") {
        return body.to_string();
    }
    let mut s = body.lines().map(redact_app_paths).collect::<Vec<_>>().join("\n");
    if body.ends_with('\n') {
        s.push('\n');
    }
    s
}

fn redact_app_paths(line: &str) -> String {
    if !line.contains("/data/app/") {
        return line.to_string();
    }
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(i) = rest.find("/data/app/") {
        out.push_str(&rest[..i]);
        out.push_str("/data/app/<redacted>");
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

    #[test]
    fn a_version_that_went_backwards_is_drift_not_context() {
        assert!(is_version_context("engine", "v30", "v32"), "forward is the user's own update");
        assert!(is_version_context("engine", "v32", "v32"), "unchanged is not drift");
        assert!(!is_version_context("engine", "v32", "v20"), "an engine DOWNGRADE is drift");
        assert!(!is_version_context("engine", "v30", "down"), "a dead engine is drift");

        assert!(is_version_context("version", "1.3.163", "1.3.176"), "Suite forward");
        assert!(!is_version_context("version", "1.3.176", "1.3.163"), "Suite DOWNGRADE is drift");
        assert!(!is_version_context("version", "1.3.176", "garbage"), "unparseable is drift");

        let drifted = drift_lines("engine=v32
rules=3
", "engine=v20
rules=3
");
        assert_eq!(drifted.len(), 1, "{drifted:?}");
        assert!(drifted[0].contains("engine"), "{drifted:?}");
        assert!(
            version_context("engine=v32
", "engine=v20
").is_none(),
            "a downgrade must not be excused in the note either"
        );
    }

    #[test]
    fn an_unresolvable_export_base_is_named_instead_of_reported_as_existing() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();

        assert_eq!(base_unusable(d.path()), None);

        assert_eq!(base_unusable(&d.path().join("not/here/yet")), None);

        let dangling = d.path().join("sdcard");
        symlink("/storage/self/primary", &dangling).unwrap();
        let why = base_unusable(&dangling.join("Download"))
            .expect("a dangling ancestor must be refused, not just a dangling base");
        assert!(why.contains("symlink"), "must name the symlink: {why}");
        assert!(
            why.contains("/storage/self/primary"),
            "must name where it points: {why}"
        );
        assert!(
            why.contains("sdcard") && !why.contains("Download"),
            "must name the ancestor that is the obstacle, not the path typed: {why}"
        );
        assert!(base_unusable(&dangling).is_some());
        assert!(
            why.contains("does not resolve") && why.contains("does not exist"),
            "must explain the eexist rather than restate it: {why}"
        );

        let f = d.path().join("afile");
        fs::write(&f, b"x").unwrap();
        assert!(base_unusable(&f).is_some_and(|w| w.contains("not a directory")));
    }

    #[test]
    fn drift_names_a_changed_field() {
        let saved = "engine=v30\nrules=257\nblocked=19\nts=1\n";
        let live = "engine=v30\nrules=260\nblocked=19\nts=2\n";
        let d = drift_lines(saved, live);
        assert_eq!(d, vec!["DRIFT rules: snapshot=257 -> live=260"]);
    }

    #[test]
    fn drift_ignores_the_timestamp() {
        let saved = "engine=v30\nrules=257\nts=1788327280\n";
        let live = "engine=v30\nrules=257\nts=1788399999\n";
        assert!(drift_lines(saved, live).is_empty(), "ts must not count as drift");
    }

    #[test]
    fn drift_reports_a_field_only_live_has() {
        let saved = "engine=v30\n";
        let live = "engine=v30\nguard=armed\n";
        assert_eq!(drift_lines(saved, live), vec!["DRIFT guard: snapshot=<absent> -> live=armed"]);
    }

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

    #[test]
    fn drift_is_empty_for_the_same_fingerprint_in_any_order() {
        let saved = "engine=v30\nrules=257\nguard=armed\nts=1\n";
        let live = "guard=armed\nts=9\nengine=v30\nrules=257\n";
        assert!(drift_lines(saved, live).is_empty());
    }

    #[test]
    fn drift_reports_every_moved_field_not_just_the_first() {
        let saved = "engine=v30\nrules=257\nmanager_umount=off\n";
        let live = "engine=v31\nrules=260\nguard=armed\n";
        let d = drift_lines(saved, live);
        assert_eq!(d.len(), 3, "expected 1 changed + 1 gained + 1 lost, got {d:?}");
        assert!(d.iter().any(|l| l.contains("rules") && l.contains("257") && l.contains("260")));
        assert!(d.iter().any(|l| l.contains("manager_umount") && l.contains("<absent>")));
        assert!(d.iter().any(|l| l.contains("guard") && l.contains("<absent>")));
    }

    #[test]
    fn drift_says_nothing_about_the_users_own_update() {
        let saved = "version=1.3.163\nengine=v30\nrules=257\nguard=armed\nts=1\n";
        let live = "version=1.3.173\nengine=v31\nrules=257\nguard=armed\nts=2\n";
        assert!(
            drift_lines(saved, live).is_empty(),
            "updating the Suite and the engine is not drift: {:?}",
            drift_lines(saved, live)
        );

        let note = version_context(saved, live).expect("the version move must still be stated");
        assert!(note.contains("1.3.163") && note.contains("1.3.173"), "{note}");
        assert!(note.contains("v30") && note.contains("v31"), "{note}");
        assert!(!note.contains("DRIFT"), "the WebUI greps for drift and reddens: {note}");
        assert!(note.contains("nothing is wrong"), "it must not read as an alarm: {note}");

        assert!(version_context(saved, saved).is_none());

        let moved = "version=1.3.173\nengine=v31\nrules=260\nguard=tripped\nts=2\n";
        let d = drift_lines(saved, moved);
        assert_eq!(d.len(), 2, "rules and guard must still drift: {d:?}");
        assert!(d.iter().any(|l| l.starts_with("DRIFT guard:")));
    }

    #[test]
    fn an_engine_that_stopped_answering_is_still_drift() {
        let saved = "version=1.3.163\nengine=v30\n";
        let live = "version=1.3.173\nengine=down\n";
        let d = drift_lines(saved, live);
        assert_eq!(d, vec!["DRIFT engine: snapshot=v30 -> live=down"], "{d:?}");
        let note = version_context(saved, live).expect("the Suite update is still context");
        assert!(note.contains("1.3.173") && !note.contains("down"), "{note}");
    }

    fn fp(engine: &str, rules: usize) -> Fingerprint {
        Fingerprint {
            version: "test".into(),
            uname: "test".into(),
            engine: engine.into(),
            rules: Some(rules),
            whiteouts: Some(0),
            mounts: Some(0),
            blocked: "0".into(),
            consistency: "unchecked".into(),
            served_matches_rule: "unchecked".into(),
            guard: "armed".into(),
            mounts_foreign: Some(0),
            manager_umount: "off".into(),
        }
    }

    fn verdict_of(fp: &Fingerprint, id: &str) -> &'static str {
        fp.checks()
            .into_iter()
            .find(|c| c.id == crate::check::slug(id))
            .unwrap_or_else(|| panic!("no check named {id}"))
            .verdict
            .tag()
    }

    #[test]
    fn every_spelling_of_shared_storage_is_recognised() {
        for p in [
            "/sdcard/Download/nm-diag-1",
            "//sdcard/Download/nm-diag-1",
            "/storage/emulated/0/Download/nm-diag-1", // what /sdcard resolves to
            "/data/media/0/Download/nm-diag-1",
            "/mnt/user/0/emulated/0/x",
            "/mnt/media_rw/ABCD-1234/x",
            "/mnt/expand/abcd/user/0/x",
        ] {
            assert!(is_shared_storage(Path::new(p)), "{p} is shared storage");
        }
    }

    #[test]
    fn private_destinations_are_not_mistaken_for_shared_ones() {
        for p in [
            "/data/adb/nomount/nm-diag-1",
            "/data/local/tmp/nm-diag-1",
            "/data/media0/x",   // Not under /data/media
            "/storagex/x",      // not under /storage
            "/mnt/vendor/persist/x",
        ] {
            assert!(!is_shared_storage(Path::new(p)), "{p} is not shared storage");
        }
    }

    #[test]
    fn zero_rules_is_only_not_applicable_when_the_engine_answered() {
        let up = fp("v26", 0);
        assert_eq!(verdict_of(&up, "per-UID consistency canary"), "N/A");
        assert_eq!(verdict_of(&up, "served bytes match the rule"), "N/A");

        let down = fp("down", 0);
        assert_eq!(verdict_of(&down, "per-UID consistency canary"), "UNMEASURED");
        assert_eq!(verdict_of(&down, "served bytes match the rule"), "UNMEASURED");

        let serving = fp("v26", 12);
        assert_eq!(verdict_of(&serving, "per-UID consistency canary"), "UNMEASURED");

        let mut mute = fp("v30", 0);
        mute.rules = None;
        mute.whiteouts = None;
        mute.consistency = "unchecked:engine-list-failed".into();
        mute.served_matches_rule = "unchecked:engine-list-failed".into();
        assert_eq!(verdict_of(&mute, "per-UID consistency canary"), "UNMEASURED");
        assert_eq!(verdict_of(&mute, "served bytes match the rule"), "UNMEASURED");
        let facts = mute.facts();
        let fact = |k: &str| facts.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()).unwrap();
        assert_eq!(fact("rules"), "unknown", "an unread rule dump is not zero rules");
        assert_eq!(fact("whiteouts"), "unknown");
        assert_eq!(fp("v30", 0).facts().iter().find(|(n, _)| n == "rules").unwrap().1, "0");

        let mut noprobe = fp("v30", 12);
        noprobe.consistency = "unchecked:probe-unavailable".into();
        assert_eq!(verdict_of(&noprobe, "per-UID consistency canary"), "UNMEASURED");
        noprobe.consistency = "unchecked:probe-uid-unknown".into();
        assert_eq!(verdict_of(&noprobe, "per-UID consistency canary"), "UNMEASURED");

        let mut bad = fp("v30", 12);
        bad.consistency = "mismatch:/system/etc/x(root=12 app=ENOENT)".into();
        assert_eq!(verdict_of(&bad, "per-UID consistency canary"), "FAIL");
    }

    #[test]
    fn a_shared_export_filters_the_files_it_still_includes() {
        let body = "# a comment\n\ncom.example.bank\nsome_module_id\n";
        let got = redact_for_shared("blocklist", body);
        assert!(!got.contains("com.example.bank"), "a package name must not survive: {got:?}");
        assert!(got.contains("# a comment"), "comments are diagnostic, keep them: {got:?}");

        assert_eq!(redact_for_shared("incident.log", body), body);
    }

    #[test]
    fn a_shared_export_keeps_data_app_paths_out_of_the_fingerprint() {
        let line = "served_matches_rule=drift:/data/app/~~aB1/com.mybank.app-x9/base.apk\
                    (rule=/data/adb/modules/M/x size 10 vs 12)";
        let got = redact_app_paths(line);
        assert!(!got.contains("com.mybank.app"), "the package must not survive: {got}");
        assert!(!got.contains("~~aB1"), "nor the install directory: {got}");
        assert!(got.starts_with("served_matches_rule=drift:/data/app/<redacted>"), "{got}");
        assert!(got.contains("/data/adb/modules/M/x"), "the module source is not a secret: {got}");
        assert!(got.contains("size 10 vs 12"), "{got}");

        assert_eq!(redact_app_paths("served_matches_rule=ok"), "served_matches_rule=ok");
        assert_eq!(redact_app_paths("rules=257"), "rules=257");

        let doc = "rules=257\nserved_matches_rule=drift:/data/app/com.x-1/base.apk (bytes differ)\n";
        assert!(!redact_for_shared("health.txt", doc).contains("com.x-1"));
        assert!(redact_for_shared("health.txt", doc).contains("rules=257"));
    }

    #[test]
    fn a_shared_export_keeps_the_kernel_ring_out_of_the_bundle() {
        let ring = "[1.0] nomount: *.bank matches com.mybank.app (appid 10231, below the app \
                    range)\n";

        let (body, withheld) = dmesg_section(true, ring);
        assert!(withheld, "dmesg-nomount.txt must be named in the closing note");
        assert!(!body.contains("com.mybank.app"), "the package must not survive: {body}");
        assert!(!body.contains("*.bank"), "nor the hide-list glob: {body}");
        assert!(body.contains("left out"), "and the file must say why it is empty: {body}");

        assert_eq!(dmesg_section(false, ring), (ring.to_string(), false));

        for shared in [true, false] {
            let (body, withheld) = dmesg_section(shared, "");
            assert!(!withheld, "nothing was kept back, so do not say it was");
            assert!(body.contains("dmesg_restrict"), "{body}");
        }
    }

    #[test]
    fn a_shared_export_keeps_data_app_paths_out_of_the_rule_list_and_the_report() {
        let dump = "/system/etc/hosts -> /data/adb/modules/M/system/etc/hosts\n\
                    /data/app/~~aB1/com.mybank.app-x9/base.apk -> /data/adb/rvhc/patched.apk \
                    [UID: 10231]\n";
        let got = redact_rules_for_shared(dump);
        assert!(!got.contains("com.mybank.app"), "the package must not survive: {got}");
        assert!(!got.contains("~~aB1"), "nor the install directory: {got}");
        assert!(!got.contains("[UID:"), "the appid strip still applies: {got}");
        assert!(got.contains("/data/app/<redacted> -> /data/adb/rvhc/patched.apk"), "{got}");
        assert!(got.contains("/system/etc/hosts -> /data/adb/modules/M/system/etc/hosts"), "{got}");

        let report = "[FAIL] served bytes match the rule\n       measured: \
                      drift:/data/app/~~aB1/com.mybank.app-x9/base.apk (bytes differ)\n";
        let got = redact_app_paths_doc(report);
        assert!(!got.contains("com.mybank.app"), "{got}");
        assert!(got.ends_with('\n'), "a text file someone will cat keeps its newline: {got:?}");
        assert!(got.contains("(bytes differ)"), "the finding survives redaction: {got}");

        let clean = "/system/etc/hosts -> /data/adb/modules/M/system/etc/hosts\n";
        assert_eq!(redact_app_paths_doc(clean), clean);
        assert_eq!(redact_rules_for_shared(clean), clean.trim_end());

        let inc = "tombstone=/data/tombstones/tombstone_00\n  Abort message: \
                   could not open /data/app/~~aB1/com.mybank.app-x9/base.apk\n";
        assert!(!redact_for_shared("incident.log", inc).contains("com.mybank.app"));
    }

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

        assert_eq!(injects[0].target, Path::new("/system/etc/a -> b"));
        assert_eq!(
            injects[0].source.as_deref(),
            Some(Path::new("/data/adb/modules/M/system/etc/ab"))
        );

        assert_eq!(
            injects[1].source.as_deref(),
            Some(Path::new("/data/adb/modules/M/product/overlay/F.apk"))
        );
        assert!(injects[1].public);

        assert_eq!(
            injects[2].source.as_deref(),
            Some(Path::new("/data/adb/modules/M/system/lib64/libx.so"))
        );
        assert_eq!(injects[2].uid, 10123);

        assert_eq!(
            live.iter().filter(|r| r.kind == crate::nm::LiveKind::Whiteout).count(),
            1
        );
    }
}
