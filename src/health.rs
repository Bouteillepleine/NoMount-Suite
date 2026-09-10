
use std::fmt::Write as _;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::check::{slug, Check, Section, Verdict};
use crate::nm::Nm;

const NM_DIR: &str = "/data/adb/nomount";
const SNAPSHOT: &str = "/data/adb/nomount/snapshot.txt";

pub struct Fingerprint {
    version: String,
    uname: String,
    engine: String,
    rules: usize,
    whiteouts: usize,
    mounts: Option<usize>,
    blocked: String,
    consistency: String,
    served_matches_rule: String,
    guard: String,
    mounts_foreign: Option<usize>,
    manager_umount: String,
}

impl Fingerprint {
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

    pub fn checks(&self) -> Vec<Check> {
        let mk = |name: &'static str, v: Verdict, ev: String| {
            Check::new(Section::Device, slug(name), name, v, ev)
        };
        let mut out = Vec::new();

        let nothing_to_serve = self.rules == 0 && self.engine != "down";

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
                     owned that path and never took effect. A bind made at post-fs-data is \
                     already handled: the pre-zygote absorb pass drops it and re-asserts the \
                     rule underneath, so this points at a bind that appeared AFTER boot -- \
                     absorb leaves those alone on my_*, because re-asserting there on a live \
                     system has rebooted a device. Delete that bind from the owning module \
                     and reboot.",
                )
                .owner("the mount pass"),
        });

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
    let ours: std::collections::HashSet<std::path::PathBuf> =
        crate::bind::tracked().into_iter().map(|(t, _)| t).collect();
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

fn consistency_probe(rules: &[crate::nm::LiveRule], probe_uid_hidden: bool) -> String {
    if probe_uid_hidden {
        return "unchecked:probe-uid-hidden".to_string();
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
    let mut checked = 0;
    for rule in rules.iter().take(CAP) {
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
    } else {
        "ok".to_string()
    }
}

pub fn gather() -> Fingerprint {
    let nm = Nm::new();
    let engine = nm.version().map(|v| format!("v{v}")).unwrap_or_else(|_| "down".into());
    let list = nm.list().unwrap_or_default();
    let live_rules = crate::nm::parse_list(&list);
    let rules = live_rules.iter().filter(|r| r.kind == crate::nm::LiveKind::Inject).count();
    let whiteouts = live_rules.iter().filter(|r| r.kind == crate::nm::LiveKind::Whiteout).count();
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
        rules,
        whiteouts,
        mounts: split.map(|(t, _)| t),
        mounts_foreign: split.map(|(t, d)| t - d),
        blocked,
        consistency: consistency_probe(&live_rules, probe_hidden),
        served_matches_rule: drift_probe(&live_rules),
        guard: guard.to_string(),
        manager_umount: match crate::manager::kernel_umount_enabled() {
            Some(true) => "on".to_string(),
            Some(false) => "off".to_string(),
            None => "unknown".to_string(),
        },
    }
}

pub fn run_snapshot() -> Result<()> {
    let body = fingerprint_text()?;
    fs::create_dir_all(NM_DIR).ok();
    fs::write(SNAPSHOT, &body).context("write snapshot.txt")?;
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

pub fn run_verify() -> Result<()> {
    let saved = match fs::read_to_string(SNAPSHOT) {
        Ok(s) => s,
        Err(_) => {
            println!("no snapshot yet - run `nomount snapshot` on a known-good boot first");
            return Ok(());
        }
    };
    let live = fingerprint_text()?;

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

pub fn run_export(dir: Option<String>) -> Result<()> {
    let ts = read_cmd("date", &["+%Y%m%d-%H%M%S"]);
    let base = dir.unwrap_or_else(|| "/sdcard/Download".to_string());
    let out = format!("{base}/nm-diag-{ts}");
    fs::create_dir_all(&out).with_context(|| format!("create {out}"))?;

    let nm = Nm::new();
    let write = |name: &str, content: &str| {
        if let Err(e) = fs::write(format!("{out}/{name}"), content) {
            eprintln!("nomount: export: could not write {name}: {e} - this diagnostic is incomplete");
        }
    };

    write("fingerprint.txt", &fingerprint_text().unwrap_or_default());
    let shared = [
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
    ]
    .iter()
    .any(|p| out.starts_with(p));
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
    if !shared {
        write("uid_live.txt", &format!("{:?}", nm.uid_list_live().unwrap_or_default()));
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
    write("check.txt", &check_out);
    write("dmesg-nomount.txt", &read_cmd("sh", &["-c", "dmesg | grep -i nomount 2>/dev/null || true"]));
    write("mountinfo.txt", &fs::read_to_string("/proc/self/mountinfo").unwrap_or_default());
    write("uname.txt", &read_cmd("uname", &["-a"]));

    const PRIVATE: &[&str] = &["uidhide", "uidhide.cache", "uidhide.conf", "spoof.conf"];
    for f in [
        "uidhide", "uidhide.cache", "uidhide.conf", "blocklist", "spoof.conf",
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
        println!(
            "note: {} were left out - {out} is shared storage, readable by any app with a \
             storage permission, and they name the apps you are hiding from (rules.txt UID \
             suffixes and the check report's hide-list names were redacted). Pass a private path to \
             include them in full: nomount export /data/adb/nomount",
            PRIVATE.join(", ")
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn verdict_of(fp: &Fingerprint, id: &str) -> &'static str {
        fp.checks()
            .into_iter()
            .find(|c| c.id == crate::check::slug(id))
            .unwrap_or_else(|| panic!("no check named {id}"))
            .verdict
            .tag()
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
