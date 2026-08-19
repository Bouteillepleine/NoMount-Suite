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
    mounts: usize,
    blocked: usize,
    consistency: String, // "ok" | "mismatch:<path>(root=A app=B)" | "unchecked"
    guard: String,       // "armed" | "tripped"
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
        let _ = writeln!(s, "mounts={}", self.mounts);
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
    let out = Command::new("su")
        .args([&uid.to_string(), "-c", &format!("stat -c %s {path} 2>/dev/null")])
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
fn count_module_mounts() -> usize {
    let Ok(body) = fs::read_to_string("/proc/self/mountinfo") else { return 0 };
    let rows = crate::absorb::parse_mountinfo(&body);
    let roots = crate::absorb::fs_roots(&rows);
    rows.iter()
        .filter_map(|r| crate::absorb::source_of(r, &roots))
        .filter(|src| src.starts_with("/data/adb/modules"))
        .count()
}

/// The Narcissus canary: sample a few injected files and confirm a normal app
/// (uid 2000, `shell`) sees the same size as root. A divergence for an unblocked
/// app is the d_drop-class regression this whole module exists to catch early.
fn consistency_probe(rules: &[(String, String)]) -> String {
    // Injected regular files only (skip virtual dirs / whiteouts which have no size).
    let mut checked = 0;
    for (target, _src) in rules.iter() {
        if checked >= 6 {
            break;
        }
        let root = fs::metadata(target).ok().map(|m| m.len().to_string());
        let Some(root_sz) = root else { continue };
        checked += 1;
        let app_sz = app_size(2000, target);
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
    let blocked = nm.uid_list_live().map(|v| v.len()).unwrap_or(0);
    let guard = if Path::new("/data/adb/nomount/disabled").exists() {
        "tripped"
    } else {
        "armed"
    };
    Fingerprint {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uname: read_cmd("uname", &["-r"]),
        engine,
        rules: rules.len(),
        whiteouts,
        mounts: count_module_mounts(),
        blocked,
        consistency: consistency_probe(&rules),
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
pub fn run_selfcheck(write: bool) -> Result<()> {
    let fp = gather();
    let ok_consistency = fp.consistency == "ok" || fp.consistency == "unchecked";
    let ok_guard = fp.guard == "armed";
    let ok_engine = fp.engine != "down";

    print!("{}", fp.to_text());
    let verdict = if ok_consistency && ok_guard && ok_engine {
        "healthy"
    } else if !ok_consistency {
        "PER-UID INCONSISTENCY (injection visible to a normal app differently than root)"
    } else if !ok_engine {
        "ENGINE DOWN"
    } else {
        "GUARD TRIPPED"
    };
    println!("verdict={verdict}");

    if write {
        fs::create_dir_all(NM_DIR).ok();
        let mut body = fp.to_text();
        let _ = writeln!(body, "verdict={verdict}");
        let _ = writeln!(body, "ts={}", read_cmd("date", &["+%s"]));
        fs::write(HEALTH, body).context("write health.txt")?;
    }

    if ok_consistency && ok_guard && ok_engine {
        Ok(())
    } else {
        std::process::exit(1);
    }
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
    let write = |name: &str, content: &str| {
        let _ = fs::write(format!("{out}/{name}"), content);
    };

    write("selfcheck.txt", &{
        let fp = gather();
        fp.to_text()
    });
    write("rules.txt", &nm.list().unwrap_or_else(|e| format!("(nm list failed: {e})")));
    write("uid_live.txt", &format!("{:?}", nm.uid_list_live().unwrap_or_default()));
    let self_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "nomount".to_string());
    write("doctor.txt", &read_cmd("sh", &["-c", &format!("'{self_exe}' doctor 2>&1 || true")]));
    write("dmesg-nomount.txt", &read_cmd("sh", &["-c", "dmesg | grep -i nomount 2>/dev/null || true"]));
    write("mountinfo.txt", &fs::read_to_string("/proc/self/mountinfo").unwrap_or_default());
    write("uname.txt", &read_cmd("uname", &["-a"]));

    // Shared storage is readable by any app holding a storage permission, and the
    // point of an export is to hand it to someone. `blocklist` names the apps you
    // are hiding FROM -- publishing it there tells a detector exactly that -- and
    // `spoof.conf` describes what is being spoofed. They go only to a destination
    // that is not shared storage; the diagnostics that matter for a bug report do
    // not include either.
    const PRIVATE: &[&str] = &["blocklist", "spoof.conf"];
    let shared = ["/sdcard", "/storage", "/mnt/sdcard"].iter().any(|p| out.starts_with(p));
    for f in ["blocklist", "spoof.conf", "spoof.log", "incident.log", "health.txt", "snapshot.txt"] {
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
            "note: blocklist and spoof.conf were left out — {out} is shared storage, readable \
             by any app with a storage permission, and the block list names the apps you are \
             hiding from. Pass a private path to include them: nomount export /data/adb/nomount"
        );
    }
    Ok(())
}
