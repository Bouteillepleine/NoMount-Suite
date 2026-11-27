
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

use crate::check::{slug, Check, Section, Verdict};
use crate::nm::Nm;

const NM_DIR: &str = "/data/adb/nomount";
const SNAPSHOT: &str = "/data/adb/nomount/snapshot.txt";

pub struct Fingerprint {
    version: String,
    uname: String,
    kbuild: String,
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
    pub fn facts(&self) -> Vec<crate::check::Fact> {
        let unk = |v: Option<usize>| v.map_or_else(|| "unknown".to_string(), |n| n.to_string());
        [
            ("version", self.version.clone()),
            ("uname", self.uname.clone()),
            ("kbuild", self.kbuild.clone()),
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

    pub fn checks(&self) -> Vec<Check> {
        let mk = |name: &'static str, v: Verdict, ev: String| {
            Check::new(Section::Device, slug(name), name, v, ev)
        };
        let mut out = Vec::new();

        let nothing_to_serve = self.rules == Some(0) && self.engine != "down";

        out.push(match self.consistency.as_str() {
            "ok" => mk("per-UID consistency canary", Verdict::Pass, self.consistency.clone())
                .meaning(
                    "A normal app sees the same size and the same first 4 KiB at an injected path \
                     as root does, which is what stops an app spotting the injection by diffing \
                     its own view.",
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
            "unchecked:seccomp-filtered" => mk(
                "per-UID consistency canary",
                Verdict::Unmeasured,
                self.consistency.clone(),
            )
            .meaning(
                "This run carries an app's seccomp filter - the manager's WebUI runs commands \
                 that way - and the filter allows neither setgroups nor setresuid, so nothing \
                 here can take on an app's uid and no comparison was attempted. Run \
                 `nomount check` from a terminal, or read the report the boot pass writes.",
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
            "unchecked:no-unhidden-app" => mk(
                "per-UID consistency canary",
                Verdict::NotApplicable,
                self.consistency.clone(),
            )
            .meaning(
                "There is no unhidden app to compare against - every candidate uid is on your \
                 hide list - so a divergence here would be the hiding working. Nothing to test.",
            ),
            "unchecked:canary-unreadable" => mk(
                "per-UID consistency canary",
                Verdict::Unmeasured,
                self.consistency.clone(),
            )
            .meaning(
                "The stock ROM file this compares against could not be read as root, so there \
                 was no baseline to diff an app's view against. This was not tested.",
            ),
            // FAIL is now reserved for the one shape that means a real divergence.
            //
            // It used to be the catch-all, and consistency_probe() emits two strings no arm
            // above matched - "unchecked:no-unhidden-app" and "unchecked:canary-unreadable" -
            // so two "could not measure" states were reported as "a normal app sees something
            // different at an injected path than root does ... the d_drop-class kernel
            // regression", complete with an oracle and the engine named as owner. That is a
            // false alarm pointing at the kernel, and the catch-all guaranteed that any status
            // a future probe learns to emit would do the same.
            s if s.starts_with("mismatch:") => mk("per-UID consistency canary", Verdict::Fail, s.to_string())
                .meaning(
                    "A normal app sees something different at an injected path than root does. \
                     That is the d_drop-class kernel regression this canary exists to catch.",
                )
                .oracle(
                    "an app can diff its own view of an injected path against another uid's and \
                     see the injection",
                )
                .owner("the kernel engine"),
            s if s.starts_with("unchecked:unreadable-as-app:") => mk(
                "per-UID consistency canary",
                Verdict::Unmeasured,
                s.to_string(),
            )
            .meaning(
                "An app could stat an injected file but not read it, so its bytes were never \
                 compared. If the stock file is app-readable, that refusal is itself a \
                 difference an app can see; a module tree with the wrong SELinux label is the \
                 usual cause.",
            ),
            s if s.starts_with("unchecked") => mk(
                "per-UID consistency canary",
                Verdict::Unmeasured,
                s.to_string(),
            )
            .meaning(
                "The canary did not run, and this build does not recognise the reason it gave, \
                 so nothing was compared.",
            ),
            other => mk("per-UID consistency canary", Verdict::Unmeasured, other.to_string())
                .meaning(
                    "The canary answered with a status this build does not recognise. That is \
                     not a measurement, and it is not a kernel fault either.",
                ),
        });

        out.push(match self.served_matches_rule.as_str() {
            "ok" => mk("served bytes match the rule", Verdict::Pass, self.served_matches_rule.clone())
                .meaning("Every injected path serves a file of the size its rule names, and the same opening 4 KiB."),
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
            s if s.starts_with("unchecked:unreadable") => mk(
                "served bytes match the rule",
                Verdict::Unmeasured,
                self.served_matches_rule.clone(),
            )
            .meaning(
                "A live rule named a source or a target that would not stat, so those paths \
                 were not compared. A rule the engine holds but does not serve looks exactly \
                 like this, so it is not a pass.",
            ),
            s if s.starts_with("ok:partial") => mk(
                "served bytes match the rule",
                Verdict::Pass,
                self.served_matches_rule.clone(),
            )
            .meaning(
                "Every injected path that could be compared serves a file of the size its rule \
                 names. The count says how many of the live rules that was - the rest are not \
                 regular files at both ends (a directory injection), so there is nothing to \
                 compare there.",
            ),
            // "I stopped at the cap" is not "I found something wrong". This used to fall through
            // to Fail and told the user to delete a bind and reboot over a scan that simply ran
            // out of budget.
            s if s.starts_with("unchecked:over-cap") => mk(
                "served bytes match the rule",
                Verdict::Unmeasured,
                self.served_matches_rule.clone(),
            )
            .meaning(
                "There are more comparable rules than this check compares in one pass, so it \
                 stopped early. Nothing was found wrong - it did not finish looking.",
            ),
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

/// Bounded: this runs `uname`, `date` and a `dmesg | grep` pipeline, and a terminal
/// `nomount check` has nothing wrapping it the way the boot path's `nmto` does -- so one
/// command that never returns hung the diagnostic that was meant to explain the problem.
fn read_cmd(prog: &str, args: &[&str]) -> String {
    let mut cmd = Command::new(prog);
    cmd.args(args);
    crate::nm::Nm::run_within(cmd, std::time::Duration::from_secs(15), prog)
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// One answer per sampled path, from inside the probe child.
const PR_AGREE: u32 = 0;
const PR_DIFFER: u32 = 1;
const PR_NOSTAT: u32 = 2;
const PR_UNUSED: u32 = 3;
/// Size agreed but the bytes did not. Strictly stronger than PR_DIFFER: the whole point of
/// the canary is that an app and root see the same FILE, and equal length is cheap to
/// satisfy by accident -- a shadowed APK, an RRO overlay or a prop file replaced with
/// another of the same length read as agreement, while the PASS row claimed "the same
/// bytes". Only raised when BOTH sides could read the prefix; a read the child cannot do
/// falls back to the size answer rather than inventing a divergence, because an injected
/// file whose stock counterpart is root-only is stock behaviour, not a tell.
const PR_BYTES: u32 = 4;
/// stat agreed but read() failed as the app: nothing was compared.
const PR_NOREAD: u32 = 5;
/// The app could stat it and its mode lets the app read it, root read the same bytes, and
/// open() still failed: an app-visible break (the engine's backing open refused), not stock.
const PR_NOOPEN: u32 = 6;

/// Bytes of each sampled file folded on both sides. One page: enough to separate two files
/// of equal length in every case this has to catch, cheap enough to do inside the probe
/// child with no allocation.
const PR_PREFIX: usize = 4096;

/// FNV-1a, so the parent and the child fold identically.
fn prefix_sum(bytes: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in bytes {
        h ^= *b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

/// An installed app's uid the hide list does not cover, lowest first for a stable pick.
///
/// The canary asks whether a NORMAL app sees what root sees. uid 2000 is shell, which
/// answers a different question: another uid band, another SELinux domain, and `su` is
/// ksud, which applies its own per-uid profile to the child. A divergence that hit
/// untrusted_app while shell agreed with root read as `consistency=ok`.
///
/// This still drops uid only -- the child keeps our SELinux domain, so it is not a full
/// untrusted_app probe. That is the right trade here: the engine keys its hide decision
/// on the uid (`nomount_is_uid_blocked(current_uid())`), so uid is the axis this canary
/// is about, and `others_can_search_to` already keeps the sample to paths DAC lets an
/// app reach.
fn pick_probe_uid(installed: &[(String, u32)], live_hidden: &[u32]) -> Option<u32> {
    // Compare appids, not raw uids: the same app in a work profile is u10_aNNN, a
    // different raw uid for the same appid, and the engine hides by normalised appid.
    let hidden: std::collections::HashSet<u32> =
        live_hidden.iter().map(|u| crate::blocklist::appid(*u)).collect();
    installed
        .iter()
        .map(|(_, uid)| *uid)
        .filter(|u| *u >= crate::blocklist::FIRST_APP_APPID)
        .filter(|u| !hidden.contains(&crate::blocklist::appid(*u)))
        .min()
}

fn count_mounts_split() -> Option<(usize, usize)> {
    let Ok(body) = fs::read_to_string("/proc/self/mountinfo") else { return None };
    let rows = crate::absorb::parse_mountinfo(&body);
    let roots = crate::absorb::fs_roots(&rows);
    let Ok(tracked) = crate::bind::tracked_result() else { return None };
    // (target, source), as check_zero_mount matches: a module's own bind over a target the
    // Suite also binds is foreign, and counting it as ours hid it from mounts_foreign.
    let ours: std::collections::HashSet<(std::path::PathBuf, std::path::PathBuf)> =
        tracked.into_iter().collect();
    let (mut total, mut by_design) = (0usize, 0usize);
    let sourced = rows.iter().filter_map(|r| {
        crate::absorb::source_of(r, &roots).filter(|s| s.starts_with("/data/adb")).map(|s| (r, s))
    });
    for (r, src) in sourced.chain(crate::absorb::foreign_overlays(&rows)) {
        total += 1;
        if ours.contains(&(r.target.clone(), src.clone()))
            || crate::absorb::module_dir_of(&src)
                .is_some_and(|d| crate::absorb::is_hook_framework(&d))
        {
            by_design += 1;
        }
    }
    Some((total, by_design))
}

fn others_can_search_to(target: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    target.ancestors().skip(1).filter(|d| !d.as_os_str().is_empty()).all(|d| {
        fs::metadata(d).is_ok_and(|m| m.is_dir() && m.permissions().mode() & 0o001 != 0)
    })
}

/// The injected targets the canary may sample, by (partition, module).
///
/// A rule that excludes the probe uid serves it stock on purpose, which would read as the
/// divergence this canary looks for.
fn canary_buckets(
    rules: &[crate::nm::LiveRule],
    probe_uid: u32,
) -> std::collections::BTreeMap<(String, String), Vec<&Path>> {
    let mut buckets: std::collections::BTreeMap<(String, String), Vec<&Path>> =
        std::collections::BTreeMap::new();
    for rule in rules.iter().filter(|r| r.uid == 0 && r.serves(probe_uid)) {
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
    buckets
}

fn consistency_probe(rules: &[crate::nm::LiveRule], probe_uid: Option<u32>) -> String {
    let Some(probe_uid) = probe_uid else {
        return "unchecked:no-unhidden-app".to_string();
    };
    // Dropping uid needs setgroups/setresuid, which an inherited app filter kills with
    // SIGSYS. Ask before forking rather than leaving a tombstone per probe.
    if crate::audit::own_seccomp_mode().is_some_and(|m| m != 0) {
        return "unchecked:seccomp-filtered".to_string();
    }
    const BUDGET: usize = 18;
    let buckets = canary_buckets(rules, probe_uid);
    let mut sample: Vec<&Path> = Vec::new();
    'outer: for i in 0.. {
        let mut progressed = false;
        for targets in buckets.values() {
            if let Some(t) = targets.get(i) {
                progressed = true;
                if !others_can_search_to(t) {
                    continue;
                }
                sample.push(t);
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

    // Slot 0 is the canary: a plain ROM file with no rule on it. If the child cannot stat
    // THAT, the probe itself is what failed, not the injection.
    const CANARY: &str = "/system/build.prop";
    const SLOTS: usize = BUDGET + 1;

    let mut names: Vec<&str> = vec![CANARY];
    names.extend(sample.iter().filter_map(|t| t.to_str()));

    // Build the CStrings and read root's sizes BEFORE forking: the child then does no
    // allocation at all, just stat(2) into a fixed array. Anything that can be done
    // before the fork belongs before it.
    let mut cpaths: Vec<std::ffi::CString> = Vec::new();
    let mut root_sizes: Vec<u64> = Vec::new();
    // None when root itself could not read the prefix: then the child compares size only,
    // rather than reporting a divergence the parent never established a baseline for.
    let mut root_sums: Vec<Option<u32>> = Vec::new();
    let mut kept: Vec<&str> = Vec::new();
    for n in names.iter().take(SLOTS) {
        let (Ok(c), Ok(m)) = (std::ffi::CString::new(*n), fs::metadata(n)) else { continue };
        // Only a regular file has bytes to compare, and opening a FIFO blocks forever --
        // as root, here, holding the pass lock.
        if !m.is_file() {
            continue;
        }
        let sum = {
            use std::io::Read;
            fs::File::open(n).ok().and_then(|f| {
                let mut buf = Vec::new();
                f.take(PR_PREFIX as u64).read_to_end(&mut buf).ok().map(|_| prefix_sum(&buf))
            })
        };
        cpaths.push(c);
        root_sizes.push(m.len());
        root_sums.push(sum);
        kept.push(n);
    }
    if kept.first() != Some(&CANARY) {
        return "unchecked:canary-unreadable".to_string();
    }

    let answers = match crate::audit::probe_as_uid(probe_uid, move || {
        let mut out = [PR_UNUSED; SLOTS];
        for i in 0..cpaths.len().min(SLOTS) {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::stat(cpaths[i].as_ptr(), &mut st) } != 0 {
                out[i] = PR_NOSTAT;
                continue;
            }
            if st.st_size as u64 != root_sizes[i] {
                out[i] = PR_DIFFER;
                continue;
            }
            // Same length. Now the bytes, if root established a baseline for them. No
            // allocation here: one stack page and read(2) until it is full or the file ends.
            out[i] = PR_AGREE;
            let Some(want) = root_sums[i] else { continue };
            let fd = unsafe { libc::open(cpaths[i].as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            if fd < 0 {
                // Refused by its own mode bits is what stock does too (/system/build.prop is
                // 0600); refused despite them is the anomaly, and its bytes went unread.
                let m = st.st_mode as u32;
                let mode_allows = m & 0o004 != 0
                    || (st.st_uid == probe_uid && m & 0o400 != 0)
                    || (st.st_gid == probe_uid && m & 0o040 != 0);
                if mode_allows {
                    out[i] = PR_NOOPEN;
                }
                continue;
            }
            let mut buf = [0u8; PR_PREFIX];
            let mut got = 0usize;
            let mut read_err = false;
            while got < PR_PREFIX {
                let r = unsafe {
                    libc::read(
                        fd,
                        buf.as_mut_ptr().add(got) as *mut libc::c_void,
                        PR_PREFIX - got,
                    )
                };
                if r < 0 {
                    read_err = true;
                    break;
                }
                if r == 0 {
                    break;
                }
                got += r as usize;
            }
            unsafe { libc::close(fd) };
            if read_err {
                out[i] = PR_NOREAD;
            } else if prefix_sum(&buf[..got]) != want {
                out[i] = PR_BYTES;
            }
        }
        out
    }) {
        Ok(a) => a,
        Err(_) => return "unchecked:probe-unavailable".to_string(),
    };

    if answers[0] != PR_AGREE {
        // The app could not read a file with no rule on it, so nothing below means
        // anything -- do not report a mismatch the injection did not cause.
        return "unchecked:probe-unavailable".to_string();
    }

    let mut checked = 0;
    let mut unread: Option<String> = None;
    for (i, target) in kept.iter().enumerate().skip(1) {
        match answers[i] {
            PR_AGREE => checked += 1,
            PR_DIFFER => return format!("mismatch:{target}(size differs for uid {probe_uid})"),
            PR_BYTES => {
                return format!("mismatch:{target}(same size, different bytes for uid {probe_uid})")
            }
            PR_NOSTAT => return format!("mismatch:{target}(ENOENT for uid {probe_uid})"),
            PR_NOOPEN => return format!("mismatch:{target}(open fails for uid {probe_uid})"),
            PR_NOREAD => {
                unread.get_or_insert_with(|| format!("{target}(uid {probe_uid})"));
            }
            _ => {}
        }
    }
    // A measured divergence above outranks this; an unread file must not pass as "ok".
    if let Some(t) = unread {
        return format!("unchecked:unreadable-as-app:{t}");
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
    // Only a rule with a source has two ends to compare. Counting whiteouts and virtual dirs,
    // which have none, inflated `comparable` past the cap and reported "did not finish looking"
    // on a device where every comparable rule had in fact been checked.
    let comparable = rules.iter().filter(|r| r.uid == 0 && r.source.is_some()).count();
    let mut checked = 0;
    let mut bytes_checked = 0;
    let mut unreadable = 0;
    for rule in rules.iter().filter(|r| r.uid == 0 && r.source.is_some()).take(CAP) {
        let Some(source) = rule.source.as_deref() else { continue };
        let target = rule.target.as_path();
        let Ok(sm) = fs::metadata(source) else {
            unreadable += 1;
            continue;
        };
        if !sm.is_file() {
            continue;
        }
        let Ok(tm) = fs::metadata(target) else {
            unreadable += 1;
            continue;
        };
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
            // head() returns None only on a READ error, and a path that stats as a
            // regular file of exactly the right size and then refuses to read is the
            // "registered but not actually served" case this probe exists to find.
            // `continue` left it in the ok:partial bucket, which grades as a Pass; it
            // belongs with the stat failures, which do not.
            unreadable += 1;
            continue;
        };
        bytes_checked += 1;
        if a != b {
            return format!("drift:{target}(rule={source} bytes differ)");
        }
    }
    // A rule whose source or target will not stat is the "registered but not serving"
    // case this probe exists to find, so it cannot be folded into the pass. A rule whose
    // ends are not regular files (a directory injection) legitimately has nothing to
    // compare, and is not a failure - hence two different words for two different skips.
    if unreadable > 0 {
        format!("unchecked:unreadable({unreadable} of {comparable})")
    } else if checked == 0 {
        "unchecked".to_string()
    } else if comparable > CAP {
        format!("unchecked:over-cap({checked} of {comparable})")
    } else if checked < comparable || bytes_checked < checked {
        format!("ok:partial({checked} of {comparable}, bytes {bytes_checked})")
    } else {
        "ok".to_string()
    }
}

pub fn gather() -> Fingerprint {
    let nm = Nm::new();
    let engine = nm.version().map(|v| format!("v{v}")).unwrap_or_else(|_| "down".into());
    let listed = nm.list();
    let list = listed.as_deref().unwrap_or("").to_string();
    // Counted: a line the parser cannot read is not a rule that went away, so the count is
    // unknown rather than short.
    let (live_rules, unread) = crate::nm::parse_list_counted(&list);
    let counted = |k: crate::nm::LiveKind| -> Option<usize> {
        listed
            .as_ref()
            .ok()
            .filter(|_| unread == 0)
            .map(|_| live_rules.iter().filter(|r| r.kind == k).count())
    };
    let rules = counted(crate::nm::LiveKind::Inject);
    let whiteouts = counted(crate::nm::LiveKind::Whiteout);
    let live = nm.uid_list_live();
    let blocked = match &live {
        Ok(v) => v.len().to_string(),
        Err(_) => "unknown".to_string(),
    };
    // Chosen from the live hide list so the canary never probes as an app we hide from:
    // that app is SUPPOSED to see something different, and measuring it would report the
    // engine working correctly as an inconsistency.
    // An unreadable hide list or package map is "could not tell who to probe as", not
    // "every candidate is hidden".
    let installed = crate::blocklist::installed_packages();
    let probe_known = live.is_ok() && installed.is_some();
    let probe_uid = match (&live, &installed) {
        (Ok(v), Some(inst)) => pick_probe_uid(inst, v),
        _ => None,
    };
    let guard = if crate::mount::guard_tripped() { "tripped" } else { "armed" };
    let split = count_mounts_split();
    Fingerprint {
        version: env!("CARGO_PKG_VERSION").to_string(),
        uname: read_cmd("uname", &["-r"]),
        kbuild: read_cmd("uname", &["-v"]),
        engine,
        rules,
        whiteouts,
        mounts: split.map(|(t, _)| t),
        mounts_foreign: split.map(|(t, d)| t - d),
        blocked,
        consistency: if listed.is_err() {
            "unchecked:engine-list-failed".to_string()
        } else if !probe_known {
            "unchecked:probe-uid-unknown".to_string()
        } else {
            consistency_probe(&live_rules, probe_uid)
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

pub fn run_snapshot() -> Result<()> {
    let body = fingerprint_text()?;
    crate::statefile::write_atomic(SNAPSHOT, &body).context("write snapshot.txt")?;
    print!("{body}");
    println!("snapshot saved to {SNAPSHOT}");
    Ok(())
}

fn fingerprint_text() -> Result<String> {
    // A baseline sampled halfway through a mount/reload pass is wrong forever: every
    // later `verify` compares against it and reports DRIFT.
    let _pass = crate::mount::pass_lock();
    let r = crate::check::build(false, true)?;
    let mut body = r.fingerprint_text();
    let _ = writeln!(body, "ts={}", r.ts);
    Ok(body)
}

pub fn run_verify() -> Result<()> {
    let saved = match fs::read_to_string(SNAPSHOT) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("no snapshot yet - run `nomount snapshot` on a known-good boot first");
            return Ok(());
        }
        // A snapshot that exists but will not open is not the same as not having one. Saying
        // "no snapshot yet" invited the user to take a fresh one, which overwrites the good
        // baseline with the drifted state it was supposed to be compared against.
        Err(e) => {
            anyhow::bail!(
                "{SNAPSHOT} exists but could not be read: {e}. NOT taking a new snapshot - that \
                 would overwrite the baseline with the current state. Fix the permissions, or \
                 delete the file if you mean to start over."
            );
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
    let drifted = lines.iter().filter(|l| l.starts_with("DRIFT ")).count();
    let skipped = lines.len() - drifted;
    let tail = if skipped > 0 {
        format!(" ({skipped} field(s) not compared - one side was not measured)")
    } else {
        String::new()
    };
    if drifted == 0 {
        println!("verify: live matches snapshot (no drift){tail}");
    } else {
        println!("verify: {drifted} field(s) drifted from snapshot{tail}");
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
    // A value that reads "unknown" or "unchecked" on either side says the probe did not run, not
    // that the system changed. Painting those transitions as DRIFT told the user their device had
    // drifted when the only thing that differed was whether a measurement happened.
    let unmeasured = |v: &str| v == "unknown" || v.starts_with("unchecked");
    let suite_moved = find(&sv, "version") != find(&lv, "version");
    let mut out = Vec::new();
    for (k, lval) in &lv {
        let Some(sval) = find(&sv, k) else {
            out.push(if suite_moved {
                format!("not compared {k}: live={lval} (the snapshot predates this field)")
            } else {
                format!("DRIFT {k}: snapshot=<absent> -> live={lval}")
            });
            continue;
        };
        if &sval == lval || is_version_context(k, &sval, lval) {
            continue;
        }
        if unmeasured(&sval) || unmeasured(lval) {
            out.push(format!(
                "not compared {k}: snapshot={sval} -> live={lval} (one side was not measured)"
            ));
            continue;
        }
        out.push(format!("DRIFT {k}: snapshot={sval} -> live={lval}"));
    }
    for (k, sval) in &sv {
        if find(&lv, k).is_none() {
            out.push(if suite_moved {
                format!("not compared {k}: snapshot={sval} (this Suite no longer records it)")
            } else {
                format!("DRIFT {k}: snapshot={sval} -> live=<absent>")
            });
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

pub(crate) fn is_shared_storage(p: &Path) -> bool {
    SHARED_ROOTS.iter().any(|r| p.starts_with(r))
}

const SHELL_TMP: &str = "/data/local/tmp";
const SHELL_ID: u32 = 2000;

fn app_readable_why(p: &Path) -> Option<&'static str> {
    if is_shared_storage(p) {
        Some("is shared storage, readable by any app with a storage permission")
    } else if p.starts_with(SHELL_TMP) {
        Some(
            "is under /data/local/tmp, where any app can look up a name (the bundle itself is \
             readable only by shell, uid 2000, so adb pull works)",
        )
    } else {
        None
    }
}

fn is_for_shell(resolved: &Path, literal: &Path) -> bool {
    !is_shared_storage(resolved) && (resolved.starts_with(SHELL_TMP) || literal.starts_with(SHELL_TMP))
}

fn resolve_existing_prefix(p: &Path) -> PathBuf {
    for a in p.ancestors() {
        let probe = if a.as_os_str().is_empty() { Path::new(".") } else { a };
        if let Ok(r) = fs::canonicalize(probe) {
            return r.join(p.strip_prefix(a).unwrap_or(Path::new("")));
        }
    }
    p.to_path_buf()
}

/// The bundle's folder, held open by fd. Every file in it is created through that fd with
/// O_EXCL|O_NOFOLLOW, the zip likewise beside it, and the folders this export made are
/// handed to shell last, by fd: a path walk after a chown let a shell-planted symlink pick
/// what root wrote through, and what it then chowned.
struct ExportDir {
    anchor: std::os::fd::OwnedFd,
    created: Vec<std::os::fd::OwnedFd>,
    leaf: std::os::fd::OwnedFd,
    name: String,
    private: bool,
    owner: Option<(u32, u32)>,
    files: std::cell::RefCell<Vec<(String, Vec<u8>)>>,
}

fn cstr(s: &std::ffi::OsStr) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(s.as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in a path"))
}

fn fd_or_err(fd: libc::c_int) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// mkdirat, then open what is there without following a link, and insist it is ours: the
/// name sits in a folder someone else may write to.
fn mkdir_open_at(
    dir: &std::os::fd::OwnedFd,
    name: &std::ffi::OsStr,
    mode: libc::mode_t,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::AsRawFd;
    let c = cstr(name)?;
    if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), mode) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let fd = fd_or_err(unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if st.st_uid != unsafe { libc::geteuid() } {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "the folder just created was replaced by someone else's",
        ));
    }
    Ok(fd)
}

impl ExportDir {
    /// `<base>/<stem>`, or `<stem>-N` when that folder or its zip already exists.
    fn claim(base: &Path, stem: &str, private: bool, owner: Option<(u32, u32)>) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        let mut anchor = base.to_path_buf();
        let mut missing: Vec<std::ffi::OsString> = Vec::new();
        loop {
            let probe = if anchor.as_os_str().is_empty() { Path::new(".") } else { anchor.as_path() };
            if fs::symlink_metadata(probe).is_ok() {
                anchor = probe.to_path_buf();
                break;
            }
            let name = anchor.file_name().map(|n| n.to_os_string()).ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a folder path")
            })?;
            missing.push(name);
            anchor = anchor.parent().map(Path::to_path_buf).unwrap_or_default();
        }
        missing.reverse();
        // The existing part is the caller's own path, links and all.
        let anchor = fd_or_err(unsafe {
            libc::open(
                cstr(anchor.as_os_str())?.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        })?;
        let mode = if private { 0o700 } else { 0o777 };
        let mut created: Vec<std::os::fd::OwnedFd> = Vec::new();
        for n in &missing {
            let fd = mkdir_open_at(created.last().unwrap_or(&anchor), n, mode)?;
            created.push(fd);
        }
        let base_fd = created.last().unwrap_or(&anchor).as_raw_fd();
        for i in 0..100 {
            let name = if i == 0 { stem.to_string() } else { format!("{stem}-{i}") };
            let zip = cstr(std::ffi::OsStr::new(&format!("{name}.zip")))?;
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstatat(base_fd, zip.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } == 0 {
                continue;
            }
            let base = created.last().unwrap_or(&anchor);
            match mkdir_open_at(base, std::ffi::OsStr::new(&name), mode) {
                Ok(leaf) => {
                    return Ok(Self {
                        anchor,
                        created,
                        leaf,
                        name,
                        private,
                        owner,
                        files: std::cell::RefCell::new(Vec::new()),
                    })
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("{stem} and 99 numbered folders beside it already exist"),
        ))
    }

    fn base(&self) -> &std::os::fd::OwnedFd {
        self.created.last().unwrap_or(&self.anchor)
    }

    /// Where the bundle really landed, read back from the fd rather than the path.
    fn resolved(&self) -> Option<PathBuf> {
        use std::os::fd::AsRawFd;
        fs::read_link(format!("/proc/self/fd/{}", self.leaf.as_raw_fd())).ok()
    }

    fn create_at(&self, dir: &std::os::fd::OwnedFd, name: &str, content: &[u8]) -> std::io::Result<()> {
        use std::io::Write as _;
        use std::os::fd::AsRawFd;
        let c = cstr(std::ffi::OsStr::new(name))?;
        let fd = fd_or_err(unsafe {
            libc::openat(
                dir.as_raw_fd(),
                c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                (if self.private { 0o600 } else { 0o644 }) as libc::c_uint,
            )
        })?;
        let mut f = fs::File::from(fd);
        if let Some((uid, gid)) = self.owner {
            std::os::unix::fs::fchown(&f, Some(uid), Some(gid))?;
        }
        f.write_all(content)
    }

    fn put(&self, name: &str, content: &[u8]) -> std::io::Result<()> {
        self.create_at(&self.leaf, name, content)?;
        self.files.borrow_mut().push((name.to_string(), content.to_vec()));
        Ok(())
    }

    fn put_zip(&self) -> std::io::Result<()> {
        let z = stored_zip(&self.files.borrow());
        self.create_at(self.base(), &format!("{}.zip", self.name), &z)
    }

    /// Last, once nothing more is written through these folders.
    fn hand_over(&self) -> std::io::Result<()> {
        let Some((uid, gid)) = self.owner else { return Ok(()) };
        for d in std::iter::once(&self.leaf).chain(self.created.iter().rev()) {
            std::os::unix::fs::fchown(d, Some(uid), Some(gid))?;
        }
        Ok(())
    }
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in bytes {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}

/// A stored (uncompressed) zip of the bundle's files. An issue takes a file, not a folder,
/// and the phone that just had the problem has no zip tool. Timestamps are fixed at
/// 1980-01-01, as in scripts/mkzip.py.
fn stored_zip(files: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut files: Vec<&(String, Vec<u8>)> = files.iter().collect();
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let (mut out, mut central, mut count) = (Vec::new(), Vec::new(), 0u16);
    for (name, data) in files {
        let (crc, size, nlen, off) =
            (crc32(&data), data.len() as u32, name.len() as u16, out.len() as u32);
        const TIME_DATE: [u8; 4] = [0, 0, 0x21, 0];
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&TIME_DATE);
        for v in [crc, size, size] {
            out.extend_from_slice(&v.to_le_bytes());
        }
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&data);
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0]);
        central.extend_from_slice(&TIME_DATE);
        for v in [crc, size, size] {
            central.extend_from_slice(&v.to_le_bytes());
        }
        central.extend_from_slice(&nlen.to_le_bytes());
        central.extend_from_slice(&[0; 12]);
        central.extend_from_slice(&off.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
        count += 1;
    }
    let (cd_off, cd_len) = (out.len() as u32, central.len() as u32);
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0; 4]);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
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
                 nomount export /data/adb/nomount/report",
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
    let stem = format!("nm-diag-{ts}");
    let out = format!("{base}/{stem}");
    if let Some(why) = base_unusable(Path::new(&base)) {
        anyhow::bail!("cannot export to {base}: {why}");
    }
    let resolved = resolve_existing_prefix(Path::new(&out));
    let public = app_readable_why(&resolved).or_else(|| app_readable_why(Path::new(&out)));
    let shared = public.is_some();
    let for_shell = is_for_shell(&resolved, Path::new(&out));
    let private = !shared || for_shell;
    let owner = for_shell.then_some((SHELL_ID, SHELL_ID));
    let bundle = ExportDir::claim(Path::new(&base), &stem, private, owner)
        .with_context(|| format!("create {out}"))?;
    let out = format!("{base}/{}", bundle.name);
    // Shell owns folders on that path, so it can swap one for a link between the check
    // above and the mkdir: the folder handed to shell must still be under /data/local/tmp.
    if for_shell && !bundle.resolved().is_some_and(|p| p.starts_with(SHELL_TMP)) {
        anyhow::bail!("cannot export to {base}: the folder did not stay under {SHELL_TMP} while it was created");
    }

    let nm = Nm::new();
    let write = |name: &str, content: &str| {
        if let Err(e) = bundle.put(name, content.as_bytes()) {
            eprintln!("nomount: export: could not write {name}: {e} - this diagnostic is incomplete");
        }
    };

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
    // Written into the bundle as well as printed: whoever reads the bundle has to be able
    // to tell "withheld" from "absent on that device", and the WebUI keeps none of stdout.
    let note = public.map(|why| {
        let left_out = if withheld.is_empty() {
            String::new()
        } else {
            format!(
                "{} left out - they can name the apps you are hiding from. ",
                withheld.join(", ")
            )
        };
        format!(
            "note: {left_out}{out} {why}, so the hide list was kept out of it: rules.txt UID, \
             scope and excluded-app suffixes, the check report's hide-list names, any package name left in blocklist, \
             any /data/app path in the fingerprint, the rule list, the check report and \
             mountinfo, and the crashed app named in incident.log were redacted in place. Pass a private path for the unredacted \
             bundle: nomount export /data/adb/nomount/report"
        )
    });
    if let Some(n) = &note {
        write("WITHHELD.txt", &format!("{n}\n"));
    }
    println!("exported to {out}");
    let zip = format!("{out}.zip");
    match bundle.put_zip() {
        Ok(()) => println!("zip: {zip}"),
        Err(e) => eprintln!("nomount: export: could not write {zip}: {e} - attach the folder's files"),
    }
    if let Err(e) = bundle.hand_over() {
        eprintln!("nomount: export: could not hand {out} to shell: {e} - adb pull needs root");
    }
    if let Some(n) = note {
        println!("{n}");
    }
    Ok(())
}

fn dmesg_section(shared: bool, dmesg: &str) -> (String, bool) {
    if shared && !dmesg.is_empty() {
        return (
            "(left out - the kernel ring carries the Suite's own boot log, which can name the \
             apps you are hiding from. For this file, re-run to a private path: \
             nomount export /data/adb/nomount/report)\n"
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
        .map(|l| crate::nm::split_markers(l).0.trim_end())
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
        "incident.log" => redact_tombstone_names(&redact_app_paths_doc(body)),
        _ => redact_app_paths_doc(body),
    }
}

/// A tombstone line names the crashed process, which can be an app on the hide list. The
/// same substitution as the WebUI's redactIncident (30-checks.js): a dotted name after
/// `>>> ` or `name: `, followed by `:` or a space, unless it is the platform's own.
fn redact_tombstone_names(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut rest = body;
    while let Some((i, len)) =
        [">>> ", "name: "].iter().filter_map(|m| rest.find(m).map(|i| (i, m.len()))).min()
    {
        let (head, tail) = rest.split_at(i + len);
        out.push_str(head);
        let end = tail
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
            .unwrap_or(tail.len());
        let name = &tail[..end];
        let dotted = name.contains('.') && name.split('.').all(|l| !l.is_empty());
        let platform = name.starts_with("com.android.") || name.starts_with("android.");
        if dotted && !platform && tail[end..].starts_with([':', ' ']) {
            out.push_str("<app>");
        } else {
            out.push_str(name);
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
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
mod zip_tests {
    use super::*;

    #[test]
    fn the_export_zip_is_a_valid_stored_archive() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926, "the standard CRC-32 check value");
        let z = stored_zip(&[
            ("b.txt".to_string(), b"second".to_vec()),
            ("a.txt".to_string(), b"first file".to_vec()),
        ]);
        assert_eq!(&z[..4], b"PK\x03\x04");
        let eocd = &z[z.len() - 22..];
        assert_eq!(&eocd[..4], b"PK\x05\x06");
        assert_eq!(u16::from_le_bytes([eocd[10], eocd[11]]), 2, "two entries");
        if let Ok(p) = std::env::var("NM_ZIP_TEST_OUT") {
            fs::write(p, &z).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_length_contents_fold_to_different_sums() {
        // What the byte half of the canary rests on. Equal st_size is cheap to satisfy by
        // accident -- a shadowed prop file, an APK replaced with another of the same length
        // -- and the comparison was size alone while the PASS row claimed "the same bytes".
        assert_eq!(prefix_sum(b"abc"), prefix_sum(b"abc"), "the fold must be deterministic");
        assert_ne!(prefix_sum(b"ro.build.x=1\n"), prefix_sum(b"ro.build.x=2\n"));
        assert_ne!(prefix_sum(&[0u8; 16]), prefix_sum(&[1u8; 16]));
        // A short read must not look like the full one either.
        assert_ne!(prefix_sum(b"abcd"), prefix_sum(b"abc"));
        assert_ne!(prefix_sum(b""), prefix_sum(b"\0"));
    }

    #[test]
    fn the_canary_probes_as_a_real_unhidden_app_never_shell() {
        let pkgs = |v: &[(&str, u32)]| -> Vec<(String, u32)> {
            v.iter().map(|(p, u)| ((*p).to_string(), *u)).collect()
        };
        let installed = pkgs(&[
            ("android", 1000),
            ("com.android.shell", 2000),
            ("com.a", 10050),
            ("com.b", 10120),
        ]);

        // Never a system uid: shell is a different uid band AND a different domain, so
        // "shell agrees with root" was never the question this canary asks.
        assert_eq!(pick_probe_uid(&installed, &[]), Some(10050));

        // An app we hide from is SUPPOSED to see something different; probing as one
        // would report the engine working correctly as an inconsistency.
        assert_eq!(pick_probe_uid(&installed, &[10050]), Some(10120));

        // Hidden in a work profile is the same appid, so it must be excluded too.
        assert_eq!(
            pick_probe_uid(&installed, &[1010050]),
            Some(10120),
            "appid must be compared after normalising the user id out"
        );

        // Everything hidden: say so rather than falling back to a system uid.
        assert_eq!(pick_probe_uid(&installed, &[10050, 10120]), None);
        assert_eq!(pick_probe_uid(&pkgs(&[("android", 1000)]), &[]), None);
    }

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
    fn a_field_a_newer_suite_added_is_not_drift() {
        let saved = "version=1.3.185\nengine=v30\n";
        let live = "version=1.3.186\nengine=v30\nkbuild=#1 SMP\n";
        assert_eq!(
            drift_lines(saved, live),
            vec!["not compared kbuild: live=#1 SMP (the snapshot predates this field)"],
            "adding a fingerprint field must not report drift on every existing install"
        );
    }

    #[test]
    fn a_field_missing_within_one_suite_version_is_still_drift() {
        let saved = "version=1.3.185\nengine=v30\nmanager_umount=off\n";
        let live = "version=1.3.185\nengine=v30\n";
        assert_eq!(
            drift_lines(saved, live),
            vec!["DRIFT manager_umount: snapshot=off -> live=<absent>"],
            "same Suite on both sides means a vanished field is a real regression"
        );
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
            kbuild: "test".into(),
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
    fn stopping_at_the_cap_is_unmeasured_not_a_failure() {
        let mut fp = fp("v33", 257);
        fp.served_matches_rule = "unchecked:over-cap(20000 of 20001)".into();
        assert_eq!(
            verdict_of(&fp, "served bytes match the rule"),
            "UNMEASURED",
            "running out of scan budget is not evidence that a path serves the wrong bytes, and \
             the FAIL text told the user to delete a bind and reboot"
        );

        // A real mismatch must still fail.
        fp.served_matches_rule = "drift:/system/etc/x(rule=/data/adb/modules/m/x bytes differ)".into();
        assert_eq!(verdict_of(&fp, "served bytes match the rule"), "FAIL");
    }

    #[test]
    fn a_field_that_was_not_measured_is_not_reported_as_drift() {
        let saved = "rules=257\nserved_matches_rule=ok\nzero_mount=unknown\n";
        let live = "rules=257\nserved_matches_rule=unchecked\nzero_mount=ok\n";
        let lines = drift_lines(saved, live);
        assert!(
            lines.iter().all(|l| !l.starts_with("DRIFT ")),
            "neither side changed state - one side simply was not measured: {lines:?}"
        );
        assert_eq!(lines.len(), 2, "but they are still reported, not hidden: {lines:?}");

        // A genuine change is still drift.
        let real = drift_lines("rules=257\n", "rules=12\n");
        assert_eq!(real.len(), 1);
        assert!(real[0].starts_with("DRIFT rules:"), "{real:?}");
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
    fn data_local_tmp_is_redacted_like_shared_storage() {
        for p in [
            "/data/local/tmp/nm-diag-1",
            "/data/local/tmp/nm-report/nm-diag-1",
            "/sdcard/Download/nm-diag-1",
            "/storage/emulated/0/Download/nm-diag-1",
        ] {
            assert!(app_readable_why(Path::new(p)).is_some(), "{p} is readable by apps");
        }
        for p in ["/data/adb/nomount/report/nm-diag-1", "/data/localx/tmp/x", "/data/local/tmpx/y"] {
            assert!(app_readable_why(Path::new(p)).is_none(), "{p} is private");
        }
        let why = app_readable_why(Path::new("/data/local/tmp/nm-diag-1")).unwrap();
        assert!(!why.contains("shared storage"), "{why}");

        let p = Path::new;
        assert!(is_for_shell(p("/data/local/tmp/nm-diag-1"), p("/data/local/tmp/nm-diag-1")));
        assert!(is_for_shell(p("/data/local/tmp/x/nm-diag-1"), p("/tmp-link/nm-diag-1")));
        assert!(!is_for_shell(p("/storage/emulated/0/x"), p("/data/local/tmp/sd/x")));
        assert!(!is_for_shell(p("/sdcard/Download/x"), p("/sdcard/Download/x")));
        assert!(!is_for_shell(p("/data/adb/nomount/report/x"), p("/data/adb/nomount/report/x")));
    }

    #[test]
    fn the_export_advice_never_points_at_an_app_readable_path() {
        const SRC: &str = include_str!("health.rs");
        let body = SRC.split("#[cfg(test)]").next().unwrap();
        let bad = ["nomount export", "/data/local", "/tmp"].concat();
        assert!(!body.contains(&bad), "the advice must not recommend an app-readable path");
        assert!(body.contains("nomount export /data/adb/nomount/report"));
    }

    #[test]
    fn a_private_export_is_root_only() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let b = ExportDir::claim(&d.path().join("report"), "nm-diag-1", true, None).unwrap();
        let out = d.path().join("report").join("nm-diag-1");
        b.put("uidhide", b"com.example.bank\n").unwrap();
        let f = out.join("uidhide");
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&out), 0o700, "the bundle folder must not be traversable by apps");
        assert_eq!(mode(out.parent().unwrap()), 0o700);
        assert_eq!(mode(&f), 0o600, "the bundle files must not be readable by apps");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "com.example.bank\n");

        assert!(b.put("uidhide", b"x").is_err(), "nothing already there is written through");
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "com.example.bank\n");
        b.put_zip().unwrap();
        assert!(d.path().join("report").join("nm-diag-1.zip").is_file());
    }

    #[test]
    fn an_export_never_writes_through_a_planted_link() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let victim = d.path().join("victim");
        std::fs::write(&victim, b"precious").unwrap();
        // The zip's name is predictable to the second: a link there moves the bundle aside.
        symlink(&victim, d.path().join("nm-diag-1.zip")).unwrap();
        std::fs::create_dir(d.path().join("nm-diag-2")).unwrap();
        let b = ExportDir::claim(d.path(), "nm-diag-1", true, None).unwrap();
        assert_eq!(b.name, "nm-diag-1-1");
        let b2 = ExportDir::claim(d.path(), "nm-diag-2", true, None).unwrap();
        assert_eq!(b2.name, "nm-diag-2-1", "an existing folder is not reused");

        symlink(&victim, d.path().join("nm-diag-1-1").join("rules.txt")).unwrap();
        assert!(b.put("rules.txt", b"bundle").is_err());
        b.put("uname.txt", b"u").unwrap();
        b.put_zip().unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious");
    }

    #[test]
    fn a_shell_export_hands_only_the_folders_it_created_to_shell() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let me = unsafe { (libc::getuid(), libc::getgid()) };
        let d = tempfile::tempdir().unwrap();
        let pre = d.path().join("tmp");
        std::fs::create_dir(&pre).unwrap();
        std::fs::set_permissions(&pre, std::fs::Permissions::from_mode(0o771)).unwrap();
        let b = ExportDir::claim(&pre.join("nm-report"), "nm-diag-1", true, Some(me)).unwrap();
        let out = pre.join("nm-report").join("nm-diag-1");
        b.put("rules.txt", b"r\n").unwrap();
        b.hand_over().unwrap();
        let f = out.join("rules.txt");
        let md = |p: &Path| std::fs::metadata(p).unwrap();
        for p in [out.as_path(), out.parent().unwrap()] {
            assert_eq!(md(p).permissions().mode() & 0o777, 0o700, "{}", p.display());
            assert_eq!((md(p).uid(), md(p).gid()), me, "{}", p.display());
        }
        assert_eq!(md(&f).permissions().mode() & 0o777, 0o600);
        assert_eq!((md(&f).uid(), md(&f).gid()), me);
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "r\n");
        assert_eq!(
            md(&pre).permissions().mode() & 0o777,
            0o771,
            "a folder that was already there is left alone"
        );
    }

    #[test]
    fn a_destination_that_does_not_exist_yet_resolves_through_its_parent() {
        let d = tempfile::tempdir().unwrap();
        let real = d.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let got = resolve_existing_prefix(&link.join("nm-diag-1").join("x"));
        let want = std::fs::canonicalize(&real).unwrap().join("nm-diag-1").join("x");
        assert_eq!(got, want);
    }

    #[test]
    fn a_target_shell_cannot_reach_is_not_sampled_by_the_canary() {
        use std::os::unix::fs::PermissionsExt;
        let set = |p: &Path, m: u32| {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap()
        };
        let d = tempfile::tempdir().unwrap();
        set(d.path(), 0o755);
        let open = d.path().join("etc");
        let locked = d.path().join("firmware_mnt");
        let inner = locked.join("image");
        std::fs::create_dir(&open).unwrap();
        std::fs::create_dir_all(&inner).unwrap();
        let reachable = open.join("hosts");
        let behind = inner.join("modem.mbn");
        std::fs::write(&reachable, b"x").unwrap();
        std::fs::write(&behind, b"x").unwrap();
        set(&locked, 0o550);
        set(&inner, 0o755);

        assert!(others_can_search_to(&reachable));
        assert!(!others_can_search_to(&behind), "a dr-xr-x--- ancestor blocks uid 2000 like any app");
        assert!(!others_can_search_to(&d.path().join("gone").join("x")));

        set(&locked, 0o551);
        assert!(others_can_search_to(&behind));
        set(&locked, 0o755);
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
    fn the_canary_never_samples_a_rule_that_excludes_the_probe_uid() {
        let list = "/data/app/~~x/pkg-y/base.apk -> /data/adb/rvhc/m.apk \
                    [SCOPE: 0-4294967295] [DENY: 10150]\n\
                    /product/app/B/B.apk -> /data/adb/modules/M/product/app/B/B.apk \
                    [SCOPE: 0-19999]\n\
                    /system/etc/hosts -> /data/adb/modules/M/system/etc/hosts\n";
        let rules = crate::nm::parse_list(list);
        let sampled = |uid: u32| -> Vec<String> {
            canary_buckets(&rules, uid)
                .into_values()
                .flatten()
                .map(|p| p.display().to_string())
                .collect()
        };
        assert_eq!(sampled(10150), ["/product/app/B/B.apk", "/system/etc/hosts"]);
        assert_eq!(sampled(1010150), ["/system/etc/hosts"], "excluded by appid, and out of range");
        assert_eq!(sampled(10151).len(), 3);
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

        let scoped = "/product/app/X/X.apk -> /data/adb/rvhc/x.apk \
                      [SCOPE: 0-4294967295] [DENY: 10397,10471]\n";
        let got = redact_rules_for_shared(scoped);
        assert!(!got.contains("10397") && !got.contains("[DENY:"), "excluded apps leak: {got}");
        assert!(!got.contains("[SCOPE:"), "{got}");
        assert_eq!(got, "/product/app/X/X.apk -> /data/adb/rvhc/x.apk");

        let clean = "/system/etc/hosts -> /data/adb/modules/M/system/etc/hosts\n";
        assert_eq!(redact_app_paths_doc(clean), clean);
        assert_eq!(redact_rules_for_shared(clean), clean.trim_end());

        let inc = "tombstone=/data/tombstones/tombstone_00\n  Abort message: \
                   could not open /data/app/~~aB1/com.mybank.app-x9/base.apk\n";
        assert!(!redact_for_shared("incident.log", inc).contains("com.mybank.app"));

        let inc = "tombstone=/data/tombstones/tombstone_01\n  \
                   pid: 4121, tid: 4121, name: com.detector.app  >>> com.detector.app:remote <<<\n";
        let got = redact_for_shared("incident.log", inc);
        assert!(!got.contains("com.detector.app"), "the crashed app must not survive: {got}");
        assert!(got.contains("name: <app>  >>> <app>:remote <<<"), "{got}");
        let sys = "  pid: 1, tid: 1, name: com.android.phone  >>> com.android.phone <<<\n";
        assert_eq!(redact_for_shared("incident.log", sys), sys, "the platform's own stays readable");
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
