//! `nomount audit` — prove the hiding actually holds, on THIS device.
//!
//! Every check here reproduces a detection oracle that was found, and closed, by
//! measuring a real device: an app that can run these can also run them against
//! us. Bundling them means a user can answer "is my setup detectable?" without
//! hand-written probes, and a regression announces itself instead of waiting for
//! someone to go looking.
//!
//! Two rules this file exists to enforce on itself:
//!   * MEASURE, never infer. Each check reports what it read, not what the
//!     configuration implies it should have read. Three kernel patches in this
//!     project compiled clean and did nothing; only measurement caught them.
//!   * A check that cannot run says so. "Skipped" is a distinct result from
//!     "passed" -- reporting an unrun check as clean is how a hole survives.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::nm::Nm;

#[derive(PartialEq, Clone, Copy)]
pub enum Verdict {
    Pass,
    Fail,
    /// Real, but already cured -- a reboot applies the fix that is pending.
    Reboot,
    /// The check does not apply to THIS device or THIS configuration, and no
    /// arrangement of the two would make it apply as things stand. No overlay
    /// mount, no single-block erofs parent, no app on the hide list yet.
    ///
    /// Split out of `Skip` because collapsing the two is what made a healthy
    /// device render amber. "There was nothing here to test" and "something
    /// stopped me testing" are different answers, and only the second is a
    /// warning. A clean device now reads `undetected` with a grey `n/a` count
    /// beside it instead of `4 unverified` in amber with an alert dot.
    ///
    /// This is NOT a softening of the honesty rule in this file's header. The
    /// rule is that an unrun check must never be reported as clean, and it still
    /// is not: `NotApplicable` is counted, printed and JSON-emitted as its own
    /// state, never folded into the pass count.
    NotApplicable,
    /// The check COULD have applied and did not run: mountinfo unreadable, fork
    /// failed, the probe child said nothing, a directory that would not
    /// enumerate. Stays amber, because this is precisely the state the "a check
    /// that cannot run says so" rule exists for.
    Unmeasured,
}

/// How much an app needs to do to read this oracle. Every FAIL used to render
/// identically fatal; they are not remotely equivalent, and sorting by this is
/// what tells a user which one to fix first.
#[derive(PartialEq, Clone, Copy)]
pub enum Reach {
    /// One syscall, any app, no permission. `getdents64` on a directory,
    /// `/proc/self/maps`, `/proc/self/mountinfo`.
    AnyApp,
    /// Reachable by an app, but it has to model the filesystem to interpret what
    /// it read -- bucket a whole directory's inodes, or replay erofs block
    /// packing -- so it takes a detector built for the purpose.
    Effort,
    /// Not reachable from an app domain at all on a stock policy.
    ///
    /// No check in this file is currently RootOnly, and that is a property of
    /// what the audit chooses to bundle rather than an oversight: every oracle
    /// here was found by measuring what an APP can read, because an oracle root
    /// alone can reach is not a detection risk. Kept so a future check can say so
    /// rather than being forced to overstate itself as `Effort`.
    #[allow(dead_code)]
    RootOnly,
}

impl Reach {
    fn slug(self) -> &'static str {
        match self {
            Reach::AnyApp => "any-app",
            Reach::Effort => "needs-effort",
            Reach::RootOnly => "root-only",
        }
    }
    fn label(self) -> &'static str {
        match self {
            Reach::AnyApp => "any app",
            Reach::Effort => "needs effort",
            Reach::RootOnly => "root only",
        }
    }
    /// Sort key: the thing any app can read comes first.
    fn rank(self) -> u8 {
        match self {
            Reach::AnyApp => 0,
            Reach::Effort => 1,
            Reach::RootOnly => 2,
        }
    }
}

/// One thing the user can do about a finding, which the WebUI renders as a
/// button. A finding with an owner but no action is still an improvement on a
/// finding with neither; a finding with both is one tap from closed.
pub struct Action {
    /// Stable id the WebUI switches on. Never shown.
    pub id: &'static str,
    pub label: &'static str,
    /// Path, module id, or whatever the action needs.
    pub arg: Option<String>,
}

pub struct Check {
    /// Stable slug. This is what an acceptance is keyed on and what the WebUI
    /// uses for element ids, so it must not change when the display name does.
    pub id: &'static str,
    pub name: &'static str,
    pub verdict: Verdict,
    /// What was actually read. Always populated, including on a pass -- a bare
    /// "OK" is not evidence.
    pub evidence: String,
    /// What an attacker would do with a failure. Only on Fail.
    pub oracle: Option<&'static str>,
    /// One line in the reader's terms, always present, on every verdict.
    ///
    /// The evidence strings are written for whoever is debugging the engine and
    /// they are good at that job: "2 injected inode(s) alone in the 3M bucket, no
    /// stock there" says exactly what was measured. It also says nothing at all
    /// to the person who installed a module and wants to know if they are fine.
    /// This field is that person's sentence; the evidence stays, one disclosure
    /// away.
    pub meaning: String,
    pub reach: Reach,
    /// Who caused this: a module id, the kernel, the root manager, or the user's
    /// own configuration. `None` where the question does not apply (a pass).
    ///
    /// A finding without an owner is a finding nobody can close. `absorb` already
    /// resolves a leaked mount to its owning module and the audit used to throw
    /// that answer away for exactly the case where it mattered.
    pub owner: Option<String>,
    pub action: Option<Action>,
}

/// Builder, so a check body stays about what it measured. Everything except the
/// verdict-specific parts has a sane default; the `with_*` methods add what the
/// individual check knows.
fn chk(id: &'static str, name: &'static str, verdict: Verdict, evidence: String) -> Check {
    Check {
        id,
        name,
        verdict,
        evidence,
        oracle: None,
        meaning: String::new(),
        reach: Reach::AnyApp,
        owner: None,
        action: None,
    }
}

impl Check {
    fn meaning(mut self, m: impl Into<String>) -> Check {
        self.meaning = m.into();
        self
    }
    fn reach(mut self, r: Reach) -> Check {
        self.reach = r;
        self
    }
    fn owner(mut self, o: impl Into<String>) -> Check {
        self.owner = Some(o.into());
        self
    }
    fn action(mut self, id: &'static str, label: &'static str, arg: Option<String>) -> Check {
        self.action = Some(Action { id, label, arg });
        self
    }
    /// Fingerprint of the evidence, for [`crate::accept`].
    pub fn fingerprint(&self) -> String {
        crate::json::fingerprint(&self.evidence)
    }
    fn verdict_slug(&self) -> &'static str {
        match self.verdict {
            Verdict::Pass => "pass",
            Verdict::Fail => "fail",
            Verdict::Reboot => "reboot",
            Verdict::NotApplicable => "n/a",
            Verdict::Unmeasured => "unmeasured",
        }
    }
    fn tag(&self) -> &'static str {
        match self.verdict {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Reboot => "REBOOT",
            Verdict::NotApplicable => "N/A",
            Verdict::Unmeasured => "UNMEASURED",
        }
    }
}

fn pass(name: &'static str, evidence: String) -> Check {
    chk(id_of(name), name, Verdict::Pass, evidence)
}
fn fail(name: &'static str, evidence: String, oracle: &'static str) -> Check {
    let mut c = chk(id_of(name), name, Verdict::Fail, evidence);
    c.oracle = Some(oracle);
    c
}
/// "Does not apply here." Grey, never amber, never counted as a pass.
fn na(name: &'static str, evidence: String) -> Check {
    chk(id_of(name), name, Verdict::NotApplicable, evidence)
}
/// "Could have applied, did not run." Amber -- this is the honesty rule's state.
fn unmeasured(name: &'static str, evidence: String) -> Check {
    chk(id_of(name), name, Verdict::Unmeasured, evidence)
}
fn reboot(name: &'static str, evidence: String, oracle: &'static str) -> Check {
    let mut c = chk(id_of(name), name, Verdict::Reboot, evidence);
    c.oracle = Some(oracle);
    c
}

/// Display name -> stable id.
///
/// Kept as one table rather than threaded through every constructor: the display
/// names are already unique and already passed everywhere, and a second literal
/// at each call site is a second thing to keep in sync. A name with no entry
/// falls back to itself, which is stable enough to key an acceptance on and loud
/// enough to notice.
fn id_of(name: &str) -> &'static str {
    match name {
        "zero-mount posture" => "zero-mount",
        "kernel surfaces" => "kernel-surfaces",
        "readdir cookie magic" => "dirent-cookie",
        "readdir ino vs stat ino" => "dino-vs-stat",
        "injected inode band" => "inode-band",
        "overlay dir inode range" => "overlay-dir-ino",
        "erofs directory shape" => "erofs-dir-shape",
        "injected files in maps" => "maps-deleted",
        "PM-published files open for a hidden app" => "pm-published-open",
        "tmpfs over the ROM" => "rom-tmpfs",
        "foreign mount over the ROM" => "rom-foreign-mount",
        _ => "unknown-check",
    }
}

// ---------------------------------------------------------------- raw readdir

#[repr(C)]
struct Dirent64Hdr {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
}

pub struct Entry {
    pub name: String,
    pub d_ino: u64,
    pub d_off: i64,
}

/// getdents64 directly: `read_dir` exposes neither `d_off` nor `d_ino`, and both
/// are oracles in their own right.
pub fn getdents(dir: &Path) -> Option<Vec<Entry>> {
    let c = std::ffi::CString::new(dir.as_os_str().to_string_lossy().as_bytes()).ok()?;
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
    if fd < 0 {
        return None;
    }
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = unsafe {
            libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) as isize
        };
        if n <= 0 {
            break;
        }
        let mut off = 0usize;
        while off + std::mem::size_of::<Dirent64Hdr>() <= n as usize {
            // SAFETY: the kernel guarantees a header plus a NUL-terminated name
            // within d_reclen; we never read past `n`.
            let h = unsafe { &*(buf.as_ptr().add(off) as *const Dirent64Hdr) };
            let reclen = h.d_reclen as usize;
            // `< 19` too, not just 0: `nstart` is off+19 and the slice below is
            // buf[nstart..off+reclen], so a d_reclen of 1..=18 gives start > end
            // and PANICS the slice index -- in the tool whose job is to report
            // rather than abort. Real kernels always emit >= 24; a truncated or
            // hostile getdents64 buffer should end the walk, not the process.
            if reclen < 19 || off + reclen > n as usize {
                break;
            }
            let nstart = off + 19; // offsetof(name)
            let nend = buf[nstart..off + reclen].iter().position(|&c| c == 0).unwrap_or(0) + nstart;
            if let Ok(name) = std::str::from_utf8(&buf[nstart..nend]) {
                if name != "." && name != ".." {
                    out.push(Entry { name: name.to_string(), d_ino: h.d_ino, d_off: h.d_off });
                }
            }
            off += reclen;
        }
    }
    unsafe { libc::close(fd) };
    Some(out)
}

// ------------------------------------------------------------------- helpers

/// Live INJECTION targets.
///
/// Deliberately not every rule: a whiteout's whole job is to make its target
/// absent from the parent's listing, so feeding one to a check that asserts
/// "this name appears in getdents" turns a working whiteout into a failure. The
/// hand-rolled token split this replaced could not tell the kinds apart, so any
/// device with a debloat module (or a hand-written `nomount whiteout add`) would
/// have reported a fabricated "readdir ino vs stat ino" FAIL on the audit users
/// are told to trust. Route through the shared typed parser instead.
fn live_targets() -> Vec<PathBuf> {
    crate::nm::parse_list(&Nm::new().list().unwrap_or_default())
        .into_iter()
        .filter(|r| r.kind == crate::nm::LiveKind::Inject)
        .map(|r| r.target)
        .collect()
}

fn parents_of(targets: &[PathBuf]) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> =
        targets.iter().filter_map(|t| t.parent().map(|p| p.to_path_buf())).collect();
    v.sort();
    v.dedup();
    v
}

fn fs_type(p: &Path) -> String {
    // statfs f_type, rendered as the names the checks care about.
    let Ok(c) = std::ffi::CString::new(p.as_os_str().to_string_lossy().as_bytes()) else {
        return "?".into();
    };
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(c.as_ptr(), &mut s) } != 0 {
        return "?".into();
    }
    match s.f_type as i64 {
        0xE0F5E1E2 => "erofs".into(),
        0x794C7630 => "overlay".into(),
        0xF2F52010 => "f2fs".into(),
        other => format!("0x{other:x}"),
    }
}

fn ino_of(p: &Path) -> Option<u64> {
    fs::symlink_metadata(p).ok().map(|m| {
        use std::os::unix::fs::MetadataExt;
        m.ino()
    })
}

// -------------------------------------------------------------------- checks

/// Injections must not be mounts. Counts on mountinfo field 4 (the mount's root
/// within its filesystem) -- matching on a path never matched anything, which is
/// how the old counter reported zero regardless of reality.
fn check_zero_mount() -> Check {
    let Ok(mi) = fs::read_to_string("/proc/self/mountinfo") else {
        // UNMEASURED, not n/a: every device has a mount table, so failing to read
        // it means the check did not run -- exactly the state that must stay amber.
        return unmeasured("zero-mount posture", "cannot read /proc/self/mountinfo".into())
            .meaning("Could not read the mount table, so whether any module mount is visible to apps is unknown.");
    };
    // /adb/, not /adb/modules/: a module is free to bind from anywhere under
    // /data/adb and several do. Issue #14 is the case in point -- a YouTube
    // ReVanced module binds /data/adb/rvhc/<apk> over the installed APK, which
    // this check called clean while Duck reported it as a critical root mount.
    // Resolve the source properly (mountinfo field 4 is fs-relative) rather than
    // matching the raw field, so the same row also yields the owning module.
    let rows = crate::absorb::parse_mountinfo(&mi);
    let roots = crate::absorb::fs_roots(&rows);
    let hits: Vec<(&crate::absorb::MountRow, std::path::PathBuf)> = rows
        .iter()
        .filter_map(|r| crate::absorb::source_of(r, &roots).map(|src| (r, src)))
        .filter(|(_, src)| src.starts_with("/data/adb"))
        .collect();
    // A hook framework's bind is one absorb deliberately never takes over --
    // breaking a Zygisk/Xposed hook surfaces hours later during dexopt, not at
    // boot. Counting it as a failure would leave every LSPosed user staring at a
    // permanent FAIL they cannot act on, so it is reported as expected. It is
    // still SHOWN, because it is genuinely visible to apps.
    // A source outside /data/adb/modules has no module dir, so it can never be a
    // hook framework: it is reported as a leak, which is what it is.
    let (by_design, leaked): (Vec<_>, Vec<_>) = hits.iter().partition(|(_, src)| {
        crate::absorb::module_dir_of(src).is_some_and(|d| crate::absorb::is_hook_framework(&d))
    });
    let show = |v: &[&(&crate::absorb::MountRow, std::path::PathBuf)]| -> String {
        v.iter()
            .map(|(r, _)| r.target.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(", ")
    };
    if leaked.is_empty() {
        let note = if by_design.is_empty() {
            "0 module mounts in this namespace".to_string()
        } else {
            format!(
                "0 unexpected module mounts; {} left by design (hook framework): {}",
                by_design.len(),
                show(&by_design)
            )
        };
        let meaning = if by_design.is_empty() {
            "Nothing the Suite or your modules do shows up in the mount table.".to_string()
        } else {
            format!(
                "Nothing unexpected. {} hook-framework bind(s) remain on purpose — absorb never \
                 takes those over, because breaking a Zygisk/Xposed hook surfaces hours later \
                 during app install, not at boot.",
                by_design.len()
            )
        };
        pass("zero-mount posture", note).meaning(meaning)
    } else {
        // Name the owner. `module_dir_of` was already being called to decide the
        // by-design split and its answer was thrown away for the leaked case --
        // the one case where the reader has something to do with it.
        let owners: Vec<String> = {
            let mut v: Vec<String> = leaked
                .iter()
                .filter_map(|(_, src)| crate::absorb::module_dir_of(src))
                .filter_map(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
                .collect();
            v.sort();
            v.dedup();
            v
        };
        let owner = if owners.is_empty() {
            "a bind from outside /data/adb/modules".to_string()
        } else {
            owners.join(", ")
        };
        fail(
            "zero-mount posture",
            format!("{} module mount(s) visible: {}", leaked.len(), show(&leaked)),
            "any app can read /proc/self/mountinfo and see a module mounted over the ROM",
        )
        .meaning(format!(
            "{} mount(s) laid over the ROM are readable by any app in its own mount table. The \
             Suite adds none of its own — these come from {owner}.",
            leaked.len()
        ))
        .owner(owner)
        .action("absorb", "Absorb now", None)
    }
}

/// The engine must expose no /sys, /proc or module surface of its own.
fn check_surfaces() -> Check {
    let mut found = Vec::new();
    // Which probes actually RAN. Each was an `if let Ok(..)` with no else, so a
    // directory that could not be enumerated contributed nothing to `found` and
    // the check still reported "no entry named nomount in /sys/kernel,
    // /sys/module, /proc" — asserting three directories had been scanned when one
    // or more had not. This file's own header says a check that cannot run says
    // so; this was the check that did not.
    let mut unread: Vec<&str> = Vec::new();
    for dir in ["/sys/kernel", "/sys/module", "/proc"] {
        match fs::read_dir(dir) {
            Ok(rd) => {
                for e in rd.flatten() {
                    let n = e.file_name().to_string_lossy().to_lowercase();
                    if n.contains("nomount") {
                        found.push(format!("{dir}/{n}"));
                    }
                }
            }
            Err(_) => unread.push(dir),
        }
    }
    match fs::read_to_string("/proc/filesystems") {
        Ok(f) => {
            if f.to_lowercase().contains("nomount") {
                found.push("/proc/filesystems".into());
            }
        }
        Err(_) => unread.push("/proc/filesystems"),
    }
    // A hit is a hit however partial the scan was, so `found` still fails below.
    // Only an EMPTY result depends on having been able to look everywhere.
    if found.is_empty() && !unread.is_empty() {
        return unmeasured(
            "kernel surfaces",
            format!(
                "could not enumerate {} — nothing named nomount was found in the rest, but \
                 this check did NOT clear the surfaces it could not read",
                unread.join(", ")
            ),
        )
        .meaning(
            "Part of the kernel's public directory listing could not be read, so this is not a \
             clean result — only an incomplete one.",
        );
    }
    if found.is_empty() {
        // Say what was actually tested. This walks DIRECTORY ENTRY NAMES only,
        // so the old wording ("no nomount entry in /proc") read as though the
        // contents of /proc had been cleared -- while /proc/kallsyms carries 56
        // matching symbol names on a shipped build, because the symbol cloak is
        // deliberately off. That residual is real but app-unreachable: the live
        // policy gives proc_kallsyms:file allowed=0 to every app domain
        // (measured on OP15). An audit that overstates its own coverage is the
        // same class of defect as a green card over a failed pass.
        pass(
            "kernel surfaces",
            "no entry named nomount in /sys/kernel, /sys/module, /proc (names only; \
             /proc/kallsyms symbols are a separate, deliberately-uncloaked residual, \
             unreadable by app domains)"
                .into(),
        )
        .meaning("The engine has no directory entry anywhere an app can list that names it.")
    } else {
        fail(
            "kernel surfaces",
            found.join(", "),
            "a named surface identifies the engine outright, with no analysis needed",
        )
        .meaning(
            "The kernel exposes a directory entry with the engine's name in it. Anything that \
             lists that directory identifies your setup outright, with no analysis at all.",
        )
        .owner("the kernel build")
    }
}

/// readdir cookies must not carry the engine's magic.
fn check_dirent_cookie(parents: &[PathBuf]) -> Check {
    const NM_MAGIC: i64 = 0x6e6d; // "nm"
    let (mut scanned, mut hits) = (0usize, 0usize);
    for p in parents {
        let Some(entries) = getdents(p) else { continue };
        for e in entries {
            scanned += 1;
            if (e.d_off >> 48) == NM_MAGIC {
                hits += 1;
            }
        }
    }
    if scanned == 0 {
        // The two reasons a directory scan finds nothing are different answers.
        // With no rules live there is nothing to inject into and never was:
        // n/a. With rules live but no parent readable, the check that would have
        // run did not: unmeasured.
        return if parents.is_empty() {
            na("readdir cookie magic", "no injection rules are live, so no directory to read".into())
                .meaning("Nothing is being injected yet, so there are no listings to check.")
        } else {
            unmeasured(
                "readdir cookie magic",
                format!("{} injected directory(ies), none could be read", parents.len()),
            )
            .meaning("The injected directories could not be listed, so this was not tested.")
        };
    }
    if hits == 0 {
        pass("readdir cookie magic", format!("0 of {scanned} dirents carry the magic"))
            .meaning("Directory listings of injected folders look the same as the ROM's own.")
    } else {
        fail(
            "readdir cookie magic",
            format!("{hits} of {scanned} dirents have 0x6e6d in the top 16 bits of d_off"),
            "one getdents64 on an injected directory identifies the engine, no root needed",
        )
        .meaning(
            "Listing an injected folder returns entries carrying the engine's marker. One \
             ordinary directory read identifies your setup — this is the cheapest oracle there is.",
        )
        .owner("the kernel engine")
    }
}

/// An injected file's readdir d_ino must equal its stat st_ino.
fn check_dino_matches_stat(targets: &[PathBuf]) -> Check {
    // `eligible` is every injected file on a readable non-overlay parent, counted
    // up front. The old code `continue`d past a name absent from getdents or one
    // that no longer stats, then reported PASS over the remainder with no
    // denominator -- so a file the engine had d_dropped out of the listing (the
    // exact regression this checks for) simply vanished from the audit. Both of
    // those are now FAIL rows, and the evidence carries checked/eligible.
    let mut eligible = 0usize;
    let mut checked = 0usize;
    let mut bad = Vec::new();
    let mut by_parent: HashMap<PathBuf, Vec<&PathBuf>> = HashMap::new();
    for t in targets {
        if let Some(p) = t.parent() {
            by_parent.entry(p.to_path_buf()).or_default().push(t);
        }
    }
    for (parent, kids) in &by_parent {
        // Only meaningful off overlayfs: there, STOCK entries disagree too
        // (readdir reports the lower's ino), so a mismatch proves nothing.
        if fs_type(parent) == "overlay" {
            continue;
        }
        let Some(entries) = getdents(parent) else { continue };
        for k in kids {
            let Some(name) = k.file_name().and_then(|n| n.to_str()) else { continue };
            eligible += 1;
            let Some(e) = entries.iter().find(|e| e.name == name) else {
                bad.push(format!("{} absent from getdents", k.display()));
                continue;
            };
            let Some(st) = ino_of(k) else {
                bad.push(format!("{} no longer stats", k.display()));
                continue;
            };
            checked += 1;
            if e.d_ino != st {
                bad.push(format!("{} d_ino={} st_ino={}", k.display(), e.d_ino, st));
            }
        }
    }
    if eligible == 0 {
        return na(
            "readdir ino vs stat ino",
            "no injected file on a non-overlay filesystem to compare".into(),
        )
        .meaning(
            "This one only applies where the ROM is NOT overlayfs — on overlay, stock files \
             disagree the same way, so the comparison proves nothing. Your injected files are \
             all on overlay.",
        );
    }
    if bad.is_empty() {
        pass("readdir ino vs stat ino", format!("{checked}/{eligible} injected file(s) agree"))
            .meaning("Injected files report the same identity when listed as when inspected.")
    } else {
        fail(
            "readdir ino vs stat ino",
            format!("{} of {eligible} eligible failed ({checked} compared): {}", bad.len(), bad.join("; ")),
            "listing a directory and stat-ing its entries separates injected files from stock",
        )
        .meaning(
            "An injected file reports one identity when the folder is listed and a different one \
             when the file itself is inspected. Comparing the two picks the injected files out of \
             the stock ones.",
        )
        .owner("the kernel engine")
    }
}

/// Injected inodes must not occupy a band the stock population never uses.
fn check_inode_band(targets: &[PathBuf]) -> Check {
    const BUCKET: u64 = 1_000_000;
    let mut worst: Option<(String, u64, usize)> = None;
    let mut examined = 0usize;
    for parent in parents_of(targets) {
        let Ok(rd) = fs::read_dir(&parent) else { continue };
        let injected: Vec<&PathBuf> =
            targets.iter().filter(|t| t.parent() == Some(parent.as_path())).collect();
        if injected.len() < 4 {
            continue; // too few to form a visible band
        }
        let mut stock_buckets: HashMap<u64, usize> = HashMap::new();
        let mut ours_buckets: HashMap<u64, usize> = HashMap::new();
        for e in rd.flatten() {
            let p = e.path();
            let Some(i) = ino_of(&p) else { continue };
            let b = i / BUCKET;
            if injected.iter().any(|t| **t == p) {
                *ours_buckets.entry(b).or_default() += 1;
            } else {
                *stock_buckets.entry(b).or_default() += 1;
            }
        }
        // A directory that is entirely ours (a synthesized tree such as
        // <app>/lib/arm64) has NO stock population, so "a bucket with no stock
        // in it" is true by construction and says nothing. Measured live:
        // /product/priv-app/Mms/lib/arm64 is 25 of 25 injected. Judging it
        // produced a FAIL that no attacker could ever act on.
        if stock_buckets.is_empty() {
            continue;
        }
        examined += 1;
        for (b, n) in &ours_buckets {
            if !stock_buckets.contains_key(b) && worst.as_ref().is_none_or(|w| *n > w.2) {
                worst = Some((parent.to_string_lossy().into_owned(), *b, *n));
            }
        }
    }
    if examined == 0 {
        return na(
            "injected inode band",
            "no directory with both enough injections and a stock population to compare".into(),
        )
        .meaning(
            "Nothing to compare: this needs a folder holding at least four injected files \
             alongside the ROM's own, and none of yours is shaped that way.",
        )
        .reach(Reach::Effort);
    }
    match worst {
        None => pass(
            "injected inode band",
            format!("{examined} directory(ies): every injected inode shares a bucket with stock"),
        )
        .meaning("Injected files sit in the same numeric range as the ROM's own files.")
        .reach(Reach::Effort),
        Some((dir, b, n)) => fail(
            "injected inode band",
            format!("{dir}: {n} injected inode(s) alone in the {}M bucket, no stock there", b),
            "bucket every inode in a directory and the all-ours band names the injections",
        )
        .meaning(
            "Injected files carry identity numbers from a range the ROM never uses, so a \
             detector that groups a folder's files by that number gets one group that is \
             entirely yours. It has to be built for the purpose — this is not a one-syscall tell.",
        )
        .owner("the kernel engine")
        .reach(Reach::Effort),
    }
}

/// A synthesized directory on an overlay mount must not carry an inode from
/// outside the range overlayfs hands its own entries.
fn check_overlay_dir_ino(targets: &[PathBuf]) -> Check {
    let mut outliers = Vec::new();
    let mut examined = 0usize;
    for parent in parents_of(targets) {
        if fs_type(&parent) != "overlay" {
            continue;
        }
        let Ok(rd) = fs::read_dir(&parent) else { continue };
        let mut stock_max = 0u64;
        let mut dirs = Vec::new();
        for e in rd.flatten() {
            let p = e.path();
            if !p.is_dir() {
                continue;
            }
            let Some(i) = ino_of(&p) else { continue };
            let ours = targets.iter().any(|t| t.starts_with(&p) || *t == p);
            if ours {
                dirs.push((p, i));
            } else if i > stock_max {
                stock_max = i;
            }
        }
        if stock_max == 0 {
            continue;
        }
        examined += 1;
        for (p, i) in dirs {
            // Generous: only flag an order-of-magnitude departure, so ordinary
            // "next allocation" values never cry wolf.
            if i > stock_max.saturating_mul(8) {
                outliers.push(format!("{} ino={i} (stock max here {stock_max})", p.display()));
            }
        }
    }
    if examined == 0 {
        return na("overlay dir inode range", "no injected directory on an overlay mount".into())
            .meaning(
                "This one only applies to folders the Suite creates on an overlayfs ROM, and you \
                 have none.",
            )
            .reach(Reach::Effort);
    }
    if outliers.is_empty() {
        pass(
            "overlay dir inode range",
            format!("{examined} overlay dir(s): synthesized inodes sit inside the stock range"),
        )
        .meaning("Folders the Suite creates carry identity numbers the ROM could plausibly issue.")
        .reach(Reach::Effort)
    } else {
        fail(
            "overlay dir inode range",
            outliers.join("; "),
            "`find <mount> -type d -inum +N` returns exactly the synthesized directories",
        )
        .meaning(
            "Folders the Suite created carry identity numbers far outside anything the ROM \
             issues, so a single search filtered on that number returns exactly the created ones.",
        )
        .owner("the kernel engine")
        .reach(Reach::Effort)
    }
}

/// On erofs a single-block directory's size is a closed form over its entries,
/// so an injected or hidden name must be reflected in the parent's size.
fn check_erofs_dir_shape(targets: &[PathBuf]) -> Check {
    let (mut ok, mut bad) = (0usize, Vec::new());
    for parent in parents_of(targets) {
        if fs_type(&parent) != "erofs" {
            continue;
        }
        let Ok(md) = fs::metadata(&parent) else { continue };
        let size = md.len();
        if size == 0 || size >= 4096 {
            continue; // multi-block padding has no closed form
        }
        let Ok(rd) = fs::read_dir(&parent) else { continue };
        let (mut n, mut bytes) = (0u64, 0u64);
        for e in rd.flatten() {
            n += 1;
            bytes += e.file_name().as_encoded_bytes().len() as u64;
        }
        let model = 12 * (n + 2) + bytes + 3;
        if model == size {
            ok += 1;
        } else {
            bad.push(format!("{} size={size} model={model}", parent.display()));
        }
    }
    if ok == 0 && bad.is_empty() {
        return na(
            "erofs directory shape",
            "no single-block erofs parent among the injected paths".into(),
        )
        .meaning(
            "This one only applies to small folders on an erofs ROM, where the folder's size is a \
             fixed formula over its contents. None of yours is both.",
        )
        .reach(Reach::Effort);
    }
    if bad.is_empty() {
        pass("erofs directory shape", format!("{ok} erofs parent(s) match the dirent model"))
            .meaning(
                "Folders holding injected or hidden files still report the size their contents \
                 imply, so adding or hiding a name left no arithmetic trace.",
            )
            .reach(Reach::Effort)
    } else {
        fail(
            "erofs directory shape",
            bad.join("; "),
            "st_size stops matching the listing, so a stat plus a getdents64 shows a name was \
             added or hidden",
        )
        .meaning(
            "A folder's reported size no longer matches what its contents imply, which says a \
             name was added or hidden. Reading it takes a detector that models how this \
             filesystem packs folders.",
        )
        .owner("the kernel engine")
        .reach(Reach::Effort)
    }
}

/// An injected file must not be mapped as deleted.
///
/// Adding a rule d_drops the cached dentry for that name, which is how the next
/// lookup gets routed through the injection. A process that already had the file
/// mapped keeps that now-unhashed dentry, and the kernel renders every such
/// mapping with a " (deleted)" suffix -- so `/proc/<pid>/maps` names exactly which
/// files are injected. Measured on OP15: of 72 overlay APKs mapped by
/// system_server, the only two flagged deleted were the two we inject, and an app
/// serving an injected APK sees the same thing in its OWN maps, which needs no
/// privilege at all.
fn check_maps_not_deleted(targets: &[PathBuf]) -> Check {
    if targets.is_empty() {
        return na("injected files in maps", "no live rules".into())
            .meaning("Nothing is being injected yet, so no process can have one mapped.");
    }
    let want: HashSet<&Path> = targets.iter().map(PathBuf::as_path).collect();
    let Ok(rd) = fs::read_dir("/proc") else {
        return unmeasured("injected files in maps", "cannot read /proc".into())
            .meaning("The process list could not be read, so this was not tested.");
    };
    let mut hits: Vec<String> = Vec::new();
    let mut scanned = 0u32;
    for e in rd.filter_map(Result::ok) {
        let pid = e.file_name().to_string_lossy().into_owned();
        if !pid.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let Ok(maps) = fs::read_to_string(format!("/proc/{pid}/maps")) else { continue };
        scanned += 1;
        for line in maps.lines() {
            let Some(rest) = line.strip_suffix(" (deleted)") else { continue };
            let Some(path) = rest.split_whitespace().nth(5) else { continue };
            if want.contains(Path::new(path)) && !hits.iter().any(|h| h.starts_with(path)) {
                hits.push(format!("{path} (pid {pid})"));
            }
        }
    }
    if hits.is_empty() {
        return pass(
            "injected files in maps",
            format!("{scanned} process(es): no injected file mapped as deleted"),
        )
        .meaning(
            "No running app has an injected file marked deleted in its own memory map — which is \
             the version of this that an app can read about itself, with no permission at all.",
        );
    }
    let shown = hits.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    // A rule change over an APK PM had already parsed unhashes the dentry every
    // process mapped it through. The rule is right and the cache is dropped; the
    // mappings are what a reboot replaces.
    let pending = crate::pmcache::pending();
    if !pending.is_empty() && hits.iter().all(|h| pending.iter().any(|p| h.starts_with(&*p.to_string_lossy()))) {
        return reboot(
            "injected files in maps",
            format!("{} injected file(s) mapped as deleted: {shown} -- pending reboot after a rule change", hits.len()),
            "still readable until the reboot: any app can see which of its files are injected",
        )
        .meaning(format!(
            "You changed a rule over {} file(s) that were already open. The rule is right; the \
             processes still holding the old copy show it as deleted until they restart. A reboot \
             finishes this — nothing else is needed.",
            hits.len()
        ))
        .owner("a rule change made since boot")
        .action("reboot", "Reboot to finish", None);
    }
    {
        fail(
            "injected files in maps",
            format!("{} injected file(s) mapped as deleted: {shown}", hits.len()),
            "any app can read its own /proc/self/maps and see which of its files are injected",
        )
        .meaning(format!(
            "{} injected file(s) show as deleted in a running process's own memory map. An app can \
             read that about itself with no permission, and it names exactly which of its files \
             were swapped.",
            hits.len()
        ))
        .owner("the kernel engine")
        .action("reboot", "Reboot", None)
    }
}

/// A hidden app must still be able to open every file the PackageManager gave it.
///
/// Per-UID hiding serves a blocked reader the stock filesystem, which for an ADDED
/// name means ENOENT. That is right for a module file nothing else mentions -- and
/// wrong for anything in a PM-registered codePath, because the PackageManager
/// scanned the directory as system_server (never blocked), registered the package,
/// and now hands its whole codePath (the APK AND its nativeLibraryDir .so files) to
/// every app that asks. The hidden app is then holding a path the system says
/// exists and open() denies, which no device produces on its own.
///
/// Measured consequence, OP15 2026-08-23: IBM Trusteer (La Banque Postale) walks
/// the package list at startup, calls getResourcesForApplication() on each entry,
/// and SIGSEGVs on the IOException from 139 unopenable /product/overlay APKs.
///
/// The probe forks, drops to a blocked appid and opens each PM-published rule
/// target. It changes UID only -- the SELinux domain stays ours -- which is exactly
/// what the engine keys on (nomount_is_uid_blocked reads current_uid()), so it
/// measures the hiding decision and NOT the app's own domain permissions.
fn check_pm_apks_open_when_hidden(targets: &[PathBuf]) -> Check {
    const NAME: &str = "PM-published files open for a hidden app";
    let apks: Vec<&PathBuf> = targets.iter().filter(|t| crate::pmcache::is_pm_published(t)).collect();
    if apks.is_empty() {
        return na(NAME, "no PM-published rules live".into())
            .meaning("No module here replaces an app the system has registered, so there is nothing for a hidden app to be denied.");
    }
    let blocked = Nm::new().uid_list_live().unwrap_or_default();
    let Some(&appid) = blocked.first() else {
        // n/a, not amber: "you have not hidden any apps yet" is a statement about
        // the user's configuration, not a measurement that failed. This is the
        // single most common amber on a fresh install.
        return na(NAME, format!("{} PM-published file rule(s), but no app is hidden", apks.len()))
            .meaning("You have not hidden any apps yet, so there is nothing to test here. Hide one and this check starts running.");
    };
    // Only paths root can open are worth asking about: one the module itself
    // cannot serve is a different bug, and this check must not claim it.
    let readable: Vec<&&PathBuf> = apks.iter().filter(|p| fs::File::open(p).is_ok()).collect();
    if readable.is_empty() {
        return unmeasured(NAME, format!("{} PM-published file rule(s), none readable as root", apks.len()))
            .meaning("None of the published files could be opened even as root, so the question this check asks could not be put.");
    }
    // The size WE are served, to compare the hidden child against. Opening is only
    // half the question: a rule that shadows a stock APK answers a blocked reader
    // from the stock file, so open() succeeds and the check used to pass -- while
    // the bytes differ from the ones the PackageManager parsed and published a
    // version and signature for. Measured on OP15 against engine v16:
    // /product/priv-app/Contacts/Contacts.apk served 74641847 bytes to us and
    // 64249089 to a hidden uid, with PM advertising the former as 16.80.0.
    let ours: Vec<u64> =
        readable.iter().map(|p| fs::metadata(p.as_path()).map(|m| m.len()).unwrap_or(0)).collect();

    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return unmeasured(NAME, "pipe() failed".into())
            .meaning("The probe could not be set up, so this was not tested.");
    }
    let (rd, wr) = (fds[0], fds[1]);
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe { libc::close(rd); libc::close(wr) };
        return unmeasured(NAME, "fork() failed".into())
            .meaning("The probe could not be started, so this was not tested.");
    }
    if pid == 0 {
        unsafe { libc::close(rd) };
        let mut denied = 0u32;
        // setgroups FIRST, then setgid, then setuid.
        //
        // Dropping the uid and gid alone leaves root's SUPPLEMENTARY groups on the
        // child -- so the probe asks "can uid N open this" while still carrying
        // group memberships the real app does not have. On a target whose group
        // bits grant more than its other bits, that answers "opened" where the app
        // is denied, i.e. this check reports PASS on a path an app cannot actually
        // read. Clearing them is only possible while still privileged, hence
        // first; setgid before setuid for the same reason.
        let dropped = unsafe {
            libc::setgroups(0, std::ptr::null()) == 0
                && libc::setgid(appid) == 0
                && libc::setuid(appid) == 0
        };
        let mut mismatched = 0u32;
        if dropped {
            for (p, &our_len) in readable.iter().zip(ours.iter()) {
                if fs::File::open(p.as_path()).is_err() {
                    denied += 1;
                } else if fs::metadata(p.as_path()).map(|m| m.len()).unwrap_or(our_len) != our_len {
                    mismatched += 1;
                }
            }
        } else {
            denied = u32::MAX;
        }
        let mut buf = [0u8; 8];
        buf[..4].copy_from_slice(&denied.to_ne_bytes());
        buf[4..].copy_from_slice(&mismatched.to_ne_bytes());
        unsafe { libc::write(wr, buf.as_ptr() as *const libc::c_void, 8) };
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(wr) };
    let mut buf = [0u8; 8];
    let got = unsafe { libc::read(rd, buf.as_mut_ptr() as *mut libc::c_void, 8) };
    unsafe { libc::close(rd) };
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if got != 8 {
        return unmeasured(NAME, "probe child said nothing".into())
            .meaning("The probe exited without answering, so this was not tested.");
    }
    let denied = u32::from_ne_bytes(buf[..4].try_into().unwrap_or_default());
    let mismatched = u32::from_ne_bytes(buf[4..].try_into().unwrap_or_default());
    if denied == u32::MAX {
        return unmeasured(NAME, format!("could not drop to uid {appid}"))
            .meaning("The probe could not take on the hidden app's identity, so this was not tested.");
    }
    if denied == 0 && mismatched == 0 {
        return pass(
            NAME,
            format!(
                "uid {appid} (hidden) opened all {} PM-published rule target(s), same bytes we serve",
                readable.len()
            ),
        )
        .meaning(
            "A hidden app can still open every file Android told it about, and gets the same \
             bytes everyone else does. This is the check that keeps hiding from crashing apps \
             that walk the package list.",
        );
    }
    if denied == 0 {
        return fail(
            NAME,
            format!(
                "uid {appid} (hidden) opened all {} PM-published rule target(s) but {mismatched} \
                 differed in size from the copy we serve",
                readable.len()
            ),
            "those rules shadow a stock file, so the blocked reader is answered from the stock \
             file -- while the PackageManager parsed OUR copy and publishes its version and \
             signature for that path, a disagreement the app can measure. Engine >= 17 keeps \
             NM_FLAG_PUBLIC on a shadowed file; below that the kernel strips it",
        );
    }
    fail(
        NAME,
        format!(
            "uid {appid} (hidden) could not open {denied} of {} PM-published rule target(s)\
             {}",
            readable.len(),
            if mismatched > 0 { format!(", and {mismatched} more differed in size") } else { String::new() }
        ),
        "the PackageManager names those paths to the app while open() answers ENOENT -- \
         an inconsistency no stock device has, and one that crashes RASP code that walks \
         the package list (engine < 15 cannot express the opt-out; see NM_FLAG_PUBLIC)",
    )
}

/// A tmpfs mounted inside a ROM partition is never stock.
///
/// Emptying a ROM directory by mounting an empty tmpfs over it is a common module
/// trick -- the ReVanced installer does exactly that to `/product/app/<App>` so its
/// /data/app copy wins. Every check we had keys on the mount's SOURCE being under
/// /data/adb, and a tmpfs has no such source, so this was invisible to absorb,
/// doctor, health and this audit alike. Measured on OP15: the only tmpfs anywhere
/// inside a ROM partition was the module's; stock keeps them at /dev, /mnt, /apex,
/// /linkerconfig and /tmp. Visible to any app in its own mountinfo.
fn check_no_rom_tmpfs() -> Check {
    let Ok(mi) = fs::read_to_string("/proc/self/mountinfo") else {
        return unmeasured("tmpfs over the ROM", "cannot read /proc/self/mountinfo".into())
            .meaning("Could not read the mount table, so whether a module emptied a ROM folder this way is unknown.");
    };
    let roots = ["/system/", "/product/", "/vendor/", "/system_ext/", "/odm/", "/oem/", "/my_"];
    let mut hits: Vec<String> = Vec::new();
    for line in mi.lines() {
        let Some((pre, post)) = line.split_once(" - ") else { continue };
        if post.split_whitespace().next() != Some("tmpfs") {
            continue;
        }
        let Some(target) = pre.split_whitespace().nth(4) else { continue };
        if roots.iter().any(|r| target.starts_with(r)) {
            hits.push(target.to_string());
        }
    }
    if hits.is_empty() {
        pass("tmpfs over the ROM", "no tmpfs mounted inside a ROM partition".into())
            .meaning("No ROM folder has been emptied by mounting scratch space over it.")
    } else {
        fail(
            "tmpfs over the ROM",
            format!("{} ROM path(s) emptied by a tmpfs: {}", hits.len(), hits.join(", ")),
            "stock never mounts tmpfs inside /system, /product or /vendor -- any app can read it from its own mountinfo",
        )
        .meaning(format!(
            "{} ROM folder(s) have been emptied by mounting scratch space over them. No stock \
             device does that anywhere under /system, /product or /vendor, and any app can see \
             it in its own mount table. Some installers (ReVanced, several debloaters) do this \
             themselves — the Suite does not.",
            hits.len()
        ))
        .owner("another module's installer")
        .action("absorb", "Absorb now", None)
    }
}

/// A bind or image mounted over the ROM from somewhere other than /data/adb.
///
/// `check_zero_mount` flags a source under /data/adb; `check_no_rom_tmpfs` flags a
/// tmpfs. Neither sees a bind over the ROM sourced from /data/local/tmp, /cache or
/// a loop image -- yet those are every bit as visible in an app's mountinfo. Flag
/// any row whose MOUNTPOINT is inside a ROM partition and whose mount root (field
/// 4) is not "/" (a bind of a subtree, never how a whole partition is mounted) OR
/// whose backing device is the /data device (content served off userdata over the
/// read-only ROM). Stock OEM mounts inside a ROM partition (vfat firmware, ext4
/// dsp, the OEM's overlayfs) have root "/" on their own block device, so they do
/// not match -- and a plain tmpfs (root "/", its own dev) is left to the check above.
fn check_no_foreign_rom_mount() -> Check {
    let Ok(mi) = fs::read_to_string("/proc/self/mountinfo") else {
        return unmeasured("foreign mount over the ROM", "cannot read /proc/self/mountinfo".into())
            .meaning("Could not read the mount table, so whether anything foreign is mounted over the ROM is unknown.");
    };
    let roots = ["/system/", "/product/", "/vendor/", "/system_ext/", "/odm/", "/oem/", "/my_"];
    let rows = crate::absorb::parse_mountinfo(&mi);
    // maj:min of /data, so a mount served off userdata is recognised by device
    // rather than by the source path (which mountinfo does not carry usefully here).
    let data_dev = rows.iter().find(|r| r.target == Path::new("/data")).map(|r| r.dev.clone());
    let mut hits: Vec<String> = Vec::new();
    for r in &rows {
        let t = r.target.to_string_lossy();
        if !roots.iter().any(|root| t.starts_with(root)) {
            continue;
        }
        let subtree_bind = r.root != "/";
        let off_userdata = data_dev.as_deref() == Some(r.dev.as_str());
        if subtree_bind || off_userdata {
            hits.push(format!("{} (root={}, dev={})", t, r.root, r.dev));
        }
    }
    if hits.is_empty() {
        pass("foreign mount over the ROM", "no non-/data/adb bind or image mounted over a ROM partition".into())
            .meaning("Nothing outside the module system is mounted over a read-only ROM partition.")
    } else {
        fail(
            "foreign mount over the ROM",
            format!("{} foreign mount(s) over the ROM: {}", hits.len(), hits.join(", ")),
            "a bind from /data/local/tmp or /cache, or an image over the ROM, is visible in any app's mountinfo just like a module mount",
        )
        .meaning(format!(
            "{} mount(s) over the ROM are served from somewhere other than the module \
             system — scratch space, cache, or a disk image. An app reads those out of its own \
             mount table exactly like a module mount.",
            hits.len()
        ))
        .owner("a mount made outside /data/adb")
    }
}

/// The three checks that read the mount table.
///
/// Split out so `nomount posture` can run exactly these and nothing else. Before
/// this existed the WebUI's posture shield answered the same question with its
/// own `awk '$4 ~ "/adb/modules/"'`, which is the pattern this file's own
/// regression test exists to reject: it cannot see a bind out of
/// `/data/adb/rvhc` (issue #14), and it DOES see a hook framework's by-design
/// bind, which the audit deliberately does not count. Measured on an OP15 with
/// LSPosed installed: the shield rendered a permanent amber "another module is
/// mounting" over the one mount the audit reports as expected. A front page
/// contradicting the audit two taps away teaches the reader to trust neither.
pub fn mount_checks() -> Vec<Check> {
    vec![check_zero_mount(), check_no_rom_tmpfs(), check_no_foreign_rom_mount()]
}

fn all_checks() -> (Vec<Check>, usize, usize) {
    let targets = live_targets();
    let parents = parents_of(&targets);
    let checks = vec![
        check_zero_mount(),
        check_surfaces(),
        check_dirent_cookie(&parents),
        check_dino_matches_stat(&targets),
        check_inode_band(&targets),
        check_overlay_dir_ino(&targets),
        check_erofs_dir_shape(&targets),
        check_maps_not_deleted(&targets),
        check_pm_apks_open_when_hidden(&targets),
        check_no_rom_tmpfs(),
        check_no_foreign_rom_mount(),
    ];
    (checks, targets.len(), parents.len())
}

/// Tallies, with `accepted` broken out of `failed` rather than subtracted from it.
pub struct Tally {
    pub passed: usize,
    pub failed: usize,
    pub reboot: usize,
    pub na: usize,
    pub unmeasured: usize,
    /// Findings that are still FAIL/REBOOT and are covered by an acceptance.
    /// Counted IN `failed` as well -- an acceptance never reduces the failure
    /// count, it only adds the fact that someone looked at it.
    pub accepted: usize,
}

impl Tally {
    fn of(checks: &[Check], acc: &[crate::accept::Acceptance]) -> Tally {
        let mut t =
            Tally { passed: 0, failed: 0, reboot: 0, na: 0, unmeasured: 0, accepted: 0 };
        for c in checks {
            match c.verdict {
                Verdict::Pass => t.passed += 1,
                Verdict::Fail => t.failed += 1,
                Verdict::Reboot => t.reboot += 1,
                Verdict::NotApplicable => t.na += 1,
                Verdict::Unmeasured => t.unmeasured += 1,
            }
            if matches!(c.verdict, Verdict::Fail | Verdict::Reboot)
                && crate::accept::covering(acc, c.id, &c.fingerprint()).is_some()
            {
                t.accepted += 1;
            }
        }
        t
    }
    /// Findings that are failing AND not accepted -- the number the chip should
    /// go red on.
    pub fn open_failures(&self) -> usize {
        (self.failed + self.reboot).saturating_sub(self.accepted)
    }
}

/// One check as JSON. Shared by `audit --json` and `posture --json` so the two
/// cannot describe the same measurement differently.
pub fn check_json(c: &Check, acc: &[crate::accept::Acceptance]) -> crate::json::J {
    use crate::json::J;
    let fp = c.fingerprint();
    let covering = crate::accept::covering(acc, c.id, &fp);
    let lapsed = if covering.is_none() { crate::accept::stale(acc, c.id, &fp) } else { None };
    J::Obj(vec![
        ("id", J::s(c.id)),
        ("name", J::s(c.name)),
        ("verdict", J::s(c.verdict_slug())),
        ("evidence", J::s(&c.evidence)),
        ("meaning", J::s(&c.meaning)),
        ("oracle", J::os(c.oracle)),
        ("reach", J::s(c.reach.slug())),
        ("reach_label", J::s(c.reach.label())),
        ("owner", J::os(c.owner.clone())),
        ("fingerprint", J::s(&fp)),
        (
            "action",
            match &c.action {
                Some(a) => J::Obj(vec![
                    ("id", J::s(a.id)),
                    ("label", J::s(a.label)),
                    ("arg", J::os(a.arg.clone())),
                ]),
                None => J::Null,
            },
        ),
        ("accepted", J::Bool(covering.is_some())),
        ("accepted_reason", J::os(covering.map(|a| a.reason.clone()))),
        ("accepted_at", J::Num(covering.map(|a| a.when as i64).unwrap_or(0))),
        // An acceptance whose evidence has since moved. The single most useful
        // line the report can print about a finding that came back: "you accepted
        // this when it said something else".
        ("acceptance_lapsed", J::Bool(lapsed.is_some())),
        ("acceptance_lapsed_reason", J::os(lapsed.map(|a| a.reason.clone()))),
    ])
}

fn tally_json(t: &Tally) -> crate::json::J {
    use crate::json::J;
    J::Obj(vec![
        ("passed", J::Num(t.passed as i64)),
        ("failed", J::Num(t.failed as i64)),
        ("reboot", J::Num(t.reboot as i64)),
        ("not_applicable", J::Num(t.na as i64)),
        ("unmeasured", J::Num(t.unmeasured as i64)),
        ("accepted", J::Num(t.accepted as i64)),
        ("open_failures", J::Num(t.open_failures() as i64)),
    ])
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// `nomount posture [--json]` — only the mount-table questions.
///
/// Exists so one implementation answers "is anything mounted that an app can
/// see" for the audit, the posture shield and anything else that asks.
pub fn run_posture(json: bool) -> Result<()> {
    let checks = mount_checks();
    let acc = crate::accept::load();
    let t = Tally::of(&checks, &acc);
    if json {
        use crate::json::J;
        let doc = J::Obj(vec![
            ("kind", J::s("posture")),
            ("ts", J::Num(now_secs())),
            ("summary", tally_json(&t)),
            ("checks", J::Arr(checks.iter().map(|c| check_json(c, &acc)).collect())),
        ]);
        println!("{}", doc.render());
    } else {
        for c in &checks {
            println!("[{}] {}\n       {}", c.tag(), c.name, c.evidence);
        }
        println!(
            "\nsummary: {} passed, {} failed, {} not applicable, {} unmeasured",
            t.passed, t.failed, t.na, t.unmeasured
        );
    }
    if t.open_failures() > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// Where the boot pass caches the last audit, so the WebUI can paint a verdict on
/// open instead of a dash. `service.sh` writes it at boot_completed and the page
/// shows it with an age; pressing the button refreshes it.
pub const CACHE: &str = "/data/adb/nomount/audit.json";

pub fn run_audit(json: bool, write: bool) -> Result<()> {
    let (mut checks, rules, dirs) = all_checks();
    let acc = crate::accept::load();

    // Worst first, and within a verdict the cheapest oracle first. Every FAIL
    // used to print in source order and read as equally fatal: `readdir cookie
    // magic` is one getdents64 from any app, `erofs directory shape` needs a
    // caller that replays erofs block packing. A reader fixing one thing should
    // be told which one.
    //
    // An ACCEPTED failure sorts with the pass block: the user has already dealt
    // with it, so it must not sit at the top pushing live findings down.
    let rank = |c: &Check| -> u8 {
        let accepted = crate::accept::covering(&acc, c.id, &c.fingerprint()).is_some();
        match c.verdict {
            Verdict::Fail if !accepted => 0,
            Verdict::Reboot if !accepted => 1,
            Verdict::Unmeasured => 2,
            Verdict::Fail | Verdict::Reboot => 3, // accepted
            Verdict::Pass => 4,
            Verdict::NotApplicable => 5,
        }
    };
    checks.sort_by(|a, b| rank(a).cmp(&rank(b)).then(a.reach.rank().cmp(&b.reach.rank())));

    let t = Tally::of(&checks, &acc);

    if json {
        use crate::json::J;
        let doc = J::Obj(vec![
            ("kind", J::s("audit")),
            ("ts", J::Num(now_secs())),
            ("suite", J::s(env!("CARGO_PKG_VERSION"))),
            ("rules", J::Num(rules as i64)),
            ("directories", J::Num(dirs as i64)),
            ("summary", tally_json(&t)),
            ("checks", J::Arr(checks.iter().map(|c| check_json(c, &acc)).collect())),
        ]);
        let text = doc.render();
        println!("{text}");
        if write {
            // Best-effort: a cache that could not be written must never fail the
            // audit itself. The consumer treats a missing or stale file as "no
            // cached verdict", which is what it is.
            let _ = fs::write(CACHE, &text);
            let _ = fs::set_permissions(
                CACHE,
                std::os::unix::fs::PermissionsExt::from_mode(0o600),
            );
        }
    } else {
        println!("nomount audit: {rules} live rule(s) across {dirs} directory(ies)\n");
        for c in &checks {
            let fp = c.fingerprint();
            let covering = crate::accept::covering(&acc, c.id, &fp);
            let tag = if covering.is_some() && matches!(c.verdict, Verdict::Fail | Verdict::Reboot)
            {
                // The verdict itself is untouched -- the word FAIL is still
                // printed. Only "and you accepted it" is added.
                "FAIL/ACCEPTED"
            } else {
                c.tag()
            };
            println!("[{tag}] {} ({})", c.name, c.reach.label());
            if !c.meaning.is_empty() {
                println!("       {}", c.meaning);
            }
            println!("       measured: {}", c.evidence);
            if let Some(o) = c.owner.as_deref() {
                println!("       from: {o}");
            }
            if let Some(o) = c.oracle {
                println!("       oracle: {o}");
            }
            if let Some(a) = covering {
                println!("       accepted: {}", a.reason);
            } else if let Some(a) = crate::accept::stale(&acc, c.id, &fp) {
                println!(
                    "       note: you accepted this once (\"{}\") but the evidence has changed \
                     since, so the acceptance no longer applies",
                    a.reason
                );
            }
        }
        println!(
            "\nsummary: {} passed, {} failed, {} pending reboot, {} not applicable, {} unmeasured",
            t.passed, t.failed, t.reboot, t.na, t.unmeasured
        );
        if t.accepted > 0 {
            println!("         {} of the failures are accepted (still failing, still shown)", t.accepted);
        }
        if t.reboot > 0 {
            println!("note: a pending-reboot check is still detectable until you reboot.");
        }
        if t.unmeasured > 0 {
            println!("note: an unmeasured check was NOT verified — it is not a pass.");
        }
        if t.na > 0 {
            println!(
                "note: a not-applicable check had nothing to test on this device — that is not a \
                 warning, and not a pass either."
            );
        }
    }

    // Exit non-zero on OPEN failures only. An accepted one has been dealt with;
    // failing the exit status on it would keep every wrapper script red forever
    // and is the scripting equivalent of the permanent chip this change removes.
    if t.open_failures() > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// `nomount accept` — record, list or drop an acceptance.
pub fn run_accept(check: Option<String>, reason: Option<String>, remove: bool, list: bool) -> Result<()> {
    let acc = crate::accept::load();
    if list || check.is_none() {
        if acc.is_empty() {
            println!("no accepted findings");
            return Ok(());
        }
        for a in &acc {
            println!("{}\t{}\t{}", a.check, a.fingerprint, a.reason);
        }
        return Ok(());
    }
    let id = check.unwrap();
    if remove {
        if crate::accept::remove(&id)? {
            println!("no longer accepting: {id}");
        } else {
            println!("nothing accepted for: {id}");
        }
        return Ok(());
    }
    // Fingerprint the CURRENT evidence, so the acceptance is bound to what the
    // user is looking at right now. Accepting a check whose id does not exist,
    // or which is not currently failing, is refused: an acceptance for a finding
    // that was never measured is a mute, and this is deliberately not a mute.
    let (checks, _, _) = all_checks();
    let Some(c) = checks.iter().find(|c| c.id == id) else {
        anyhow::bail!(
            "unknown check id: {id}\nrun `nomount audit --json` and use the \"id\" field of the finding"
        );
    };
    if !matches!(c.verdict, Verdict::Fail | Verdict::Reboot) {
        anyhow::bail!(
            "{id} is not currently failing (it is {}), so there is nothing to accept",
            c.verdict_slug()
        );
    }
    let reason = reason.unwrap_or_default();
    crate::accept::add(&id, &c.fingerprint(), &reason)?;
    println!("accepted {id}: {reason}");
    println!("this does NOT mark it clean — it stays a failure, shown in grey, and comes back at");
    println!("full severity if the evidence changes.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(id: &'static str, v: Verdict, ev: &str) -> Check {
        chk(id, id, v, ev.to_string())
    }

    /// The change this whole split exists for: a device where every check either
    /// passed or had nothing to test must not render as a warning.
    #[test]
    fn not_applicable_is_neither_a_pass_nor_a_warning() {
        let checks = vec![
            c("zero-mount", Verdict::Pass, "clean"),
            c("dino-vs-stat", Verdict::NotApplicable, "all on overlay"),
            c("pm-published-open", Verdict::NotApplicable, "no app is hidden"),
        ];
        let t = Tally::of(&checks, &[]);
        assert_eq!(t.passed, 1, "an n/a must never be counted as a pass");
        assert_eq!(t.na, 2);
        assert_eq!(t.unmeasured, 0);
        assert_eq!(t.open_failures(), 0, "nothing here is a failure");
    }

    /// ...while a check that COULD have run and did not stays amber. This is the
    /// half of the old `Skip` that the honesty rule is actually about.
    #[test]
    fn unmeasured_stays_distinct_from_both() {
        let checks = vec![c("zero-mount", Verdict::Unmeasured, "cannot read mountinfo")];
        let t = Tally::of(&checks, &[]);
        assert_eq!((t.passed, t.na, t.unmeasured), (0, 0, 1));
    }

    /// An acceptance never reduces the failure count -- it only records that
    /// someone looked. `failed` stays 1; only `open_failures` moves.
    #[test]
    fn an_acceptance_never_turns_a_failure_into_a_pass() {
        let checks = vec![c("rom-tmpfs", Verdict::Fail, "one tmpfs")];
        let fp = checks[0].fingerprint();
        let acc = vec![crate::accept::Acceptance {
            check: "rom-tmpfs".into(),
            fingerprint: fp,
            when: 1,
            reason: "ReVanced, on purpose".into(),
        }];
        let t = Tally::of(&checks, &acc);
        assert_eq!(t.passed, 0);
        assert_eq!(t.failed, 1, "still a failure, still counted as one");
        assert_eq!(t.accepted, 1);
        assert_eq!(t.open_failures(), 0, "but not one the user still has to act on");
    }

    /// The safety property, at the tally level: accepting one measured state does
    /// not accept the next one.
    #[test]
    fn an_acceptance_lapses_when_the_evidence_moves() {
        let checks = vec![c("rom-tmpfs", Verdict::Fail, "TWO tmpfs now")];
        let acc = vec![crate::accept::Acceptance {
            check: "rom-tmpfs".into(),
            fingerprint: "stale-fingerprint".into(),
            when: 1,
            reason: "was one tmpfs".into(),
        }];
        let t = Tally::of(&checks, &acc);
        assert_eq!(t.accepted, 0);
        assert_eq!(t.open_failures(), 1, "the finding is back at full severity");
    }

    /// Reachability orders the report: one syscall from any app outranks
    /// something that needs a purpose-built detector.
    #[test]
    fn reach_ranks_the_cheapest_oracle_first() {
        assert!(Reach::AnyApp.rank() < Reach::Effort.rank());
        assert!(Reach::Effort.rank() < Reach::RootOnly.rank());
    }

    /// Every check name must map to a real id: the fallback is what an
    /// acceptance would be keyed on, and two checks sharing "unknown-check" would
    /// let one acceptance silence the other.
    #[test]
    fn every_shipped_check_name_has_its_own_id() {
        let (checks, _, _) = (
            vec![
                "zero-mount posture",
                "kernel surfaces",
                "readdir cookie magic",
                "readdir ino vs stat ino",
                "injected inode band",
                "overlay dir inode range",
                "erofs directory shape",
                "injected files in maps",
                "PM-published files open for a hidden app",
                "tmpfs over the ROM",
                "foreign mount over the ROM",
            ],
            0,
            0,
        );
        let mut ids: Vec<&str> = checks.iter().map(|n| id_of(n)).collect();
        assert!(!ids.contains(&"unknown-check"), "a check name lost its id: {ids:?}");
        ids.sort_unstable();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n, "two checks share an id");
    }

    /// Issue #14: a ReVanced module binds its APK from /data/adb/rvhc, not from
    /// /data/adb/modules, over the installed app. The old filter keyed on
    /// "/adb/modules/" so this row was invisible and the check reported clean
    /// while Duck flagged the very same line as a critical root mount.
    #[test]
    fn a_bind_from_outside_modules_is_still_a_module_mount() {
        let mi = "\
25 2 254:81 / /data rw,nosuid,nodev,noatime - f2fs /dev/block/dm-81 rw
30311 2105 254:81 /adb/rvhc/youtube-morphe-jhc-arm64.apk /data/app/~~j9==/com.google.android.youtube-Zv==/base.apk rw,nosuid,nodev,noatime - f2fs /dev/block/dm-81 rw
";
        let rows = crate::absorb::parse_mountinfo(mi);
        let roots = crate::absorb::fs_roots(&rows);
        let srcs: Vec<_> = rows
            .iter()
            .filter_map(|r| crate::absorb::source_of(r, &roots))
            .filter(|s| s.starts_with("/data/adb"))
            .collect();
        assert_eq!(srcs.len(), 1, "the rvhc bind must resolve under /data/adb");
        assert_eq!(srcs[0], Path::new("/data/adb/rvhc/youtube-morphe-jhc-arm64.apk"));
        // No module dir, so it can never be excused as a hook framework.
        assert!(crate::absorb::module_dir_of(&srcs[0]).is_none());
    }

    /// The by-design exemption still has to work for a real module source.
    #[test]
    fn a_bind_from_a_module_dir_still_names_its_module() {
        let mi = "\
25 2 254:81 / /data rw - f2fs /dev/block/dm-81 rw
900 25 254:81 /adb/modules/zygisk_lsposed/bin/dex2oat /apex/com.android.art/bin/dex2oat64 rw - f2fs /dev/block/dm-81 rw
";
        let rows = crate::absorb::parse_mountinfo(mi);
        let roots = crate::absorb::fs_roots(&rows);
        let src = rows
            .iter()
            .filter_map(|r| crate::absorb::source_of(r, &roots))
            .find(|s| s.starts_with("/data/adb"))
            .expect("resolves");
        assert_eq!(
            crate::absorb::module_dir_of(&src).as_deref(),
            Some(Path::new("/data/adb/modules/zygisk_lsposed"))
        );
    }
}
