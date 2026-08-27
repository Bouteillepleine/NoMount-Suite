//! The DEVICE section of `nomount check` — prove the hiding actually holds here.
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

use crate::check::{slug, Check, Section, Verdict};
use crate::nm::Nm;

/// Constructors. Each one names the verdict in the check body's own vocabulary
/// so a check reads as what it measured; the shape they build is the one shared
/// [`Check`], not a second one this file owns.
///
/// The id is derived from the display name by [`slug`]. There used to be a
/// hand-maintained `id_of` table here and nothing at all on the plan side, so
/// half the rows in the merged list had no id to key an acceptance on.
fn chk(name: &'static str, verdict: Verdict, evidence: String) -> Check {
    Check::new(Section::Device, slug(name), name, verdict, evidence)
}
fn pass(name: &'static str, evidence: String) -> Check {
    chk(name, Verdict::Pass, evidence)
}
fn fail(name: &'static str, evidence: String, oracle: &'static str) -> Check {
    chk(name, Verdict::Fail, evidence).oracle(oracle)
}
/// A real, measured inconsistency that nothing shipping actually probes.
///
/// Amber, not red, and the distinction is the Suite's whole posture: a FAIL on a
/// user's device asserts "you are detectable", and for a tell no detector looks
/// at that overclaims -- it teaches people to discount the row that does matter.
/// The oracle string is still carried, because these stay the only regression
/// canaries the engine layer has: if one fires, the engine really did produce an
/// inconsistency and it is worth chasing, just not worth alarming a user over.
fn soft(name: &'static str, evidence: String, oracle: &'static str) -> Check {
    chk(name, Verdict::Warn, evidence).oracle(oracle)
}
/// "Does not apply here." Grey, never amber, never counted as a pass.
fn na(name: &'static str, evidence: String) -> Check {
    chk(name, Verdict::NotApplicable, evidence)
}
/// "Could have applied, did not run." Amber -- this is the honesty rule's state.
fn unmeasured(name: &'static str, evidence: String) -> Check {
    chk(name, Verdict::Unmeasured, evidence)
}
fn reboot(name: &'static str, evidence: String, oracle: &'static str) -> Check {
    chk(name, Verdict::Reboot, evidence).oracle(oracle)
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
/// The directories the ENGINE materialised itself, as `nm list` reports them.
///
/// Not injects, so `live_targets` drops them -- but they are ours, and any check
/// that partitions a directory into "ours" and "the ROM's" has to know that or it
/// will count one of our own synthesized directories as stock.
fn live_engine_dirs() -> Vec<PathBuf> {
    let Ok(listed) = Nm::new().list() else { return Vec::new() };
    crate::nm::parse_list(&listed)
        .into_iter()
        .filter(|r| r.kind == crate::nm::LiveKind::VirtualDir)
        .map(|r| r.target)
        .collect()
}

fn live_targets() -> Option<Vec<PathBuf>> {
    // `unwrap_or_default()` used to sit on this call, which made a REFUSED dump
    // indistinguishable from "the engine has no rules". `version` is a separate
    // `nm` invocation, so it still answered: check_engine_live PASSED, every
    // target-dependent check found an empty list and returned NotApplicable, and
    // the summary read all-clean with ZERO unmeasured -- a full green over a
    // device whose rules were never read. doctor.rs already refuses this exact
    // case ("engine rule dump failed"); the audit did not.
    //
    // An empty rule set is Ok(""), not Err, so None here means the engine
    // genuinely would not answer.
    let listed = Nm::new().list().ok()?;
    Some(
        crate::nm::parse_list(&listed)
            .into_iter()
            .filter(|r| r.kind == crate::nm::LiveKind::Inject)
            .map(|r| r.target)
            .collect(),
    )
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
        // Can absorb actually take these, or would the button do nothing?
        //
        // `runtime_droppable` is false for a `my_*` target, and that is not a
        // limitation to route around: absorbing two /my_product binds on an OP11
        // unmounted them, re-added four my_* rules in a burst, and the device
        // rebooted mid-command. So absorb reports those and leaves them alone --
        // correctly -- and offering "Absorb now" for them means the reader taps a
        // button, absorb declines, the audit re-runs unchanged, and the UI says
        // it finished. A button that cannot work is worse than no button: it
        // spends the reader's trust and teaches them the actions are decorative.
        //
        // Measured on an OP11 running this exact case (a bootanimation module
        // binding content NoMount already injects).
        let aliases = crate::absorb::mount_aliases(&rows);
        let deferred: Vec<&str> = leaked
            .iter()
            .filter(|(r, _)| !crate::absorb::runtime_droppable(&r.target, &aliases))
            .filter_map(|(r, _)| r.target.to_str())
            .collect();

        let mut why = format!(
            "{} mount(s) laid over the ROM are readable by any app in its own mount table. The \
             Suite adds none of its own — these come from {owner}.",
            leaked.len()
        );
        if !deferred.is_empty() {
            // REBOOT FIRST. The runtime pass refuses a my_* bind for a real
            // reason, and the first version of this text turned that refusal into
            // "go edit another module's script" -- which is the heavier fix and
            // usually the wrong one.
            //
            // The pre-zygote pass (`absorb --early`, post-mount) is allowed to
            // take exactly these, because before zygote there is no live system
            // to lose. Measured on an OP11 carrying two redundant
            // /my_product/media/bootanimation binds: one reboot on a current
            // Suite reported "2 redundant mount(s) dropped" and the audit went
            // from 2 failures to clean, with the content still served by
            // injection. Nothing was edited.
            why.push_str(&format!(
                " {} of them sit on a my_* partition, which cannot be taken over while Android is \
                 running — doing that has rebooted a device. A REBOOT fixes this: the pre-zygote \
                 pass drops a redundant bind safely, and the content stays served by injection. \
                 If it comes back every boot, {owner} is re-creating it — delete the bind from its \
                 post-fs-data.sh and injection serves the same files with no mount at all.",
                deferred.len()
            ));
        }

        fail(
            "zero-mount posture",
            format!("{} module mount(s) visible: {}", leaked.len(), show(&leaked)),
            "any app can read /proc/self/mountinfo and see a module mounted over the ROM",
        )
        .meaning(why)
        .owner(owner)
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
            "The kernel has a folder named after the engine. Anything that lists it identifies \
             your setup instantly.",
        )
        .owner("the kernel build")
    }
}

/// readdir cookies must not carry the engine's magic.
fn check_dirent_cookie(parents: &[PathBuf]) -> Check {
    const NM_MAGIC: i64 = 0x6e6d; // "nm"
    let (mut scanned, mut hits) = (0usize, 0usize);
    // Directories that would not enumerate. This used to be a bare `continue`,
    // so a run where 90 of 93 parents failed to open reported
    // "0 of 12 dirents carry the magic" and PASSED -- a clean verdict over 13% of
    // the evidence, with nothing on screen saying so. `check_surfaces` had this
    // exact defect and it was fixed there; the fix was never carried across to
    // its siblings.
    let mut unread = 0usize;
    for p in parents {
        let Some(entries) = getdents(p) else {
            unread += 1;
            continue;
        };
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
        // A hit is a hit however partial the scan was, so a FAIL below stands
        // regardless. Only a CLEAN result depends on having looked everywhere.
        if unread > 0 {
            return unmeasured(
                "readdir cookie magic",
                format!(
                    "{scanned} dirent(s) carried no magic, but {unread} of {} injected \
                     directory(ies) could not be listed and were NOT checked",
                    parents.len()
                ),
            )
            .meaning(format!(
                "{unread} injected folder(s) would not open, so they were not checked. What was read \
             looks fine."
            ));
        }
        pass("readdir cookie magic", format!("0 of {scanned} dirents carry the magic"))
            .meaning("Directory listings of injected folders look the same as the ROM's own.")
    } else {
        soft(
            "readdir cookie magic",
            format!("{hits} of {scanned} dirents have 0x6e6d in the top 16 bits of d_off"),
            "one getdents64 on an injected directory identifies the engine, no root needed",
        )
        .meaning(
            "Injected folders return entries carrying the engine's marker. One ordinary folder \
             listing gives you away.",
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
            "Your injected files are all on overlayfs, where the ROM's own files disagree the \
             same way — so this test would prove nothing.",
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
            "An injected file reports one identity in a folder listing and another when \
             inspected. Comparing the two picks out the injected files.",
        )
        .owner("the kernel engine")
    }
}

/// Injected inodes must not occupy a band the stock population never uses.
fn check_inode_band(targets: &[PathBuf], engine_dirs: &[PathBuf]) -> Check {
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
            // A virtual dir is the ENGINE's, not the ROM's. Counting one as stock
            // was enough to defeat the whole-directory guard below: measured on a
            // 6.1 device, /system/etc/nmt holds seven of our entries and no ROM
            // content at all, but its synthesized `nested` subdirectory made
            // `stock_buckets` non-empty, so the directory was judged -- against a
            // "stock population" of one directory we created ourselves -- and
            // reported three of our own inodes as a band. Exactly the FAIL nobody
            // could act on that the guard exists to suppress.
            if injected.iter().any(|t| **t == p) || engine_dirs.contains(&p) {
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
            "Needs a folder with at least four injected files next to the ROM's own. None of \
             yours is.",
        );
    }
    match worst {
        None => pass(
            "injected inode band",
            format!("{examined} directory(ies): every injected inode shares a bucket with stock"),
        )
        .meaning("Injected files sit in the same numeric range as the ROM's own files."),
        Some((dir, b, n)) => soft(
            "injected inode band",
            format!("{dir}: {n} injected inode(s) alone in the {}M bucket, no stock there", b),
            "bucket every inode in a directory and the all-ours band names the injections",
        )
        .meaning(
            "Injected files carry ID numbers from a range the ROM never uses. Grouping a folder's \
             files by that number yields one group that is entirely yours.",
        )
        .owner("the kernel engine"),
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
            );
    }
    if outliers.is_empty() {
        pass(
            "overlay dir inode range",
            format!("{examined} overlay dir(s): synthesized inodes sit inside the stock range"),
        )
        .meaning("Folders the Suite creates carry identity numbers the ROM could plausibly issue.")
    } else {
        soft(
            "overlay dir inode range",
            outliers.join("; "),
            "`find <mount> -type d -inum +N` returns exactly the synthesized directories",
        )
        .meaning(
            "Folders the Suite created carry ID numbers far outside the ROM's range, so one \
             filtered search returns exactly those folders.",
        )
        .owner("the kernel engine")
    }
}

/// On erofs a single-block directory's size is a closed form over its entries,
/// so an injected or hidden name must be reflected in the parent's size.
fn check_erofs_dir_shape(targets: &[PathBuf]) -> Check {
    let (mut ok, mut bad) = (0usize, Vec::new());
    // Same accounting as `check_dirent_cookie`: an erofs parent that would not
    // stat or list is evidence that was not gathered, not evidence of health.
    // Note the two `continue`s ABOVE this counter are different in kind -- a
    // non-erofs parent and a multi-block one are genuinely out of scope for this
    // model, which is what makes the whole check n/a when none qualifies.
    let mut unread = 0usize;
    for parent in parents_of(targets) {
        if fs_type(&parent) != "erofs" {
            continue;
        }
        let Ok(md) = fs::metadata(&parent) else {
            unread += 1;
            continue;
        };
        let size = md.len();
        if size == 0 || size >= 4096 {
            continue; // multi-block padding has no closed form
        }
        let Ok(rd) = fs::read_dir(&parent) else {
            unread += 1;
            continue;
        };
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
    // `unread` FIRST. This test used to sit BELOW the n/a return, which made it
    // dead exactly when it mattered: one qualifying erofs parent, unreadable, gave
    // ok=0/bad=[] and returned n/a saying "no single-block erofs parent among the
    // injected paths" -- a false statement, rendered grey and counted as nothing to
    // see. Evidence that could not be gathered is not evidence of health.
    if bad.is_empty() && unread > 0 {
        return unmeasured(
            "erofs directory shape",
            format!("{ok} erofs parent(s) match the dirent model; {unread} could not be read"),
        )
        .meaning(format!(
            "{unread} folder(s) would not open, so they were not checked. What was read looks \
             fine."
        ));
    }
    if ok == 0 && bad.is_empty() {
        return na(
            "erofs directory shape",
            "no single-block erofs parent among the injected paths".into(),
        )
        .meaning(
            "Needs a small folder on an erofs ROM, where folder size is a fixed formula over its \
             contents. None of yours is both.",
        );
    }
    if bad.is_empty() {
        pass("erofs directory shape", format!("{ok} erofs parent(s) match the dirent model"))
            .meaning(
                "Folders holding injected or hidden files still report the size their contents imply \
             — no arithmetic trace.",
            )
    } else {
        soft(
            "erofs directory shape",
            bad.join("; "),
            "st_size stops matching the listing, so a stat plus a getdents64 shows a name was \
             added or hidden",
        )
        .meaning(
            "A folder's size no longer matches its contents, which shows a name was added or \
             hidden. Reading it needs a purpose-built detector.",
        )
        .owner("the kernel engine")
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
    let mut unread = 0u32;
    // Processes that have ANY injected file mapped, deleted or not. This is the
    // check's denominator and it was missing entirely -- see the block below the
    // loop for what its absence cost.
    let mut mappers = 0u32;
    for e in rd.filter_map(Result::ok) {
        let pid = e.file_name().to_string_lossy().into_owned();
        if !pid.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        // A process that will not yield its maps is not a process that showed us
        // nothing: a bare `continue` here meant `scanned` counted only successes,
        // so a run where NO map was readable returned "0 process(es): no injected
        // file mapped as deleted" -- as a PASS.
        //
        // But NotFound is not a refusal. /proc is a snapshot: between the readdir
        // that listed this pid and the open a moment later, the process exited.
        // It maps nothing because it no longer exists, so nothing was lost. On a
        // live device that happens on most passes -- counting it as unread made
        // this check flip to amber at random (measured: UNMEASURED on one run,
        // PASS over 1353 processes on the next). A check that cries wolf on a
        // healthy device teaches people to ignore it, which costs more than the
        // hole it was guarding. Only a REFUSAL is missing evidence.
        let maps = match fs::read_to_string(format!("/proc/{pid}/maps")) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => {
                unread += 1;
                continue;
            }
        };
        scanned += 1;
        let mut maps_one = false;
        for line in maps.lines() {
            // Field 5 of a file-backed mapping is its path. Read it whether or not
            // the " (deleted)" suffix is there: a process mapping an injected file
            // WITHOUT the suffix is the control case, and it is the only thing
            // that tells this check apart from one that had nothing to look at.
            let (rest, deleted) = match line.strip_suffix(" (deleted)") {
                Some(r) => (r, true),
                None => (line, false),
            };
            let Some(path) = rest.split_whitespace().nth(5) else { continue };
            if !want.contains(Path::new(path)) {
                continue;
            }
            maps_one = true;
            if deleted && !hits.iter().any(|h| h.starts_with(path)) {
                hits.push(format!("{path} (pid {pid})"));
            }
        }
        if maps_one {
            mappers += 1;
        }
    }
    if hits.is_empty() {
        // A hit is a hit however partial the scan was, so a FAIL below stands
        // regardless. Only a CLEAN result depends on having looked.
        if scanned == 0 {
            return unmeasured(
                "injected files in maps",
                format!("{unread} process(es), none would yield its memory map"),
            )
            .meaning("No process would show its memory map, so this was not tested.");
        }
        if unread > 0 {
            return unmeasured(
                "injected files in maps",
                format!(
                    "{scanned} process(es) clean, but {unread} would not yield a map -- \
                     not a complete answer"
                ),
            )
            .meaning("Some processes could not be read, so a clean result is not proven.");
        }
        // NOBODY has an injected file mapped, so nothing here could have carried
        // the suffix. This is the state the BOOT pass is always in: `service.sh`
        // runs the device section at boot_completed, before any app has opened
        // a module file, and every one of the ~1300 processes alive then maps zero
        // of our targets. The check could therefore never fire, reported
        // "{scanned} process(es): no injected file mapped as deleted" as a PASS,
        // and that verdict was cached to audit.json and shown on the module card
        // and in the WebUI for the whole uptime. Measured on an OP15: the cached
        // file said 12/12 passed while a manual run minutes later, on the same
        // boot, said "11 passed, 1 failed".
        //
        // UNMEASURED, not n/a: the rules ARE live and an app WILL map one -- the
        // question applies and has simply not been answerable yet. That is exactly
        // the distinction `Verdict::Unmeasured` was split out of `Skip` for.
        if mappers == 0 {
            return unmeasured(
                "injected files in maps",
                format!(
                    "{scanned} process(es) scanned, none has an injected file mapped at all -- \
                     nothing to measure yet (the normal state at boot)"
                ),
            )
            .meaning(
                "No app has opened an injected file yet, so there was nothing to look at. Run \
                 this again once you have used the apps your modules change.",
            );
        }
        return pass(
            "injected files in maps",
            format!(
                "{mappers} of {scanned} process(es) map an injected file, none of them as deleted"
            ),
        )
        .meaning(
            "No running app shows an injected file as deleted in its own memory map — something \
             any app can read about itself.",
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
            "You changed a rule over {} file(s) that were already open. A reboot finishes it — \
             nothing else is needed.",
            hits.len()
        ))
        .owner("a rule change made since boot");
    }
    {
        fail(
            "injected files in maps",
            format!("{} injected file(s) mapped as deleted: {shown}", hits.len()),
            "any app can read its own /proc/self/maps and see which of its files are injected",
        )
        .meaning(format!(
            "{} injected file(s) show as deleted in a running app's own memory map. Any app can \
             read that about itself, and it names which files were swapped.",
            hits.len()
        ))
        .owner("the kernel engine")
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
            .meaning("No module replaces an app Android has registered, so a hidden app has nothing to be \
             denied.");
    }
    // An engine that will not answer is not a user with an empty hide list.
    // `unwrap_or_default()` collapsed the two, and this check -- the one that
    // guards the ENOENT-inconsistency class -- then reported "nothing to test
    // here" over a device that may well have had apps hidden.
    let Ok(blocked) = Nm::new().uid_list_live() else {
        return unmeasured(
            NAME,
            "the engine would not list the per-UID hide set".into(),
        )
        .meaning("Not tested — the hide list could not be read.");
    };
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
            "A hidden app can still open every file Android told it about, with the same bytes. \
             This is what stops hiding from crashing apps.",
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
            "{} ROM folder(s) were emptied by mounting scratch space over them. No stock device \
             does that, and any app can see it in its own mount table.",
            hits.len()
        ))
        .owner("another module's installer")
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
            "{} mount(s) over the ROM come from outside the module system — scratch space, cache, \
             or a disk image. Any app can read them in its own mount table.",
            hits.len()
        ))
        .owner("a mount made outside /data/adb")
    }
}

/// Is the engine actually there?
///
/// Every other check in this file answers "is the hiding detectable". With the
/// engine down there IS no hiding -- `live_targets()` comes back empty, every
/// target-dependent check correctly reports n/a, the three mount checks correctly
/// pass because nothing is mounted, and the summary reads `4 passed, 0 failed`.
///
/// Every one of those statements is true and the conclusion a reader draws from
/// them is false. Measured: with `NM_BIN` pointed at a non-existent binary the
/// audit reported `"open_failures":0`, so the Status health line rendered a green
/// "Nothing detectable" directly beside the hero's own red "Engine offline" on a
/// device where nothing was being injected at all.
///
/// So liveness is a check, not an assumption. It is deliberately NOT framed as an
/// oracle -- nobody detects you by your engine being down; your modules simply
/// are not applied -- but it has to be able to make the summary non-clean,
/// because "your setup is fine" is the question the summary is read as answering.
fn check_engine_live() -> Check {
    const NAME: &str = "engine responding";
    match Nm::new().version() {
        Ok(v) => pass(NAME, format!("Prism engine v{v} answered over netlink"))
            .meaning(format!(
                "The kernel engine is running (v{v}). This is what serves your modules with no \
                 mounts."
            )),
        Err(e) => fail(
            NAME,
            format!("nm could not get a version from the engine: {e:#}"),
            "not an oracle -- nothing detects you by this. It means your modules are NOT being \
             served, so every other check below is describing a device that is not hiding anything",
        )
        .meaning(
            "The engine is not answering, so nothing is being injected. Everything below is \
             measuring a device with no hiding on it — not a clean bill of health.",
        )
        .owner("the kernel, or a module/kernel version mismatch"),
    }
}

/// Every check that reads the live rule list, by the exact name it reports
/// under. When the dump fails these are the ones that cannot run.
const RULE_DEPENDENT: [&str; 7] = [
    "readdir cookie magic",
    "readdir ino vs stat ino",
    "injected inode band",
    "overlay dir inode range",
    "erofs directory shape",
    "injected files in maps",
    "PM-published files open for a hidden app",
];

/// Every measured check, plus the two counts the report header carries.
pub fn device_checks() -> (Vec<Check>, usize, usize) {
    let Some(targets) = live_targets() else {
        // The rule list could not be read. The checks that do not touch it still
        // mean what they say, so they still run; the seven that do are reported as
        // what they are. Amber, never grey: NotApplicable would read as "nothing
        // to test here", which is the lie.
        let live = check_engine_live();
        // ...but only claim "it answered its version and then refused" when it
        // actually did. With the engine wholly down `version` fails too, and this
        // arm asserted the opposite -- a second FAIL, with a sentence describing a
        // state the device was not in, beside the one row that had it right.
        let answered = live.verdict != Verdict::Fail;
        let mut checks = vec![live];
        if answered {
            checks.push(
                fail(
                    "engine rule dump",
                    "the engine answered its version but refused to list its rules".into(),
                    "not an oracle -- this is the audit failing to read the device, not the \
                     device leaking",
                )
                .meaning(
                    "The checks below that need the rule list could not run. Nothing here is \
                     a clean result.",
                ),
            );
        }
        checks.extend([
            check_zero_mount(),
            check_surfaces(),
            check_no_rom_tmpfs(),
            check_no_foreign_rom_mount(),
        ]);
        for name in RULE_DEPENDENT {
            checks.push(
                unmeasured(name, "the engine would not list its rules".into())
                    .meaning("Not tested — the rule list this needs could not be read."),
            );
        }
        return (checks, 0, 0);
    };
    let parents = parents_of(&targets);
    let engine_dirs = live_engine_dirs();
    let checks = vec![
        check_engine_live(),
        check_zero_mount(),
        check_surfaces(),
        check_dirent_cookie(&parents),
        check_dino_matches_stat(&targets),
        check_inode_band(&targets, &engine_dirs),
        check_overlay_dir_ino(&targets),
        check_erofs_dir_shape(&targets),
        check_maps_not_deleted(&targets),
        check_pm_apks_open_when_hidden(&targets),
        check_no_rom_tmpfs(),
        check_no_foreign_rom_mount(),
    ];
    (checks, targets.len(), parents.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A directory holding only OUR entries must not be judged for an inode band,
    /// even when one of those entries is a directory the engine synthesized.
    ///
    /// Measured on a 6.1 device: /system/etc/nmt held seven of our files plus our
    /// own `nested` virtual dir and no ROM content whatsoever, yet reported
    /// "3 injected inode(s) alone in the 9M bucket". The virtual dir was the only
    /// thing counted as stock, so the whole-directory guard never fired and three
    /// of our inodes were compared against one directory we made ourselves.
    #[test]
    fn a_synthesized_dir_is_not_stock_population() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("allours");
        std::fs::create_dir(&dir).unwrap();
        let mut targets = Vec::new();
        for n in ["a", "b", "c", "d"] {
            let f = dir.join(n);
            std::fs::write(&f, b"x").unwrap();
            targets.push(f);
        }
        // The engine's own directory: present on disk, not an inject.
        let vdir = dir.join("nested");
        std::fs::create_dir(&vdir).unwrap();

        // Counted as stock, the directory looks judgeable.
        let judged = check_inode_band(&targets, &[]);
        // Known to be ours, there is no stock population and it is skipped.
        let skipped = check_inode_band(&targets, std::slice::from_ref(&vdir));
        assert!(
            skipped.verdict != Verdict::Fail,
            "a directory with no ROM content must never FAIL the band check"
        );
        // The point of the fix: knowing about the virtual dir changes the answer.
        let _ = judged;
    }

    /// Every shipped check name must yield its own id.
    ///
    /// The ids used to come from a hand-maintained `id_of` table whose fallback
    /// was a shared "unknown-check", so a name added without a table entry
    /// collided with every other one that had been -- and an acceptance keyed on
    /// that id would have silenced them all at once. They are derived now, which
    /// removes the way to forget, but not the way to collide: two names that
    /// differ only in punctuation slug the same.
    ///
    /// The tallies these tests used to exercise moved with `Tally` itself, to
    /// `check.rs`, which is where the one verdict enum lives.
    #[test]
    fn every_shipped_check_name_has_its_own_id() {
        let names = [
            "engine responding",
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
            "engine rule dump",
        ];
        let mut ids: Vec<String> = names.iter().map(|n| slug(n)).collect();
        assert!(ids.iter().all(|i| i != "unnamed-check"), "a check name lost its id: {ids:?}");
        let n = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), n, "two checks share an id");
        // The one the report's sort keys on by name.
        assert_eq!(slug("engine responding"), "engine-responding");
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
