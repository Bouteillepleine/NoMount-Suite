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

#[derive(PartialEq)]
pub enum Verdict {
    Pass,
    Fail,
    /// Real, but already cured -- a reboot applies the fix that is pending.
    Reboot,
    /// Could not be measured here (nothing to sample, wrong fs, no engine).
    Skip,
}

pub struct Check {
    pub name: &'static str,
    pub verdict: Verdict,
    /// What was actually read. Always populated, including on a pass -- a bare
    /// "OK" is not evidence.
    pub evidence: String,
    /// What an attacker would do with a failure. Only on Fail.
    pub oracle: Option<&'static str>,
}

fn pass(name: &'static str, evidence: String) -> Check {
    Check { name, verdict: Verdict::Pass, evidence, oracle: None }
}
fn fail(name: &'static str, evidence: String, oracle: &'static str) -> Check {
    Check { name, verdict: Verdict::Fail, evidence, oracle: Some(oracle) }
}
fn skip(name: &'static str, evidence: String) -> Check {
    Check { name, verdict: Verdict::Skip, evidence, oracle: None }
}
fn reboot(name: &'static str, evidence: String, oracle: &'static str) -> Check {
    Check { name, verdict: Verdict::Reboot, evidence, oracle: Some(oracle) }
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
            if reclen == 0 || off + reclen > n as usize {
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

fn live_targets() -> Vec<PathBuf> {
    Nm::new()
        .list()
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.split(" [UID:").next().unwrap_or(l).split_whitespace().next())
        .map(PathBuf::from)
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
        return skip("zero-mount posture", "cannot read /proc/self/mountinfo".into());
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
        pass("zero-mount posture", note)
    } else {
        fail(
            "zero-mount posture",
            format!("{} module mount(s) visible: {}", leaked.len(), show(&leaked)),
            "any app can read /proc/self/mountinfo and see a module mounted over the ROM",
        )
    }
}

/// The engine must expose no /sys, /proc or module surface of its own.
fn check_surfaces() -> Check {
    let mut found = Vec::new();
    for dir in ["/sys/kernel", "/sys/module", "/proc"] {
        if let Ok(rd) = fs::read_dir(dir) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().to_lowercase();
                if n.contains("nomount") {
                    found.push(format!("{dir}/{n}"));
                }
            }
        }
    }
    if let Ok(f) = fs::read_to_string("/proc/filesystems") {
        if f.to_lowercase().contains("nomount") {
            found.push("/proc/filesystems".into());
        }
    }
    if found.is_empty() {
        pass("kernel surfaces", "no nomount entry in /sys/kernel, /sys/module, /proc".into())
    } else {
        fail(
            "kernel surfaces",
            found.join(", "),
            "a named surface identifies the engine outright, with no analysis needed",
        )
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
        return skip("readdir cookie magic", "no injected directory could be read".into());
    }
    if hits == 0 {
        pass("readdir cookie magic", format!("0 of {scanned} dirents carry the magic"))
    } else {
        fail(
            "readdir cookie magic",
            format!("{hits} of {scanned} dirents have 0x6e6d in the top 16 bits of d_off"),
            "one getdents64 on an injected directory identifies the engine, no root needed",
        )
    }
}

/// An injected file's readdir d_ino must equal its stat st_ino.
fn check_dino_matches_stat(targets: &[PathBuf]) -> Check {
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
            let Some(e) = entries.iter().find(|e| e.name == name) else { continue };
            let Some(st) = ino_of(k) else { continue };
            checked += 1;
            if e.d_ino != st {
                bad.push(format!("{} d_ino={} st_ino={}", k.display(), e.d_ino, st));
            }
        }
    }
    if checked == 0 {
        return skip(
            "readdir ino vs stat ino",
            "no injected file on a non-overlay filesystem to compare".into(),
        );
    }
    if bad.is_empty() {
        pass("readdir ino vs stat ino", format!("{checked} injected file(s) agree"))
    } else {
        fail(
            "readdir ino vs stat ino",
            format!("{} of {checked} disagree: {}", bad.len(), bad.join("; ")),
            "listing a directory and stat-ing its entries separates injected files from stock",
        )
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
        return skip(
            "injected inode band",
            "no directory with both enough injections and a stock population to compare".into(),
        );
    }
    match worst {
        None => pass(
            "injected inode band",
            format!("{examined} directory(ies): every injected inode shares a bucket with stock"),
        ),
        Some((dir, b, n)) => fail(
            "injected inode band",
            format!("{dir}: {n} injected inode(s) alone in the {}M bucket, no stock there", b),
            "bucket every inode in a directory and the all-ours band names the injections",
        ),
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
        return skip("overlay dir inode range", "no injected directory on an overlay mount".into());
    }
    if outliers.is_empty() {
        pass(
            "overlay dir inode range",
            format!("{examined} overlay dir(s): synthesized inodes sit inside the stock range"),
        )
    } else {
        fail(
            "overlay dir inode range",
            outliers.join("; "),
            "`find <mount> -type d -inum +N` returns exactly the synthesized directories",
        )
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
        return skip(
            "erofs directory shape",
            "no single-block erofs parent among the injected paths".into(),
        );
    }
    if bad.is_empty() {
        pass("erofs directory shape", format!("{ok} erofs parent(s) match the dirent model"))
    } else {
        fail(
            "erofs directory shape",
            bad.join("; "),
            "st_size stops matching the listing, so a stat plus a getdents64 shows a name was \
             added or hidden",
        )
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
        return skip("injected files in maps", "no live rules".into());
    }
    let want: HashSet<&Path> = targets.iter().map(PathBuf::as_path).collect();
    let Ok(rd) = fs::read_dir("/proc") else {
        return skip("injected files in maps", "cannot read /proc".into());
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
        );
    }
    {
        fail(
            "injected files in maps",
            format!("{} injected file(s) mapped as deleted: {shown}", hits.len()),
            "any app can read its own /proc/self/maps and see which of its files are injected",
        )
    }
}

/// A hidden app must still be able to open the APKs the PackageManager gave it.
///
/// Per-UID hiding serves a blocked reader the stock filesystem, which for an ADDED
/// name means ENOENT. That is right for a module file nothing else mentions -- and
/// wrong for a ROM APK, because the PackageManager scanned the directory as
/// system_server (never blocked), registered the package, and now hands its path to
/// every app that asks. The hidden app is then holding a path the system says
/// exists and open() denies, which no device produces on its own.
///
/// Measured consequence, OP15 2026-08-23: IBM Trusteer (La Banque Postale) walks
/// the package list at startup, calls getResourcesForApplication() on each entry,
/// and SIGSEGVs on the IOException from 139 unopenable /product/overlay APKs.
///
/// The probe forks, drops to a blocked appid and opens each ROM APK rule target.
/// It changes UID only -- the SELinux domain stays ours -- which is exactly what
/// the engine keys on (nomount_is_uid_blocked reads current_uid()), so it measures
/// the hiding decision and NOT the app's own domain permissions.
fn check_pm_apks_open_when_hidden(targets: &[PathBuf]) -> Check {
    const NAME: &str = "PM-registered APKs open for a hidden app";
    let apks: Vec<&PathBuf> = targets.iter().filter(|t| crate::pmcache::is_rom_apk(t)).collect();
    if apks.is_empty() {
        return skip(NAME, "no ROM APK rules live".into());
    }
    let blocked = Nm::new().uid_list_live().unwrap_or_default();
    let Some(&appid) = blocked.first() else {
        return skip(NAME, format!("{} ROM APK rule(s), but no app is hidden", apks.len()));
    };
    // Only paths root can open are worth asking about: one the module itself
    // cannot serve is a different bug, and this check must not claim it.
    let readable: Vec<&&PathBuf> = apks.iter().filter(|p| fs::File::open(p).is_ok()).collect();
    if readable.is_empty() {
        return skip(NAME, format!("{} ROM APK rule(s), none readable as root", apks.len()));
    }

    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return skip(NAME, "pipe() failed".into());
    }
    let (rd, wr) = (fds[0], fds[1]);
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe { libc::close(rd); libc::close(wr) };
        return skip(NAME, "fork() failed".into());
    }
    if pid == 0 {
        unsafe { libc::close(rd) };
        let mut denied = 0u32;
        // setgid before setuid: the reverse leaves the group id unchanged with no
        // privilege left to change it.
        let dropped = unsafe { libc::setgid(appid) == 0 && libc::setuid(appid) == 0 };
        if dropped {
            for p in &readable {
                if fs::File::open(p.as_path()).is_err() {
                    denied += 1;
                }
            }
        } else {
            denied = u32::MAX;
        }
        let buf = denied.to_ne_bytes();
        unsafe { libc::write(wr, buf.as_ptr() as *const libc::c_void, 4) };
        unsafe { libc::_exit(0) };
    }
    unsafe { libc::close(wr) };
    let mut buf = [0u8; 4];
    let got = unsafe { libc::read(rd, buf.as_mut_ptr() as *mut libc::c_void, 4) };
    unsafe { libc::close(rd) };
    let mut status = 0i32;
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if got != 4 {
        return skip(NAME, "probe child said nothing".into());
    }
    let denied = u32::from_ne_bytes(buf);
    if denied == u32::MAX {
        return skip(NAME, format!("could not drop to uid {appid}"));
    }
    if denied == 0 {
        return pass(
            NAME,
            format!("uid {appid} (hidden) opened all {} ROM APK rule target(s)", readable.len()),
        );
    }
    fail(
        NAME,
        format!(
            "uid {appid} (hidden) could not open {denied} of {} ROM APK rule target(s)",
            readable.len()
        ),
        "the PackageManager names those paths to the app while open() answers ENOENT --          an inconsistency no stock device has, and one that crashes RASP code that walks          the package list (engine < 15 cannot express the opt-out; see NM_FLAG_PUBLIC)",
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
        return skip("tmpfs over the ROM", "cannot read /proc/self/mountinfo".into());
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
    } else {
        fail(
            "tmpfs over the ROM",
            format!("{} ROM path(s) emptied by a tmpfs: {}", hits.len(), hits.join(", ")),
            "stock never mounts tmpfs inside /system, /product or /vendor -- any app can read it from its own mountinfo",
        )
    }
}

pub fn run_audit() -> Result<()> {
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
    ];

    println!("nomount audit: {} live rule(s) across {} directory(ies)\n", targets.len(), parents.len());
    let (mut p, mut fl, mut sk, mut rb) = (0, 0, 0, 0);
    for c in &checks {
        let tag = match c.verdict {
            Verdict::Pass => {
                p += 1;
                "PASS"
            }
            Verdict::Fail => {
                fl += 1;
                "FAIL"
            }
            Verdict::Reboot => {
                rb += 1;
                "REBOOT"
            }
            Verdict::Skip => {
                sk += 1;
                "SKIP"
            }
        };
        println!("[{tag}] {}\n       {}", c.name, c.evidence);
        if let Some(o) = c.oracle {
            println!("       oracle: {o}");
        }
    }
    println!("\nsummary: {p} passed, {fl} failed, {sk} skipped, {rb} pending reboot");
    if rb > 0 {
        println!("note: a pending-reboot check is still detectable until you reboot.");
    }
    if sk > 0 {
        println!("note: a skipped check was NOT verified — it is not a pass.");
    }
    if fl > 0 || rb > 0 {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
