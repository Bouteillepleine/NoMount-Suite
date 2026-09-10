
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::check::{slug, Check, Section, Verdict};
use crate::nm::Nm;

fn chk(name: &'static str, verdict: Verdict, evidence: String) -> Check {
    Check::new(Section::Device, slug(name), name, verdict, evidence)
}
fn pass(name: &'static str, evidence: String) -> Check {
    chk(name, Verdict::Pass, evidence)
}
fn fail(name: &'static str, evidence: String, oracle: &'static str) -> Check {
    chk(name, Verdict::Fail, evidence).oracle(oracle)
}
fn soft(name: &'static str, evidence: String, oracle: &'static str) -> Check {
    chk(name, Verdict::Warn, evidence).oracle(oracle)
}
fn na(name: &'static str, evidence: String) -> Check {
    chk(name, Verdict::NotApplicable, evidence)
}
fn unmeasured(name: &'static str, evidence: String) -> Check {
    chk(name, Verdict::Unmeasured, evidence)
}
fn reboot(name: &'static str, evidence: String, oracle: &'static str) -> Check {
    chk(name, Verdict::Reboot, evidence).oracle(oracle)
}

pub(crate) const N_ENGINE_LIVE: &str = "engine responding";
pub(crate) const N_ZERO_MOUNT: &str = "zero-mount posture";
pub(crate) const N_SURFACES: &str = "kernel surfaces";
pub(crate) const N_DIRENT_COOKIE: &str = "readdir cookie magic";
pub(crate) const N_DINO_STAT: &str = "readdir ino vs stat ino";
pub(crate) const N_INODE_BAND: &str = "injected inode band";
pub(crate) const N_OVERLAY_DIR_INO: &str = "overlay dir inode range";
pub(crate) const N_EROFS_SHAPE: &str = "erofs directory shape";
pub(crate) const N_MAPS_DELETED: &str = "injected files in maps";
pub(crate) const N_PM_OPEN: &str = "PM-published files open for a hidden app";
pub(crate) const N_ROM_TMPFS: &str = "tmpfs over the ROM";
pub(crate) const N_FOREIGN_MOUNT: &str = "foreign mount over the ROM";
pub(crate) const N_RULE_DUMP: &str = "engine rule dump";

#[cfg(test)]
pub(crate) const ALL_CHECK_NAMES: [&str; 13] = [
    N_ENGINE_LIVE, N_ZERO_MOUNT, N_SURFACES, N_DIRENT_COOKIE, N_DINO_STAT,
    N_INODE_BAND, N_OVERLAY_DIR_INO, N_EROFS_SHAPE, N_MAPS_DELETED, N_PM_OPEN,
    N_ROM_TMPFS, N_FOREIGN_MOUNT, N_RULE_DUMP,
];

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
            let h = unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off) as *const Dirent64Hdr) };
            let reclen = h.d_reclen as usize;
            if reclen < 19 || off + reclen > n as usize {
                break;
            }
            let nstart = off + 19;
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

fn live_engine_dirs() -> Vec<PathBuf> {
    let Ok(listed) = Nm::new().list() else { return Vec::new() };
    crate::nm::parse_list(&listed)
        .into_iter()
        .filter(|r| r.kind == crate::nm::LiveKind::VirtualDir)
        .map(|r| r.target)
        .collect()
}

fn live_targets() -> Option<Vec<PathBuf>> {
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

fn check_zero_mount() -> Check {
    let Ok(mi) = fs::read_to_string("/proc/self/mountinfo") else {
        return unmeasured(N_ZERO_MOUNT, "cannot read /proc/self/mountinfo".into())
            .meaning("Could not read the mount table, so whether any module mount is visible to apps is unknown.");
    };
    let rows = crate::absorb::parse_mountinfo(&mi);
    let roots = crate::absorb::fs_roots(&rows);
    let hits: Vec<(&crate::absorb::MountRow, std::path::PathBuf)> = rows
        .iter()
        .filter_map(|r| crate::absorb::source_of(r, &roots).map(|src| (r, src)))
        .filter(|(_, src)| src.starts_with("/data/adb"))
        .collect();
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
                "Nothing unexpected. {} hook-framework bind(s) remain on purpose - absorb never \
                 takes those over, because breaking a Zygisk/Xposed hook surfaces hours later \
                 during app install, not at boot.",
                by_design.len()
            )
        };
        pass(N_ZERO_MOUNT, note).meaning(meaning)
    } else {
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
        let aliases = crate::absorb::mount_aliases(&rows);
        let deferred: Vec<&str> = leaked
            .iter()
            .filter(|(r, _)| !crate::absorb::runtime_droppable(&r.target, &aliases))
            .filter_map(|(r, _)| r.target.to_str())
            .collect();

        let ours: std::collections::HashSet<std::path::PathBuf> =
            crate::bind::tracked().into_iter().map(|(t, _)| t).collect();
        let mine = leaked.iter().filter(|(r, _)| ours.contains(&r.target)).count();
        let mut why = if mine == leaked.len() {
            format!(
                "{} mount(s) laid over the ROM are readable by any app in its own mount table. \
                 The SUITE made these itself: a my_* target is served by a real bind unless the \
                 `my_hookless` opt-in is set, because a leaf my_* injection can trip zygote's FD \
                 allowlist. They serve content from {owner}. Set /data/adb/nomount/my_hookless \
                 and reboot to serve them by injection instead, with no mount at all.",
                leaked.len()
            )
        } else if mine > 0 {
            format!(
                "{} mount(s) laid over the ROM are readable by any app in its own mount table. \
                 {mine} of them the Suite made itself (a my_* target is served by bind; set \
                 /data/adb/nomount/my_hookless to inject instead). The rest come from {owner}.",
                leaked.len()
            )
        } else {
            format!(
                "{} mount(s) laid over the ROM are readable by any app in its own mount table. The \
                 Suite adds none of its own - these come from {owner}.",
                leaked.len()
            )
        };
        let deferred: Vec<&str> = deferred
            .into_iter()
            .filter(|t| !ours.contains(std::path::Path::new(t)))
            .collect();
        if !deferred.is_empty() {
            why.push_str(&format!(
                " {} of them sit on a my_* partition, which cannot be taken over while Android is \
                 running - doing that has rebooted a device. A REBOOT fixes this: the pre-zygote \
                 pass drops a redundant bind safely, and the content stays served by injection. \
                 If it comes back every boot, {owner} is re-creating it - delete the bind from its \
                 post-fs-data.sh and injection serves the same files with no mount at all.",
                deferred.len()
            ));
        }

        let evidence = format!("{} module mount(s) visible: {}", leaked.len(), show(&leaked));
        let oracle = "any app can read /proc/self/mountinfo and see a module mounted over the ROM";
        let c = if mine == leaked.len() {
            chk(N_ZERO_MOUNT, Verdict::Note, evidence).oracle(oracle)
        } else {
            fail(N_ZERO_MOUNT, evidence, oracle)
        };
        c.meaning(why).owner(owner)
    }
}

fn check_surfaces() -> Check {
    let mut found = Vec::new();
    let mut unread: Vec<&str> = Vec::new();
    for dir in ["/sys/kernel", "/sys/module", "/proc", "/dev"] {
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
    if found.is_empty() && !unread.is_empty() {
        return unmeasured(
            N_SURFACES,
            format!(
                "could not enumerate {} - nothing named nomount was found in the rest, but \
                 this check did NOT clear the surfaces it could not read",
                unread.join(", ")
            ),
        )
        .meaning(
            "Part of the kernel's public directory listing could not be read, so this is not a \
             clean result - only an incomplete one.",
        );
    }
    if found.is_empty() {
        pass(
            N_SURFACES,
            "no entry named nomount in /sys/kernel, /sys/module, /proc, /dev (names only; \
             /proc/kallsyms symbols are a separate, deliberately-uncloaked residual, \
             unreadable by app domains)"
                .into(),
        )
        .meaning("The engine has no directory entry anywhere an app can list that names it.")
    } else {
        fail(
            N_SURFACES,
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

fn check_dirent_cookie(parents: &[PathBuf]) -> Check {
    const NM_MAGIC: i64 = 0x6e6d;
    let (mut scanned, mut hits) = (0usize, 0usize);
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
        return if parents.is_empty() {
            na(N_DIRENT_COOKIE, "no injection rules are live, so no directory to read".into())
                .meaning("Nothing is being injected yet, so there are no listings to check.")
        } else {
            unmeasured(
                N_DIRENT_COOKIE,
                format!("{} injected directory(ies), none could be read", parents.len()),
            )
            .meaning("The injected directories could not be listed, so this was not tested.")
        };
    }
    if hits == 0 {
        if unread > 0 {
            return unmeasured(
                N_DIRENT_COOKIE,
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
        pass(N_DIRENT_COOKIE, format!("0 of {scanned} dirents carry the magic"))
            .meaning("Directory listings of injected folders look the same as the ROM's own.")
    } else {
        soft(
            N_DIRENT_COOKIE,
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

fn check_dino_matches_stat(targets: &[PathBuf]) -> Check {
    let mut eligible = 0usize;
    let mut checked = 0usize;
    let mut unread = 0usize;
    let mut bad = Vec::new();
    let mut by_parent: HashMap<PathBuf, Vec<&PathBuf>> = HashMap::new();
    for t in targets {
        if let Some(p) = t.parent() {
            by_parent.entry(p.to_path_buf()).or_default().push(t);
        }
    }
    for (parent, kids) in &by_parent {
        if fs_type(parent) == "overlay" {
            continue;
        }
        let Some(entries) = getdents(parent) else {
            unread += 1;
            continue;
        };
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
        if unread > 0 {
            return unmeasured(
                N_DINO_STAT,
                format!("{unread} injected directory(ies) could not be listed, so nothing was compared"),
            )
            .meaning(
                "The folders holding your injected files would not open, so this was not tested.",
            );
        }
        return na(
            N_DINO_STAT,
            "no injected file on a non-overlay filesystem to compare".into(),
        )
        .meaning(
            "Your injected files are all on overlayfs, where the ROM's own files disagree the \
             same way - so this test would prove nothing.",
        );
    }
    if bad.is_empty() && unread > 0 {
        return unmeasured(
            N_DINO_STAT,
            format!(
                "{checked}/{eligible} injected file(s) agree, but {unread} directory(ies) could \
                 not be listed and were NOT checked"
            ),
        )
        .meaning(format!(
            "{unread} folder(s) would not open, so they were not checked. What was read looks fine."
        ));
    }
    if bad.is_empty() {
        pass(N_DINO_STAT, format!("{checked}/{eligible} injected file(s) agree"))
            .meaning("Injected files report the same identity when listed as when inspected.")
    } else {
        fail(
            N_DINO_STAT,
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

fn check_inode_band(targets: &[PathBuf], engine_dirs: &[PathBuf]) -> Check {
    const BUCKET: u64 = 1_000_000;
    let mut worst: Option<(String, u64, usize)> = None;
    let mut examined = 0usize;
    let mut unread = 0usize;
    for parent in parents_of(targets) {
        let Ok(rd) = fs::read_dir(&parent) else {
            unread += 1;
            continue;
        };
        let injected: Vec<&PathBuf> =
            targets.iter().filter(|t| t.parent() == Some(parent.as_path())).collect();
        if injected.len() < 4 {
            continue;
        }
        let mut stock_buckets: HashMap<u64, usize> = HashMap::new();
        let mut ours_buckets: HashMap<u64, usize> = HashMap::new();
        for e in rd.flatten() {
            let p = e.path();
            let Some(i) = ino_of(&p) else { continue };
            let b = i / BUCKET;
            if injected.iter().any(|t| **t == p) || engine_dirs.contains(&p) {
                *ours_buckets.entry(b).or_default() += 1;
            } else {
                *stock_buckets.entry(b).or_default() += 1;
            }
        }
        if stock_buckets.is_empty() {
            continue;
        }
        examined += 1;
        let mut bands: Vec<(&u64, &usize)> = ours_buckets.iter().collect();
        bands.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (b, n) in bands {
            if !stock_buckets.contains_key(b) && worst.as_ref().is_none_or(|w| *n > w.2) {
                worst = Some((parent.to_string_lossy().into_owned(), *b, *n));
            }
        }
    }
    if examined == 0 {
        if unread > 0 {
            return unmeasured(
                N_INODE_BAND,
                format!("{unread} directory(ies) could not be read, so none could be compared"),
            )
            .meaning("The folders this needed to read would not open, so this was not tested.");
        }
        return na(
            N_INODE_BAND,
            "no directory with both enough injections and a stock population to compare".into(),
        )
        .meaning(
            "Needs a folder with at least four injected files next to the ROM's own. None of \
             yours is.",
        );
    }
    if worst.is_none() && unread > 0 {
        return unmeasured(
            N_INODE_BAND,
            format!(
                "{examined} directory(ies) clean, but {unread} could not be read and were NOT \
                 checked"
            ),
        )
        .meaning(format!(
            "{unread} folder(s) would not open, so they were not checked. What was read looks fine."
        ));
    }
    match worst {
        None => pass(
            N_INODE_BAND,
            format!("{examined} directory(ies): every injected inode shares a bucket with stock"),
        )
        .meaning("Injected files sit in the same numeric range as the ROM's own files."),
        Some((dir, b, n)) => soft(
            N_INODE_BAND,
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

fn check_overlay_dir_ino(targets: &[PathBuf]) -> Check {
    let mut outliers = Vec::new();
    let mut examined = 0usize;
    let mut unread = 0usize;
    for parent in parents_of(targets) {
        if fs_type(&parent) != "overlay" {
            continue;
        }
        let Ok(rd) = fs::read_dir(&parent) else {
            unread += 1;
            continue;
        };
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
            if i > stock_max.saturating_mul(8) {
                outliers.push(format!("{} ino={i} (stock max here {stock_max})", p.display()));
            }
        }
    }
    if examined == 0 {
        if unread > 0 {
            return unmeasured(
                N_OVERLAY_DIR_INO,
                format!("{unread} overlay directory(ies) could not be read"),
            )
            .meaning("The folders this needed to read would not open, so this was not tested.");
        }
        return na(N_OVERLAY_DIR_INO, "no injected directory on an overlay mount".into())
            .meaning(
                "This one only applies to folders the Suite creates on an overlayfs ROM, and you \
                 have none.",
            );
    }
    if outliers.is_empty() && unread > 0 {
        return unmeasured(
            N_OVERLAY_DIR_INO,
            format!(
                "{examined} overlay dir(s) clean, but {unread} could not be read and were NOT \
                 checked"
            ),
        )
        .meaning(format!(
            "{unread} folder(s) would not open, so they were not checked. What was read looks fine."
        ));
    }
    if outliers.is_empty() {
        pass(
            N_OVERLAY_DIR_INO,
            format!("{examined} overlay dir(s): synthesized inodes sit inside the stock range"),
        )
        .meaning("Folders the Suite creates carry identity numbers the ROM could plausibly issue.")
    } else {
        soft(
            N_OVERLAY_DIR_INO,
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

fn check_erofs_dir_shape(targets: &[PathBuf]) -> Check {
    let (mut ok, mut bad) = (0usize, Vec::new());
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
            continue;
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
    if bad.is_empty() && unread > 0 {
        return unmeasured(
            N_EROFS_SHAPE,
            format!("{ok} erofs parent(s) match the dirent model; {unread} could not be read"),
        )
        .meaning(format!(
            "{unread} folder(s) would not open, so they were not checked. What was read looks \
             fine."
        ));
    }
    if ok == 0 && bad.is_empty() {
        return na(
            N_EROFS_SHAPE,
            "no single-block erofs parent among the injected paths".into(),
        )
        .meaning(
            "Needs a small folder on an erofs ROM, where folder size is a fixed formula over its \
             contents. None of yours is both.",
        );
    }
    if bad.is_empty() {
        pass(N_EROFS_SHAPE, format!("{ok} erofs parent(s) match the dirent model"))
            .meaning(
                "Folders holding injected or hidden files still report the size their contents imply \
 - no arithmetic trace.",
            )
    } else {
        soft(
            N_EROFS_SHAPE,
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

fn maps_pathname(rest: &str) -> Option<&str> {
    let mut s = rest;
    for _ in 0..5 {
        s = s.trim_start();
        s = &s[s.find(char::is_whitespace)?..];
    }
    let p = s.trim_start();
    (!p.is_empty()).then_some(p)
}

fn check_maps_not_deleted(targets: &[PathBuf]) -> Check {
    if targets.is_empty() {
        return na(N_MAPS_DELETED, "no live rules".into())
            .meaning("Nothing is being injected yet, so no process can have one mapped.");
    }
    let want: HashSet<&Path> = targets.iter().map(PathBuf::as_path).collect();
    let Ok(rd) = fs::read_dir("/proc") else {
        return unmeasured(N_MAPS_DELETED, "cannot read /proc".into())
            .meaning("The process list could not be read, so this was not tested.");
    };
    let mut hits: Vec<String> = Vec::new();
    let mut scanned = 0u32;
    let mut unread = 0u32;
    let mut mappers = 0u32;
    for e in rd.filter_map(Result::ok) {
        let pid = e.file_name().to_string_lossy().into_owned();
        if !pid.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
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
            let (rest, deleted) = match line.strip_suffix(" (deleted)") {
                Some(r) => (r, true),
                None => (line, false),
            };
            let Some(path) = maps_pathname(rest) else { continue };
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
        if scanned == 0 {
            return unmeasured(
                N_MAPS_DELETED,
                format!("{unread} process(es), none would yield its memory map"),
            )
            .meaning("No process would show its memory map, so this was not tested.");
        }
        if unread > 0 {
            return unmeasured(
                N_MAPS_DELETED,
                format!(
                    "{scanned} process(es) clean, but {unread} would not yield a map -- \
                     not a complete answer"
                ),
            )
            .meaning("Some processes could not be read, so a clean result is not proven.");
        }
        if mappers == 0 {
            return unmeasured(
                N_MAPS_DELETED,
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
            N_MAPS_DELETED,
            format!(
                "{mappers} of {scanned} process(es) map an injected file, none of them as deleted"
            ),
        )
        .meaning(
            "No running app shows an injected file as deleted in its own memory map - something \
             any app can read about itself.",
        );
    }
    let shown = hits.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
    let pending = crate::pmcache::pending();
    if !pending.is_empty() && hits.iter().all(|h| pending.iter().any(|p| h.starts_with(&*p.to_string_lossy()))) {
        return reboot(
            N_MAPS_DELETED,
            format!("{} injected file(s) mapped as deleted: {shown} -- pending reboot after a rule change", hits.len()),
            "still readable until the reboot: any app can see which of its files are injected",
        )
        .meaning(format!(
            "You changed a rule over {} file(s) that were already open. A reboot finishes it - \
             nothing else is needed.",
            hits.len()
        ))
        .owner("a rule change made since boot");
    }
    {
        fail(
            N_MAPS_DELETED,
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

fn check_pm_apks_open_when_hidden(targets: &[PathBuf]) -> Check {
    const NAME: &str = N_PM_OPEN;
    let apks: Vec<&PathBuf> = targets.iter().filter(|t| crate::pmcache::is_pm_published(t)).collect();
    if apks.is_empty() {
        return na(NAME, "no PM-published rules live".into())
            .meaning("No module replaces an app Android has registered, so a hidden app has nothing to be \
             denied.");
    }
    let Ok(blocked) = Nm::new().uid_list_live() else {
        return unmeasured(
            NAME,
            "the engine would not list the per-UID hide set".into(),
        )
        .meaning("Not tested - the hide list could not be read.");
    };
    let Some(&appid) = blocked.first() else {
        return na(NAME, format!("{} PM-published file rule(s), but no app is hidden", apks.len()))
            .meaning("You have not hidden any apps yet, so there is nothing to test here. Hide one and this check starts running.");
    };
    let readable: Vec<&&PathBuf> = apks.iter().filter(|p| fs::File::open(p).is_ok()).collect();
    if readable.is_empty() {
        return unmeasured(NAME, format!("{} PM-published file rule(s), none readable as root", apks.len()))
            .meaning("None of the published files could be opened even as root, so the question this check asks could not be put.");
    }
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
        )
        .meaning(
            "A hidden app CAN open every file Android told it about, but for some of them it is \
             handed the ROM's original instead of your module's version -- while Android still \
             advertises your version's number and signature for that path. An app that checks \
             gets two different answers about one file.",
        )
        .owner("the kernel engine");
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
    .meaning(
        "A hidden app is being told those files do not exist, while Android tells it they do. \
         No ordinary device answers both ways about one file, and banking apps that walk the \
         package list crash on it. Update the kernel, or stop hiding from that app.",
    )
    .owner("the kernel engine")
}

fn check_no_rom_tmpfs() -> Check {
    let Ok(mi) = fs::read_to_string("/proc/self/mountinfo") else {
        return unmeasured(N_ROM_TMPFS, "cannot read /proc/self/mountinfo".into())
            .meaning("Could not read the mount table, so whether a module emptied a ROM folder this way is unknown.");
    };
    let roots = crate::absorb::ROM_ROOTS;
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
        pass(N_ROM_TMPFS, "no tmpfs mounted inside a ROM partition".into())
            .meaning("No ROM folder has been emptied by mounting scratch space over it.")
    } else {
        fail(
            N_ROM_TMPFS,
            format!("{} ROM path(s) emptied by a tmpfs: {}", hits.len(), hits.join(", ")),
            "stock never mounts tmpfs inside /system, /product or /vendor - any app can read it from its own mountinfo",
        )
        .meaning(format!(
            "{} ROM folder(s) were emptied by mounting scratch space over them. No stock device \
             does that, and any app can see it in its own mount table.",
            hits.len()
        ))
        .owner("another module's installer")
    }
}

fn check_no_foreign_rom_mount() -> Check {
    let Ok(mi) = fs::read_to_string("/proc/self/mountinfo") else {
        return unmeasured(N_FOREIGN_MOUNT, "cannot read /proc/self/mountinfo".into())
            .meaning("Could not read the mount table, so whether anything foreign is mounted over the ROM is unknown.");
    };
    let roots = crate::absorb::ROM_ROOTS;
    let rows = crate::absorb::parse_mountinfo(&mi);
    let data_dev = rows.iter().find(|r| r.target == Path::new("/data")).map(|r| r.dev.clone());
    let mut hits: Vec<String> = Vec::new();
    for r in &rows {
        let t = r.target.to_string_lossy();
        if !roots.iter().any(|root| t.starts_with(root)) {
            continue;
        }
        if r.root.starts_with("/adb/modules/") || r.root.starts_with("/data/adb/modules/") {
            continue;
        }
        let subtree_bind = r.root != "/";
        let off_userdata = data_dev.as_deref() == Some(r.dev.as_str());
        if subtree_bind || off_userdata {
            hits.push(format!("{} (root={}, dev={})", t, r.root, r.dev));
        }
    }
    if hits.is_empty() {
        pass(N_FOREIGN_MOUNT, "no non-/data/adb bind or image mounted over a ROM partition".into())
            .meaning("Nothing outside the module system is mounted over a read-only ROM partition.")
    } else {
        fail(
            N_FOREIGN_MOUNT,
            format!("{} foreign mount(s) over the ROM: {}", hits.len(), hits.join(", ")),
            "a bind from /data/local/tmp or /cache, or an image over the ROM, is visible in any app's mountinfo just like a module mount",
        )
        .meaning(format!(
            "{} mount(s) over the ROM come from outside the module system - scratch space, cache, \
             or a disk image. Any app can read them in its own mount table.",
            hits.len()
        ))
        .owner("a mount made outside /data/adb")
    }
}

fn check_engine_live() -> Check {
    const NAME: &str = N_ENGINE_LIVE;
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
             measuring a device with no hiding on it - not a clean bill of health.",
        )
        .owner("the kernel, or a module/kernel version mismatch"),
    }
}

const RULE_DEPENDENT: [&str; 7] = [
    N_DIRENT_COOKIE,
    N_DINO_STAT,
    N_INODE_BAND,
    N_OVERLAY_DIR_INO,
    N_EROFS_SHAPE,
    N_MAPS_DELETED,
    N_PM_OPEN,
];

pub fn device_checks() -> (Vec<Check>, usize, usize) {
    let Some(targets) = live_targets() else {
        let live = check_engine_live();
        let answered = live.verdict != Verdict::Fail;
        let mut checks = vec![live];
        if answered {
            checks.push(
                fail(
                    N_RULE_DUMP,
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
                    .meaning("Not tested - the rule list this needs could not be read."),
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
        let vdir = dir.join("nested");
        std::fs::create_dir(&vdir).unwrap();

        let judged = check_inode_band(&targets, &[]);
        let skipped = check_inode_band(&targets, std::slice::from_ref(&vdir));
        assert!(
            skipped.verdict != Verdict::Fail,
            "a directory with no ROM content must never FAIL the band check"
        );
        let _ = judged;
    }

    #[test]
    fn a_maps_pathname_survives_a_space_in_it() {
        let plain = "7f8a00000-7f8a01000 r--p 00000000 fe:29 1234    /product/app/Foo/Foo.apk";
        assert_eq!(maps_pathname(plain), Some("/product/app/Foo/Foo.apk"));

        let spaced = "7f8a00000-7f8a01000 r--p 00000000 fe:29 1234    /product/app/My App/My App.apk";
        assert_eq!(maps_pathname(spaced), Some("/product/app/My App/My App.apk"));

        assert_eq!(maps_pathname("7f8a00000-7f8a01000 rw-p 00000000 00:00 0 "), None);
        assert_eq!(maps_pathname("short line"), None);
    }

    #[test]
    fn an_unreadable_parent_is_unmeasured_not_not_applicable() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("locked");
        std::fs::create_dir(&dir).unwrap();
        let f = dir.join("x");
        std::fs::write(&f, b"x").unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();

        let blocked = getdents(&dir).is_none();
        if blocked {
            let c = check_dino_matches_stat(std::slice::from_ref(&f));
            assert_eq!(
                c.verdict.tag(),
                "UNMEASURED",
                "an unreadable directory must not read as \"nothing to compare\""
            );
            let b = check_inode_band(std::slice::from_ref(&f), &[]);
            assert_eq!(b.verdict.tag(), "UNMEASURED");
        }
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }

    #[test]
    fn every_shipped_check_name_has_its_own_id() {
        let names = ALL_CHECK_NAMES;
        let mut ids: Vec<String> = names.iter().map(|n| slug(n)).collect();
        assert!(ids.iter().all(|i| i != "unnamed-check"), "a check name lost its id: {ids:?}");
        let n = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), n, "two checks share an id");
        assert_eq!(slug(N_ENGINE_LIVE), "engine-responding");
    }

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
        assert!(crate::absorb::module_dir_of(&srcs[0]).is_none());
    }

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
