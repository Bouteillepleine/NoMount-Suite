//! `nomount doctor` — lint the mount plan before a reboot turns a bad rule into a bootloop.
//!
//! The checks below are not generic: each one encodes a failure this engine (or the
//! Android platform underneath it) actually produces, so a clean run means something.
//! The plan is resolved by [`crate::mount::collect_plan`], i.e. the *same* decisions the
//! mount pass will make — following the "detect conflicts at plan time, not randomly at
//! boot" approach the other mount metamodules settled on.
//!
//! Live rules are cross-checked too when the engine is up, because some hazards can only
//! come from a hand-written `nm add` (the plan can no longer produce them).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::mount::{collect_plan, PlanEntry, PlanKind};
use crate::nm::{LiveRule, Nm};

/// Partitions whose file descriptors zygote will accept across `forkSystemServer`.
///
/// `FileDescriptorInfo::CreateFromFd` validates every open FD against this set when
/// zygote forks system_server. An RRO overlay APK served from anywhere else (OnePlus/Oppo
/// ship `/my_product/cust/<region>/overlay/…` twins) aborts the fork with
/// `JNI FatalError: Not allowlisted` *before* system_server or OMS ever runs — an
/// unrecoverable early bootloop with no useful logcat.
const ZYGOTE_FD_ALLOWLISTED: &[&str] = &[
    "system", "product", "vendor", "system_ext", "odm", "apex", "oem",
];

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Error,
    Warn,
    /// Worth printing, not worth acting on. Kept out of the warning count so a
    /// standing observation about a working configuration cannot bury a real one.
    Info,
}

struct Finding {
    level: Level,
    check: &'static str,
    detail: String,
}

/// What a hidden caller sees at a ghosted path. Ordered by severity.
#[derive(PartialEq)]
enum GhostSeen {
    /// Indistinguishable from a path that does not exist. What _ghost is for.
    Absent,
    /// The path is VISIBLE to a uid the cloak claims to hide it from, so the
    /// cloak is lying about it: `stat` succeeds while the guarded syscalls
    /// answer ENOENT, a contradiction no real file can produce.
    Visible,
    /// Hidden from `stat`, but `getxattr(security.selinux)` still answers. The
    /// guards are compiled in and not effective -- the shape a kernel takes when
    /// the patch applied but the wrapper it targets is not the one this tree
    /// actually routes through.
    XattrLeak,
    Unknown,
}

/// Become `uid` in a forked child and look at `path`. READ-ONLY: `stat` and
/// `lgetxattr` only, never the write-ish members of the oracle class -- those
/// are safe on a read-only ROM and unsafe anywhere else, and a check that has to
/// reason about which one it is on does not belong in a linter.
///
/// This exists because _ghost is boot-proven on 6.12 alone; 6.6, 6.1, 5.15 and
/// 5.10 are only apply- and compile-verified, and no amount of CI can close that
/// gap. The device can: the guards are inert until the tables are populated, so
/// what is genuinely unknown on those kernels is not whether they boot but
/// whether the cloak WORKS. That is a question the running kernel can be asked.
fn ghost_seen_by(uid: u32, path: &Path) -> GhostSeen {
    use std::os::unix::ffi::OsStrExt;
    let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return GhostSeen::Unknown;
    };
    let Ok(attr) = std::ffi::CString::new("security.selinux") else {
        return GhostSeen::Unknown;
    };
    // Exit statuses, because the answer has to cross a fork.
    const ABSENT: i32 = 0;
    const VISIBLE: i32 = 1;
    const XLEAK: i32 = 2;
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return GhostSeen::Unknown;
        }
        if pid == 0 {
            // Supplementary groups FIRST, then gid, then uid. Each step needs
            // the privilege the next one drops. Without setgroups the child keeps
            // root's group list, so a path readable through one of those groups
            // stats OK here and not for a real app -- reported as an over-reach
            // that is not one. The error is in the safe direction (a false alarm,
            // never a false pass), which is exactly why it would have survived.
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setresgid(uid, uid, uid) != 0
                || libc::setresuid(uid, uid, uid) != 0
            {
                libc::_exit(3);
            }
            let mut st: libc::stat = std::mem::zeroed();
            if libc::stat(cpath.as_ptr(), &mut st) == 0 {
                libc::_exit(VISIBLE);
            }
            let mut buf = [0u8; 256];
            let n = libc::lgetxattr(
                cpath.as_ptr(),
                attr.as_ptr(),
                buf.as_mut_ptr().cast(),
                buf.len(),
            );
            libc::_exit(if n >= 0 { XLEAK } else { ABSENT });
        }
        let mut status: i32 = 0;
        if libc::waitpid(pid, &mut status, 0) < 0 || !libc::WIFEXITED(status) {
            return GhostSeen::Unknown;
        }
        match libc::WEXITSTATUS(status) {
            ABSENT => GhostSeen::Absent,
            VISIBLE => GhostSeen::Visible,
            XLEAK => GhostSeen::XattrLeak,
            _ => GhostSeen::Unknown,
        }
    }
}

/// Split `nm l g` output into its two tables.
fn parse_ghost_tables(txt: &str) -> (Vec<PathBuf>, Vec<u32>) {
    let mut paths = Vec::new();
    let mut uids = Vec::new();
    for line in txt.lines() {
        let line = line.trim();
        if let Some(p) = line.strip_prefix("p ") {
            if p.starts_with('/') {
                paths.push(PathBuf::from(p));
            }
        } else if let Some(u) = line.strip_prefix("u ") {
            if let Ok(v) = u.trim().parse::<u32>() {
                uids.push(v);
            }
        }
    }
    (paths, uids)
}

fn partition_of(p: &Path) -> Option<String> {
    p.components()
        .nth(1)
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
}

fn is_partition_root(p: &Path) -> bool {
    p.components().skip(1).count() == 1
}

/// Parse `nm list` output into typed rules.
///
/// The parsing itself is [`crate::nm::parse_list`], which every reader of that
/// text now shares -- this file's copy, `mount`'s and `absorb`'s had already
/// drifted apart on how a line is split and which suffixes are peeled. Doctor
/// keeps every row, whatever its kind: the partition-root check below has to see
/// whiteouts and virtual dirs too, which the pre-typed parser dropped.
fn parse_live(list: &str) -> Vec<LiveRule> {
    crate::nm::parse_list(list)
}


/// One `.replace` marker or opaque dir expands into a whiteout per stock entry the
/// module does not ship (see `mount::expand_replacement`), so a single marker can
/// be responsible for a great many rules. Group them by the marker that produced
/// them: every whiteout from one expansion carries that marker as its `source`,
/// while a 0:0 char device is its own source and so always counts 1.
fn expansions_by_marker(plan: &[PlanEntry]) -> Vec<(&Path, &str, usize)> {
    let mut by: HashMap<&Path, (&str, usize)> = HashMap::new();
    for e in plan.iter().filter(|e| e.kind == PlanKind::Whiteout) {
        let slot = by.entry(e.source.as_path()).or_insert((e.module.as_str(), 0));
        slot.1 += 1;
    }
    let mut v: Vec<(&Path, &str, usize)> =
        by.into_iter().map(|(m, (module, n))| (m, module, n)).collect();
    // Widest first, and by path for a stable order when counts tie.
    v.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(b.0)));
    v
}

/// Report threshold for one marker's expansion.
///
/// Deliberately a REPORT and not a cap. Refusing to expand past some N would leave
/// the module looking applied while the stock entries past the cutoff still showed
/// through -- silent truncation, which is the failure this project refuses to ship
/// elsewhere. So the count is surfaced and the expansion happens in full.
///
/// The numbers are calibrated against a stock OP15, which runs ~258 rules total:
/// `.replace` on `/system/app` is 15 entries, on `/product/app` 75, but a FLAT
/// directory is the pathological case -- `/system/fonts` is 224 and
/// `/product/overlay` 217, either of which would roughly double the rule count
/// from a single marker.
fn expansion_level(count: usize) -> Option<Level> {
    match count {
        0..=49 => None,
        50..=199 => Some(Level::Info),
        _ => Some(Level::Warn),
    }
}

/// A way a module can be incompatible with this environment, and why.
///
/// One scanner for three findings that share a shape: something the module's
/// own scripts do that cannot work here, where the failure is silent. Silence
/// is the whole problem -- a module that copies into /system gets no error, it
/// just carries on believing it worked, and the user is left with a feature
/// that does nothing and no way to know why.
///
/// Measured across 576 real module payloads to size each one.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Incompat {
    /// Writes into a ROM partition at runtime. 5.9% of the corpus.
    RomWrite,
    /// Reads through Magisk's mirror. 23% of the corpus mentions it.
    ///
    /// NOT a NoMount limitation, and the finding says so: there is no mirror on
    /// KernelSU at all -- no `/sbin/.magisk`, no `magisk` binary -- so these
    /// modules read nothing on a KSU device with or without NoMount. Reported
    /// because the user still ends up with a module that silently does nothing,
    /// and nothing else on the device will tell them why.
    MagiskMirror,
    /// Loop-mounts an image or runs a chroot. 6.2% of the corpus.
    ///
    /// No redirection can make a block device appear, so this is not something
    /// the VFS engine will ever serve. The module keeps its own mount and
    /// `posture` reports it honestly -- the point of naming it here is that the
    /// mount is then explained rather than anonymous.
    ImageBacked,
}

impl Incompat {
    fn check(self) -> &'static str {
        match self {
            Incompat::RomWrite => "writes into a ROM partition",
            Incompat::MagiskMirror => "needs Magisk's mirror",
            Incompat::ImageBacked => "image-backed or chroot module",
        }
    }

    fn explain(self) -> &'static str {
        match self {
            Incompat::RomWrite =>
                "NoMount serves ROM paths by read-only redirection, so this write goes \
                 nowhere the module can read back and will fail silently. Expect that \
                 feature of the module not to work.",
            Incompat::MagiskMirror =>
                "there is no Magisk mirror on KernelSU -- no /sbin/.magisk and no magisk \
                 binary -- so this read returns nothing, with or without NoMount. This is \
                 a Magisk-only module running on KSU, not something NoMount broke.",
            Incompat::ImageBacked =>
                "no path redirection can make a block device appear, so the engine cannot \
                 serve this. The module keeps its own mount; `posture` will report it, and \
                 that report is correct rather than a leak.",
        }
    }
}

/// Scan enabled modules' scripts for the three incompatibilities above.
///
/// Deliberately narrow, because the obvious patterns over-count badly and were
/// measured doing so:
///
///   * `$MODPATH/system/...` is how 56% of modules build their payload and is
///     completely fine. The ROM-write match therefore requires whitespace before
///     the leading slash, which `$MODPATH/system/` cannot satisfy.
///   * `mount -o rw,remount $MAGISKTMP` remounts the module's OWN tmpfs, not a
///     ROM partition -- nine corpus modules do it. The remount arm requires the
///     target to name a partition.
///   * Merely assigning `MAGISKTMP=` is boilerplate; 50 of 182 corpus matches
///     never path into the mirror at all. The mirror arm requires a path
///     component after it.
///
/// One finding per (module, kind), not one per line.
fn scan_module_incompat() -> Vec<(String, String, Incompat, String)> {
    const PARTS: [&str; 5] = ["system", "vendor", "product", "system_ext", "odm"];
    const SCRIPTS: [&str; 5] = [
        "post-fs-data.sh", "service.sh", "boot-completed.sh", "post-mount.sh", "customize.sh",
    ];
    let mut out: Vec<(String, String, Incompat, String)> = Vec::new();
    let Ok(dirs) = std::fs::read_dir(crate::mount::MODULES_DIR) else { return out };
    let mut dirs: Vec<_> = dirs.flatten().collect();
    dirs.sort_by_key(|e| e.file_name());

    for d in dirs {
        let mdir = d.path();
        if !mdir.is_dir() || !crate::mount::module_enabled(&mdir) {
            continue;
        }
        let Some(id) = mdir.file_name().and_then(|n| n.to_str()).map(str::to_string) else {
            continue;
        };
        let mut seen: Vec<Incompat> = Vec::new();
        for script in SCRIPTS {
            let Ok(body) = std::fs::read_to_string(mdir.join(script)) else { continue };
            for line in body.lines() {
                let t = line.trim();
                if t.starts_with('#') || t.is_empty() {
                    continue;
                }
                let kind = if (["cp ", "mv ", "ln ", "touch ", "rm "]
                    .iter()
                    .any(|v| t.contains(v))
                    && PARTS.iter().any(|p| t.contains(&format!(" /{p}/"))))
                    || (t.contains("remount")
                        && PARTS.iter().any(|p| {
                            t.contains(&format!(" /{p} ")) || t.ends_with(&format!(" /{p}"))
                        }))
                {
                    Some(Incompat::RomWrite)
                } else if t.contains(".magisk/mirror/")
                    || (t.contains("MAGISKTMP") && t.contains("/mirror"))
                    || t.contains("mirror/system")
                    || t.contains("mirror/vendor")
                {
                    Some(Incompat::MagiskMirror)
                } else if t.contains("losetup")
                    || t.contains("mount -o loop")
                    || t.contains("mkfs.ext4")
                    || t.contains("chroot ")
                    || t.contains("proot ")
                    || t.contains("nsenter")
                    || t.contains("unshare ")
                {
                    Some(Incompat::ImageBacked)
                } else {
                    None
                };
                if let Some(k) = kind {
                    if !seen.contains(&k) {
                        seen.push(k);
                        out.push((
                            id.clone(),
                            script.to_string(),
                            k,
                            t.chars().take(90).collect(),
                        ));
                    }
                }
            }
        }

        // A shipped filesystem image, with nothing in the scripts to match on.
        //
        // Everything above reads script TEXT, so a module that ships a prebuilt
        // rootfs and mounts it from a compiled binary, a helper the scan does not
        // read, or an init script would go unreported.
        //
        // Honest impact: ZERO modules in the 576-payload corpus need this. The
        // single module there that ships a real .img also says `losetup` in its
        // scripts, so the text rule already had it. It was added on the strength
        // of a corpus signal that counted .tar.gz as a filesystem image, and once
        // that was corrected the case it was meant to cover evaporated.
        //
        // Kept anyway, at depth 2 rather than a full walk: doctor reading only
        // script text is a real hole in its coverage, and this closes it for
        // roughly the cost of a readdir. Delete it without hesitation if the
        // cost ever shows up -- nothing measured depends on it.
        //
        // Only if the module did not already report ImageBacked from its scripts;
        // saying it twice for one module helps nobody.
        if !seen.contains(&Incompat::ImageBacked) {
            if let Some(img) = find_shipped_image(&mdir, 0) {
                out.push((id.clone(), "shipped file".to_string(), Incompat::ImageBacked, img));
            }
        }
    }
    out
}

/// First filesystem image found in a module tree, as a module-relative path.
///
/// Depth 2, not a full walk. A module that ships an image puts it at the top
/// level or one directory down; walking a large module tree to depth 6 on every
/// `doctor` run costs real I/O to find nothing. Extensions only -- sniffing
/// magic bytes would mean opening every file in every module on every run.
fn find_shipped_image(dir: &std::path::Path, depth: u32) -> Option<String> {
    const IMG_EXT: [&str; 6] = [".img", ".img.xz", ".img.gz", ".rootfs", ".ext4", ".erofs"];
    if depth > 2 {
        return None;
    }
    let entries = std::fs::read_dir(dir).ok()?;
    let mut dirs = Vec::new();
    for e in entries.flatten() {
        let ft = match e.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        // file_type does not follow symlinks, which is what keeps a link back up
        // the tree from being descended.
        if ft.is_dir() {
            dirs.push(e.path());
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let name = e.file_name();
        let name = name.to_string_lossy().to_lowercase();
        if IMG_EXT.iter().any(|x| name.ends_with(x)) {
            return Some(e.file_name().to_string_lossy().into_owned());
        }
    }
    for d in dirs {
        if let Some(found) = find_shipped_image(&d, depth + 1) {
            return Some(found);
        }
    }
    None
}

pub fn run_doctor(json: bool) -> Result<()> {
    // partition -> count of non-overlay entries not in zygote's FD allowlist
    let mut fd_note: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut f: Vec<Finding> = Vec::new();
    let (plan, skipped) = collect_plan()?;

    // ---- plan-level checks -------------------------------------------------
    let mut by_target: HashMap<&Path, Vec<&str>> = HashMap::new();
    let mut holes: HashMap<&str, Vec<&Path>> = HashMap::new();
    for e in &plan {
        by_target
            .entry(e.target.as_path())
            .or_default()
            .push(e.module.as_str());

        // A rule on a bare partition root redirects/masks the WHOLE partition, hiding
        // every stock entry under it. Fatal for a whiteout just as much as an inject, so
        // this is checked for both kinds (a whiteout on a root was previously unguarded).
        if is_partition_root(&e.target) {
            f.push(Finding {
                level: Level::Error,
                check: "partition-root target",
                detail: format!(
                    "{} would {} all of {}",
                    e.module,
                    if e.kind == PlanKind::Whiteout { "hide" } else { "replace" },
                    e.target.display()
                ),
            });
        }

        // Only where a hole genuinely REMAINS: from engine v13 a single-block
        // erofs parent is recomputed, so reporting those would cry wolf on the
        // debloat case -- the very one the fix made clean.
        // Collected, not emitted here: one `.replace` can expand into hundreds of
        // whiteouts, and a line each buried every other finding under its own output
        // (236 informational lines on a single probe). Grouped per module below.
        if e.kind == PlanKind::Whiteout && crate::mount::whiteout_leaves_hole(&e.target) {
            holes.entry(e.module.as_str()).or_default().push(e.target.as_path());
        }

        if e.kind == PlanKind::Inject {
            // Backing gone (module updated/removed underneath us) -> rule serves nothing.
            // `exists()` follows symlinks, so a DANGLING symlink lands here too — and
            // reporting that as "source missing" sends the reader to a path that is
            // plainly there in `ls`. Injection resolves a symlink to its target, so a
            // link with no target yields no rule at all: `plan` lists the entry and
            // `reload` counts it, then the path simply never appears. Name which of
            // the two it is, because the fixes differ.
            if !e.source.exists() {
                let detail = match fs::symlink_metadata(&e.source) {
                    Ok(m) if m.file_type().is_symlink() => {
                        let dest = fs::read_link(&e.source).unwrap_or_default();
                        format!(
                            "{} -> {} is a symlink to {}, which does not exist. Injection \
                             serves a link's TARGET, so this produces no rule and the path \
                             never appears — an installer that symlinks before its target \
                             lands hits this",
                            e.target.display(),
                            e.source.display(),
                            dest.display()
                        )
                    }
                    _ => format!("{} -> {} (source missing)", e.target.display(), e.source.display()),
                };
                f.push(Finding { level: Level::Error, check: "missing backing", detail });
            }
        }

        // Target on a partition this device doesn't have -> silently dead rule.
        if let Some(part) = partition_of(&e.target) {
            if !Path::new(&format!("/{part}")).is_dir() {
                f.push(Finding {
                    level: Level::Warn,
                    check: "no such partition",
                    detail: format!("{} targets /{} which does not exist", e.module, part),
                });
            }
        }
    }

    // MODULE-LEVEL rollup, kept but inverted: with the policy flip nothing is
    // declined, so the question is no longer "does this module work" but "how
    // much detectable surface does it add". Reported per module because that is
    // the unit a user installs and can uninstall.
    let mut per_mod: HashMap<&str, usize> = HashMap::new();
    for e in &plan {
        if e.kind == PlanKind::Whiteout && crate::mount::whiteout_leaves_hole(&e.target) {
            *per_mod.entry(e.module.as_str()).or_default() += 1;
        }
    }
    let mut rolled: Vec<(&str, usize)> = per_mod.into_iter().collect();
    rolled.sort_by_key(|(m, _)| *m);
    for (module, n) in rolled {
        f.push(Finding {
            level: Level::Info,
            check: "module hides where the hole remains",
            detail: format!(
                "{module} hides {n} path(s) the engine cannot fully mask (their folder spans several \
             blocks). Uninstall it or move its targets if that matters."
            ),
        });
    }

    // A target whose first two segments repeat a partition name -- /product/product,
    // /system/system -- is not something a module can mean. It comes from the
    // installer's partition handler moving `system/product` INTO an already-existing
    // top-level `product/` instead of merging the two, which nests the subtree one
    // level too deep. The rule that results serves real bytes at a directory the ROM
    // does not have, which is both wrong and a free existence oracle, and nothing
    // downstream notices because every individual rule looks healthy.
    //
    // Measured on an OP15: a module shipping BOTH `product/` and `system/product/`
    // produced `/product/product/etc/...` and doctor reported zero errors. A module
    // shipping only `system/product/` resolves correctly, so the trigger is the
    // collision, not the SAR alias.
    let mut nested: Vec<(&Path, &str)> = Vec::new();
    for e in &plan {
        let mut segs = e.target.components().skip(1).filter_map(|c| c.as_os_str().to_str());
        if let (Some(a), Some(b)) = (segs.next(), segs.next()) {
            if a == b && is_partition_root(Path::new(&format!("/{a}"))) {
                nested.push((e.target.as_path(), e.module.as_str()));
            }
        }
    }
    nested.sort_by_key(|(t, _)| *t);
    for (target, module) in &nested {
        f.push(Finding {
            level: Level::Error,
            check: "partition name nested",
            detail: format!(
                "{} <- {module}: the path repeats a partition name, so this is serving \
                 content at a directory the ROM does not have. It happens when a module \
                 ships both `product/` and `system/product/` and the installer nests one \
                 inside the other -- ship only one of the two.",
                target.display()
            ),
        });
    }

    // A directory whose every entry is injected is its own detection oracle.
    //
    // Injected files carry inode numbers from a band the ROM never allocates
    // from. In a directory that also holds stock files that is harmless -- the
    // stock inodes are camouflage. In a directory the module invented, every
    // inode is in the injected band, so bucketing that directory by inode range
    // yields one bucket that is entirely ours and names every file in it.
    //
    // `audit` already measures this, but only after the fact, on a device that
    // has already booted with the module. Saying it here means the user learns
    // at install time, when moving the files into an existing directory is still
    // an easy change.
    //
    // The stock/injected test works whether or not the engine is live: with
    // rules applied, read_dir returns the synthesised listing (ours only, if the
    // directory is wholly new); without them it returns the stock listing, or
    // fails outright when the directory does not exist yet. In every case, "no
    // entry here that is not one of ours" is the question worth asking.
    let served: Vec<&Path> = plan
        .iter()
        .filter(|e| e.kind != PlanKind::Whiteout) // whiteouts hide, they materialise nothing
        .map(|e| e.target.as_path())
        .collect();

    // Is this path one we serve, or a directory on the way down to one? A
    // sub-DIRECTORY that only holds injections is not stock camouflage, and
    // treating it as one is what made a first cut miss `/system/etc/nmt`
    // entirely: it saw the `nested/` child, did not recognise it as ours, and
    // called the directory mixed.
    let ours = |p: &Path| served.iter().any(|t| *t == p || t.starts_with(p));

    // An APK has to live in a directory of its own -- that is the layout
    // PackageManager requires, and stock `/system/priv-app/Mms` holds nothing
    // but `Mms.apk` either. Flagging those would be advice with no available
    // remedy, so they are deliberately not reported.
    // The whole codePath, not just the directory holding the .apk.
    //
    // An app's native libraries live at <codePath>/lib/<abi>, which is two levels
    // below priv-app, and PackageManager decides that layout -- the module has no
    // more choice about it than it has about the .apk's own directory. Measured on
    // an OP11: all 29 rules under /product/priv-app/Mms are served --public,
    // because mount.rs already treats the codePath as one unit for the public
    // flag. Checking only the immediate parent flagged Mms/lib/arm64 and left a
    // warning nobody could act on.
    let is_apk_container = |p: &Path| {
        p.ancestors().any(|a| {
            a.parent().and_then(|g| g.file_name()).is_some_and(|n| {
                matches!(n.to_str(), Some("app" | "priv-app" | "overlay" | "framework"))
            })
        })
    };

    let mut invented: HashMap<PathBuf, (Vec<String>, usize)> = HashMap::new();
    for e in &plan {
        if e.kind == PlanKind::Whiteout {
            continue;
        }
        let Some(parent) = e.target.parent() else { continue };
        if is_partition_root(parent) || parent.parent().is_none() || is_apk_container(parent) {
            continue;
        }
        let has_stock = match fs::read_dir(parent) {
            Ok(rd) => rd.flatten().any(|d| !ours(&parent.join(d.file_name()))),
            // Does not exist yet: once the pass runs, nothing but ours is in it.
            Err(_) => false,
        };
        if has_stock {
            continue;
        }
        let slot = invented.entry(parent.to_path_buf()).or_insert((Vec::new(), 0));
        // (count accumulates below; the single-file case is filtered after)
        slot.0.push(e.module.clone());
        slot.1 += 1;
    }

    // Report the SHALLOWEST invented directory of a chain. A module shipping
    // `etc/foo/bar/baz/x` invents four directories, and naming all four says the
    // same thing four times -- the actionable unit is the top of the new subtree.
    // One injected file in a directory is not an inode BAND -- it is one inode,
    // and a single number cannot be grouped against anything.
    //
    // This matters because the common shape is not an invented directory, it is a
    // SHADOWED one: OnePlus_Dialer_Universal replaces the single stock file in each
    // of 80 country directories under /my_product/etc/extension. Stock has one file
    // there, the module serves one file there, and the directory looks exactly as
    // the ROM shipped it. Reporting that as "holds only injected files" is true by
    // the letter and useless: there is nothing to bucket, the module has no other
    // layout available, and `audit`'s own inode-band check declines the case
    // ("no directory with both enough injections and a stock population to
    // compare") -- so the finding cited a measurement that does not apply to it.
    //
    // Threshold matches what the oracle actually needs: the harness directory it
    // did fire on had 3 injected inodes alone in a band, with no stock there.
    invented.retain(|_, (_, n)| *n > 1);

    let invented_dirs: std::collections::HashSet<PathBuf> = invented.keys().cloned().collect();
    let mut rolled: Vec<(PathBuf, Vec<String>, usize)> = invented
        .into_iter()
        // Every ancestor, not just the immediate parent: a chain like
        // `nmt/nested/deep/a/b` has intermediate levels that hold no file of
        // their own, so they never enter the map and checking one level up
        // finds no ancestor to roll into.
        .filter(|(p, _)| !p.ancestors().skip(1).any(|a| invented_dirs.contains(a)))
        .map(|(p, (mods, n))| {
            // Count everything served underneath, not just the immediate level,
            // so a rolled-up chain reports the size of the whole subtree.
            let total = served.iter().filter(|t| t.starts_with(&p)).count();
            let mut m = mods;
            m.sort_unstable();
            m.dedup();
            (p, m, total.max(n))
        })
        .collect();
    rolled.sort_by(|a, b| a.0.cmp(&b.0));

    if !rolled.is_empty() {
        // One finding, not one per directory. The explanation is the same every
        // time and repeating it buries the list it is about.
        // Group by owning module before listing anything.
        //
        // Listing every directory reads fine on a handful and is unusable on a
        // real device: measured on an OP15, OnePlus_Dialer_Universal ships one
        // country-config file into each of 82 sibling directories under
        // /my_product/etc/extension, and naming them individually produced a
        // 6042-character finding that says the same thing 82 times. The module
        // is the actionable unit -- there is one decision to make about it, not
        // 82 -- so a module with more than a few directories is reported as its
        // common prefix and a count.
        // Key on (module, PARENT of the flagged directory), not on the module
        // alone. A module that owns 78 country dirs under one parent and three
        // more elsewhere has a longest-common-ancestor of "/", and "81
        // directories under /" tells the reader nothing. Clustering by parent
        // names the subtree each group actually sits in.
        let mut by_mod: HashMap<String, Vec<(&Path, usize)>> = HashMap::new();
        for (p, m, n) in &rolled {
            let parent = p.parent().unwrap_or(Path::new("/")).display();
            by_mod
                .entry(format!("{} under {}", m.join(", "), parent))
                .or_default()
                .push((p.as_path(), *n));
        }
        let mut groups: Vec<(String, Vec<(&Path, usize)>)> = by_mod.into_iter().collect();
        groups.sort_by(|a, b| a.0.cmp(&b.0));

        let list = groups
            .iter()
            .map(|(mods, dirs)| {
                let files: usize = dirs.iter().map(|(_, n)| n).sum();
                if dirs.len() <= 3 {
                    let names = dirs
                        .iter()
                        .map(|(p, n)| format!("{} ({n} file(s))", p.display()))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("{mods}: {names}")
                } else {
                    // Longest common ancestor of the group, so the message points
                    // at the subtree the module actually owns.
                    let mut prefix: Vec<&std::ffi::OsStr> =
                        dirs[0].0.iter().collect();
                    for (p, _) in dirs.iter().skip(1) {
                        let other: Vec<&std::ffi::OsStr> = p.iter().collect();
                        let keep = prefix
                            .iter()
                            .zip(other.iter())
                            .take_while(|(a, b)| a == b)
                            .count();
                        prefix.truncate(keep);
                    }
                    let _ = &prefix; // parent is already in the group key
                    format!("{mods}: {} directories ({files} file(s) total)", dirs.len())
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        f.push(Finding {
            level: Level::Warn,
            check: "directory holds only injected files",
            detail: format!(
                "{list}. Injected files carry inode numbers from a band the ROM never \
                 allocates from, so a directory holding several of them and no stock file \
                 groups into one bucket that is entirely yours. Shipping into a directory \
                 that already has stock content removes the tell. `audit`'s \"injected \
                 inode band\" check may call this not-applicable: it compares against stock \
                 inodes in the SAME directory and there are none here, while a detector \
                 comparing against the partition's range does not need them. Single-file \
                 directories and app/priv-app/overlay containers are excluded — one inode \
                 is not a bucket, and an APK cannot share a directory."
            ),
        });
    }

    // Modules that cannot work here, named before the user goes hunting.
    //
    // All three of these fail SILENTLY today: the write lands nowhere, the
    // mirror read returns nothing, the image mount is simply a mount the engine
    // never touches. Each is shipped as a loud finding well before any attempt
    // to support it, because a wrong answer the user can see beats a wrong
    // answer they cannot.
    for (module, script, kind, hit) in scan_module_incompat() {
        f.push(Finding {
            level: Level::Warn,
            check: kind.check(),
            detail: format!("{module} ({script}): `{hit}`. {}", kind.explain()),
        });
    }

    // Two modules writing the same path: the plan is sorted and only the last is
    // applied, so the winner is stable -- but the loser's content is simply absent.
    let mut collisions: Vec<(&Path, Vec<&str>)> = by_target
        .into_iter()
        .filter(|(_, m)| {
            let mut u: Vec<&&str> = m.iter().collect();
            u.sort_unstable();
            u.dedup();
            u.len() > 1
        })
        .collect();
    collisions.sort_by_key(|(t, _)| *t);
    for (target, mods) in &collisions {
        let mut m = mods.clone();
        m.sort_unstable();
        m.dedup();
        f.push(Finding {
            level: Level::Warn,
            check: "target claimed twice",
            detail: format!("{} <- {}", target.display(), m.join(", ")),
        });
    }

    // Stale entries in the legacy `blocklist` file. blocklist.rs migrates app
    // names out of it into `uidhide` but deliberately COPIES rather than moves --
    // deleting an entry that really is a module id would let a self-mounting
    // module inject and break boot, which is the worse mistake. The cost is that
    // the leftovers are invisible: mount.rs reads that file as a module-id skip
    // list, so a module whose id happens to match a hidden package would be
    // silently skipped, and nothing would say so. Report them instead of
    // deleting them. Measured on OP15 2026-08-21: four package names still there.
    if let Ok(raw) = std::fs::read_to_string("/data/adb/nomount/blocklist") {
        let hidden: std::collections::HashSet<String> =
            crate::blocklist::read().unwrap_or_default().into_iter().collect();
        let stale: Vec<String> = raw
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter(|l| !Path::new("/data/adb/modules").join(l).is_dir())
            .filter(|l| hidden.contains(*l))
            .map(str::to_string)
            .collect();
        if !stale.is_empty() {
            // The names are hidden-app package names -- the same secret as the hide
            // list. When `nomount export` runs doctor for shared storage it sets
            // NM_REDACT_HIDE_LIST=1, so print the count only there (health.rs owns
            // the destination decision; see M-S2).
            let redact = std::env::var_os("NM_REDACT_HIDE_LIST").is_some();
            let names = if redact {
                "names redacted".to_string()
            } else {
                stale.join(", ")
            };
            f.push(Finding {
                level: Level::Info,
                check: "stale legacy blocklist entries",
                detail: format!(
                    "{} entry/entries in /data/adb/nomount/blocklist are hidden APPS ({}). They moved \
                 to `uidhide` and do nothing here. Remove them if you want that file to mean only \
                 \"skip this module\".",
                    stale.len(),
                    names
                ),
            });
        }
    }

    // The root manager's own "umount modules" switch. With the Suite this is
    // inert -- injection is a VFS redirect, not a mount, so there is nothing for
    // it to unmount and the kernel's umount list stays empty. Users reach for it
    // expecting it to hide modules, which it cannot do here, and on this build
    // enabling it once cost ~8 reboots: su used to arrive as a module overlay,
    // so anything stripping module content stripped su with it. The Suite keeps
    // su out entirely now (kernel sucompat), but there is still no upside.
    let kernel_umount = crate::manager::kernel_umount_enabled();
    if kernel_umount == Some(true) {
        f.push(Finding {
            level: Level::Warn,
            check: "manager kernel umount ON",
            detail: "manager \"Kernel umount\" is ON — it hides nothing here (injections are \
                     not mounts). Turn it OFF; use `nomount uid block <uid>` per app."
                .to_string(),
        });
    }

    // The GLOBAL "Umount modules by default". This is the dangerous one: it
    // strips module content from every app WITHOUT a profile, which in July
    // included any app the moment it asked for root, and that is what broke root
    // on this device. Warned above kernel_umount's own finding because enabling
    // kernel_umount is what silently turned THIS on.
    let global_umount = crate::manager::global_umount_default();
    if global_umount == Some(true) {
        f.push(Finding {
            level: Level::Warn,
            check: "manager global umount ON",
            detail: "manager \"Umount modules by default\" is ON — strips module content from \
                     every profile-less app and hides nothing here. Turn it OFF"
                .to_string(),
        });
    }

    // Per-app "umount modules" profiles. Read from the allowlist rather than
    // guessed: the layout is verified against known uids before it is trusted,
    // and a decode that stops making sense yields nothing instead of invented
    // flags. Info, not warn -- these are harmless here, just pointless.
    let flags = crate::manager::app_umount_flags();
    if let Some(flags) = &flags {
        let umounters: Vec<&str> =
            flags.iter().filter(|a| a.umount_modules).map(|a| a.package.as_str()).collect();
        if !umounters.is_empty() {
            let shown: Vec<&str> = umounters.iter().take(2).copied().collect();
            f.push(Finding {
                level: Level::Info,
                check: "per-app umount profiles",
                detail: format!(
                    "{} app(s) have an \"umount modules\" profile ({}{}) — harmless here, hides \
                     nothing we inject",
                    umounters.len(),
                    shown.join(", "),
                    if umounters.len() > shown.len() { ", …" } else { "" }
                ),
            });
        }
    }

    // ...and say so when we could NOT read it. The two checks above are silent
    // both when the switches are off and when the allowlist is missing, truncated,
    // or its record layout has moved, and those render identically to a reader who
    // then concludes the dangerous global is off. It is the one this module's
    // header says must never be guessed, and the one that broke root here in July.
    // Only when a KernelSU-family manager is actually installed: a manager that
    // keeps no allowlist has nothing to fail at reading.
    // kernel_umount.is_none() belongs here too: ksud missing, the exec failing, or
    // its output moving all render as "off" to a reader, and the WebUI banner keys
    // on THIS check's name so it stays hidden as well -- the precise argument the
    // detail text makes for the other two switches.
    // Name WHICH of the three signals could not be read, and say nothing about the
    // ones that could.
    //
    // The old text fired if any one of them was missing and then declared the
    // whole umount configuration unknown, telling the reader to check both
    // switches by hand. Measured on a CPH2645 running ksud 4.1.0: `kernel_umount`
    // read cleanly (Value: 0) and all 14 per-app profiles decoded — only the
    // global default was missing, because that version of ksud no longer writes
    // the `$`/9999 sentinel record the value lives in. So the finding sent its
    // reader to re-check two settings the Suite had already read, on the strength
    // of a third it had not. A diagnostic that overstates what it does not know
    // is the same defect as one that overstates what it does.
    // Written for whoever is looking at the card, not for whoever wrote the
    // parser. The previous text opened with "manager umount config unreadable"
    // and explained itself with "no sentinel record in .allowlist" -- an
    // implementation detail of a file format nobody outside this repo has read --
    // then said both "check it by hand" and "it hides nothing either way", which
    // leaves a reader unable to tell whether they should care. Name the setting
    // the way the manager's own UI names it, say what it does, say what to do,
    // and say that the note is permanent so nobody re-reads it every boot
    // wondering what they missed.
    let mut unread: Vec<&str> = Vec::new();
    if kernel_umount.is_none() {
        unread.push("\"Kernel umount\"");
    }
    if global_umount.is_none() {
        unread.push("\"Umount modules by default\"");
    }
    if flags.is_none() {
        unread.push("the per-app \"umount modules\" list");
    }
    if crate::manager::ksu_manager_present() && !unread.is_empty() {
        f.push(Finding {
            level: Level::Warn,
            check: "check a setting in your root manager",
            detail: format!(
                "Could not read your root manager's {} — so it is UNKNOWN, not off. That switch \
                 strips module files from apps and has broken root. NoMount never needs it: check \
                 it once, in the manager.",
                unread.join(" and "),
            ),
        });
    }

    // ---- live checks (engine up) ------------------------------------------
    let nm = Nm::new();
    let engine = nm.version().ok();
    let live_ok = engine.is_some();
    let mut live_count = 0usize;
    // Apps hidden from the injections, and the live rules the PackageManager
    // advertises regardless -- the pair the opt-out check below is about.
    let hidden_apps = crate::blocklist::read().unwrap_or_default();
    let mut pm_rules = 0usize;
    // PM-published rules live WITHOUT the `(public)` flag, i.e. still subject to
    // per-UID hiding despite the PackageManager advertising them. Only meaningful
    // on an engine that reports flags (>= 17); see the finding below.
    let mut pm_rules_no_public: Vec<PathBuf> = Vec::new();
    // An engine that is not responding means NOTHING below was verified -- yet the
    // only trace used to be the header line `live: engine not responding`, which
    // is not part of the summary the WebUI chip and the manager card parse. On a
    // mountless device with a clean plan that produced `no problems found` /
    // `summary: 0 errors, 0 warnings` and a green "healthy" chip. `health.rs`
    // reports ENGINE DOWN for the same condition; the greener surface was winning.
    if !live_ok {
        f.push(Finding {
            level: Level::Error,
            check: "engine not responding",
            detail: "the engine did not answer, so none of the live checks below ran. `live: 0 rules` \
                 means \"could not ask\", not \"no rules\". Flash the kernel and module as a set."
                .to_string(),
        });
    }
    if live_ok {
        // `if let Ok(..)` with no else: an engine that answered `v` but would not
        // ENUMERATE left live_count at 0, printed `live: 0 rules`, and skipped the
        // partition-root, FD-allowlist, size-mismatch and all three PM-published
        // checks -- rendering identically to "the engine has zero rules".
        let listed = nm.list();
        if let Err(e) = &listed {
            f.push(Finding {
                level: Level::Error,
                check: "engine rule dump failed",
                detail: format!(
                    "the engine answered, but listing its rules failed ({e:#}). The live rule checks did \
             not run: `live: 0 rules` means \"could not enumerate\", not \"none\"."
                ),
            });
        }
        if let Ok(list) = listed {
            let live = parse_live(&list);
            live_count = live.len();
            for r in &live {
                let target = &r.target;
                // Broadened from is_rom_apk: the opt-out now covers a package's whole
                // codePath (the nativeLibraryDir .so too), so count that.
                // INJECT rules only. `is_pm_published` tests the path, and a
                // whiteout is added with `nm w` which never carries --public, so
                // every whiteout on a PM-advertised path counted here and landed
                // in pm_rules_no_public. A `.replace` on /product/app expands to
                // ~75 of them, so doctor warned that 75 rules "get ENOENT on a
                // path the PackageManager advertises" -- which is a whiteout's
                // entire purpose. Unactionable, permanently amber, and it
                // inflated pm_rules in two other messages. audit.rs's
                // live_targets() was fixed for exactly this; this copy was not.
                if r.kind == crate::nm::LiveKind::Inject
                    && crate::pmcache::is_pm_published(target)
                {
                    pm_rules += 1;
                    if !r.public {
                        pm_rules_no_public.push(target.clone());
                    }
                }
                // Partition-root check applies to every kind (a whiteout on a root
                // masks the whole partition just as an inject does).
                if is_partition_root(target) {
                    f.push(Finding {
                        level: Level::Error,
                        check: "partition-root rule live",
                        detail: match &r.source {
                            Some(s) => format!("{} is redirected wholesale -> {}", target.display(), s.display()),
                            None => format!("{} ({:?}) masks the whole partition", target.display(), r.kind),
                        },
                    });
                }
                // The zygote FD-allowlist trap. Overlay APKs are the dangerous case because
                // zygote preloads them; flag anything else on such a partition as a warning.
                if let Some(part) = partition_of(target) {
                    if !ZYGOTE_FD_ALLOWLISTED.contains(&part.as_str()) {
                        let is_overlay_apk = target.extension().and_then(|x| x.to_str()) == Some("apk")
                            && target.components().any(|c| c.as_os_str() == "overlay");
                        if is_overlay_apk {
                            // The genuinely dangerous case: zygote preloads these and an
                            // identity mismatch aborts forkSystemServer. Always per-file.
                            f.push(Finding {
                                level: Level::Error,
                                check: "not FD-allowlisted",
                                detail: format!(
                                    "{} lives on /{part} — an overlay APK here aborts forkSystemServer",
                                    target.display()
                                ),
                            });
                        } else {
                            // Everything else on such a partition is the same observation
                            // repeated once per file. Emitting one warning per entry buried
                            // real findings under ~85 identical lines on a device that boots
                            // fine, so count them and report once per partition below.
                            *fd_note.entry(part).or_insert(0usize) += 1;
                        }
                    }
                }
                // Served content should be byte-identical in size to its backing; a mismatch
                // means the redirect is not actually being served. Injects only (a
                // whiteout/virtual-dir has no backing file to compare against).
                if let Some(source) = &r.source {
                    if let (Ok(a), Ok(b)) = (fs::metadata(target), fs::metadata(source)) {
                        if a.is_file() && b.is_file() && a.len() != b.len() {
                            f.push(Finding {
                                level: Level::Warn,
                                check: "size mismatch",
                                detail: format!(
                                    "{} is {} bytes, backing is {}",
                                    target.display(),
                                    a.len(),
                                    b.len()
                                ),
                            });
                        }
                    }
                }
            }
        }
    }

    // A PM-published file is the one injection the system advertises to an app
    // that is hidden from us: the PackageManager scans those directories as
    // system_server (never blocked), registers what it finds, and names the whole
    // codePath to every app that asks. `Nm::add` therefore serves them with the
    // hiding opt-out.
    //
    // From engine v17 the client PRINTS the per-rule `(public)` flag, so we can
    // name the exact rules missing it rather than inferring from the version. A
    // PM-published rule live without the flag on a v17+ engine means the opt-out
    // did not take, and the hidden app gets ENOENT on a path the PM says exists
    // (Trusteer SIGSEGVs). The engine is bumped 17 -> 18 this cycle and v18 keeps
    // the flag behaviour, so this is `>= 17`, not `== 17`.
    let engine_v = engine.unwrap_or(0);
    if live_ok && !hidden_apps.is_empty() && engine_v >= 17 && !pm_rules_no_public.is_empty() {
        let shown: Vec<String> =
            pm_rules_no_public.iter().take(3).map(|t| t.display().to_string()).collect();
        let more = pm_rules_no_public.len().saturating_sub(shown.len());
        f.push(Finding {
            level: Level::Warn,
            check: "PM-published rule not opted out of hiding",
            detail: format!(
                "engine v{engine_v}: {} rule(s) Android registered are hidden from your {} hidden \
                 app(s), so those apps get \"not found\" for a file Android says exists. Re-run \
                 the mount pass. {}{}",
                pm_rules_no_public.len(),
                hidden_apps.len(),
                shown.join(", "),
                if more > 0 { format!(", and {more} more") } else { String::new() }
            ),
        });
    }

    // Fallback for engines that do NOT report the flag (< 17): infer from the
    // version. `Nm::add` opts these rules out, but that flag only exists from
    // engine v15, and an older one strips it with every other unknown bit. The
    // result is silent: the rule applies, the app still gets ENOENT on a path the
    // PM says exists. Say so instead.
    if live_ok && !hidden_apps.is_empty() && pm_rules > 0 && engine_v < 15 {
        f.push(Finding {
            level: Level::Warn,
            check: "engine predates the hiding opt-out",
            detail: format!(
                "engine v{engine_v} is too old to exempt registered apps from hiding, so your {} \
                 hidden app(s) get \"not found\" for {pm_rules} file(s) Android says exist. That \
                 crashes apps that walk the package list. Update the kernel.",
                hidden_apps.len()
            ),
        });
    }

    // v15 gave an ADDED PM-published file the opt-out but the kernel stripped it
    // again from any rule that turned out to SHADOW a stock file, on the reasoning
    // that the blocked reader is served the stock bytes and is therefore
    // consistent. It is not: the PackageManager parsed the MODULE's copy as
    // system_server and publishes that version and signature for the path, so a
    // blocked reader handed the stock bytes disagrees with what the PM advertises.
    // Only the kernel knows which rules shadow, so gate on the version rather than
    // trying to count them here.
    //
    // 15..18, not 15..17: v17 SET the bit and printed it, but nothing acted on it
    // -- nm_stock_for_caller() still decided with the raw blocked-uid test, so a
    // v17 engine is observationally identical to v16. Excluding 17 here while the
    // `>= 17` check above sees a fully-flagged rule list meant a v17 device passed
    // BOTH checks clean while a blocked reader was still served stock bytes for a
    // shadowed PM-published file -- the exact inconsistency both exist to catch.
    if live_ok && !hidden_apps.is_empty() && pm_rules > 0 && (15..18).contains(&engine_v) {
        f.push(Finding {
            level: Level::Warn,
            check: "engine strips the opt-out from a replaced PM-published file",
            detail: format!(
                "engine v{engine_v} serves stock bytes to your {} hidden app(s) for any rule that \
                 REPLACES a ROM file, while Android advertises the module's version for it. \
                 Rebuild the kernel from kbuild@hookless >= 17.",
                hidden_apps.len()
            ),
        });
    }

    // _ghost: is the cloak telling the truth on THIS kernel?
    //
    // Two failures, and they need opposite responses. OVER-REACH is ours and it
    // is the dangerous one: a path that a hidden caller can still see must never
    // be in the table, because ghosting it makes one path answer stat=OK and
    // chmod=ENOENT at once -- louder than the oracle it replaces, and visible
    // without a control path. Shipped that way in v1.3.55-.57 with 259 of 260
    // entries wrong. INEFFECTIVE is the kernel's: guards compiled in that do not
    // fire, which is exactly what an untested 6.6/6.1/5.15/5.10 build might do
    // and what no CI can rule out.
    //
    // Sampled, not exhaustive: each path costs a fork, and the table is built by
    // one predicate, so a systematic error shows up in the first few. The count
    // is reported so a clean verdict cannot be mistaken for a full sweep.
    if live_ok && engine_v >= 26 {
        if let Ok(txt) = nm.ghost_list() {
            let (gpaths, guids) = parse_ghost_tables(&txt);
            if let (Some(&uid), false) = (guids.first(), gpaths.is_empty()) {
                const SAMPLE: usize = 16;
                let checked = gpaths.len().min(SAMPLE);
                let mut visible: Vec<&PathBuf> = Vec::new();
                let mut leaked: Vec<&PathBuf> = Vec::new();
                for p in gpaths.iter().take(SAMPLE) {
                    match ghost_seen_by(uid, p) {
                        GhostSeen::Visible => visible.push(p),
                        GhostSeen::XattrLeak => leaked.push(p),
                        _ => {}
                    }
                }
                let name = |v: &[&PathBuf]| -> String {
                    v.iter().take(3).map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
                };
                if !visible.is_empty() {
                    f.push(Finding {
                        level: Level::Error,
                        check: "ghost cloak over-reaches",
                        detail: format!(
                            "{} of {checked} sampled path(s) are still visible to hidden uid {uid} — they \
                 answer \"exists\" and \"does not exist\" at once, which is louder than the leak \
                 this closes. Re-run the mount pass: {}",
                            visible.len(),
                            name(&visible)
                        ),
                    });
                }
                if !leaked.is_empty() {
                    f.push(Finding {
                        level: Level::Warn,
                        check: "ghost cloak compiled in but not effective",
                        detail: format!(
                            "{} of {checked} sampled path(s) hide from `stat` but still leak their label — \
                 the guards are compiled in and not firing on this kernel: {}",
                            leaked.len(),
                            name(&leaked)
                        ),
                    });
                }
                if visible.is_empty() && leaked.is_empty() {
                    f.push(Finding {
                        level: Level::Info,
                        check: "ghost cloak verified on this kernel",
                        detail: format!(
                            "{checked} of {} hidden path(s) sampled: each looks exactly like a path that never \
             existed, to uid {uid}. Measured here, not assumed from the build.",
                            gpaths.len()
                        ),
                    });
                }
            }
        }
    }

    // ---- report ------------------------------------------------------------
    let injects = plan.iter().filter(|e| e.kind == PlanKind::Inject).count();
    let whiteouts = plan.iter().filter(|e| e.kind == PlanKind::Whiteout).count();
    let binds = plan.iter().filter(|e| e.kind == PlanKind::Bind).count();
    let modules = {
        let mut m: Vec<&str> = plan.iter().map(|e| e.module.as_str()).collect();
        m.sort_unstable();
        m.dedup();
        m.len()
    };
    // Suppressed under --json: stdout has to be one parseable object. The plan
    // refusals from collect_plan are already eprintln, so stderr is the only
    // other writer and the caller keeps the two apart.
    if !json {
        println!(
            "nomount doctor: {modules} modules planned | {injects} injects, {whiteouts} whiteouts, \
             {binds} my_* binds, {skipped} blocklisted | live: {}",
            if live_ok {
                format!("{live_count} rules")
            } else {
                "engine not responding".to_string()
            }
        );
    }

    f.sort_by(|a, b| a.level.cmp(&b.level).then(a.check.cmp(b.check)));
    // Any module-backed mount still standing is an app-visible detection surface:
    // it is the one thing the mountless posture exists to deny, and after absorb
    // has run the only ones left are those deliberately skipped. Report them, so
    // opting out of absorption is a visible trade rather than a silent one.
    // A mount left standing on purpose is an observation, not a warning: absorb is
    // never going to take it, so there is nothing to act on. Only a mount that
    // nothing declined is worth flagging — that one means absorb has not run or
    // could not do its job.
    for s in crate::absorb::survey().unwrap_or_default() {
        let (level, check, detail) = match &s.disposition {
            crate::absorb::Disposition::Declined(crate::absorb::Declined::Framework(id)) => (
                Level::Info,
                "module mount left by design",
                format!(
                    "{} <- {} — {id} is a hook framework; absorb leaves it alone",
                    s.target.display(),
                    s.source.display()
                ),
            ),
            crate::absorb::Disposition::Declined(crate::absorb::Declined::Listed(from)) => (
                Level::Info,
                "module mount left by design",
                format!(
                    "{} <- {} stays mounted: listed in {from}. Remove its entry to absorb it",
                    s.target.display(),
                    s.source.display()
                ),
            ),
            crate::absorb::Disposition::Declined(crate::absorb::Declined::HooksElsewhere(id)) => (
                Level::Info,
                "module mount left by design",
                format!(
                    "{} <- {} stays mounted: {id} also mounts a known hook path, so absorb \
                     leaves everything it owns alone",
                    s.target.display(),
                    s.source.display()
                ),
            ),
            crate::absorb::Disposition::Declined(crate::absorb::Declined::MustBind) => (
                Level::Info,
                "module mount left by design",
                format!(
                    "{} <- {} stays mounted: a my_* target is served by a real bind, so \
                     absorbing it into an injection would bootloop zygote",
                    s.target.display(),
                    s.source.display()
                ),
            ),
            // Nothing declined it and absorb cannot take it, so it is simply
            // there — the exact condition the mountless posture exists to deny.
            crate::absorb::Disposition::Leaking(why) => (
                Level::Warn,
                "foreign mount absorb cannot take",
                format!(
                    "{} <- {} is a real mount visible to any app, and absorb cannot convert \
                     it: {why}",
                    s.target.display(),
                    s.source.display()
                ),
            ),
            // Already served by an injection, so absorb only has to unmount it —
            // no `--include-dirs`, nothing to re-serve. Still a warning while it
            // stands: a redundant mount is every bit as visible to an app as a
            // load-bearing one.
            crate::absorb::Disposition::Redundant => (
                Level::Warn,
                "module mount not absorbed",
                format!(
                    "{} <- {} is still a real mount and visible to any app, but its content is ALREADY served by live injections, so the mount is redundant — `nomount absorb` just unmounts it. The owning module is bind-mounting content NoMount already injects; dropping that bind from its post-fs-data.sh stops it coming back at boot",
                    s.target.display(),
                    s.source.display()
                ),
            ),
            // A DIRECTORY bind is absorbable in principle but a plain run always
            // skips it, so telling the reader to "run nomount absorb" would send
            // them to a command that declines it again and explains nothing.
            crate::absorb::Disposition::Absorb if s.source.is_dir() => (
                Level::Warn,
                "module mount not absorbed",
                format!(
                    "{} <- {} is a directory bind, still a real mount and visible to any \
                     app. A plain `nomount absorb` skips it, because injecting a directory \
                     snapshots its listing and would miss files the module adds later — \
                     `nomount absorb --include-dirs` takes it anyway",
                    s.target.display(),
                    s.source.display()
                ),
            ),
            crate::absorb::Disposition::Absorb => (
                Level::Warn,
                "module mount not absorbed",
                format!(
                    "{} <- {} is still a real mount and visible to any app, and nothing \
                     declined it — run `nomount absorb` (it runs at boot, so this usually \
                     means it failed)",
                    s.target.display(),
                    s.source.display()
                ),
            ),
        };
        f.push(Finding { level, check, detail });
    }

    // Mounts absorb can neither see nor remove, because they live in a namespace
    // it is not in. Reported separately from the survey above: the verdict there
    // is about our own mountinfo, and an app's view can be strictly worse.
    for e in crate::absorb::survey_elsewhere() {
        f.push(Finding {
            level: Level::Warn,
            check: "foreign mount in another namespace",
            detail: format!(
                "{} (from {}) is mounted in {} but not here, so absorb cannot see or unmount \
                 it. It was replicated with nsenter, and apps can see it.",
                e.mount.target.display(),
                e.mount.source.display(),
                e.seen_in
            ),
        });
    }

    // Static pre-flight: what each module's OWN scripts will do to the mount
    // table. The checks above describe mounts that already exist; this one runs
    // off the scripts on disk, so it lands BEFORE boot -- which is the only
    // point at which the nsenter family can still be avoided rather than
    // discovered. See preflight.rs for the survey this is sized from.
    // Which modules actually own a mount right now. A static scan reads every
    // branch of a script, including ones that never execute -- and modules with
    // several mount strategies are common. bindhosts is the case that showed
    // this up: it picks one of ELEVEN modes at boot, its service.sh contains an
    // `mount -t overlay` for two of them, and on a metamodule device it selects
    // mode 0, which mounts nothing at all. The finding still read "sets up
    // overlayfs -- absorb cannot re-serve it, so it stays a real mount" on a
    // device where `/proc/mounts` had no such mount and the hosts file was being
    // served as an injection.
    //
    // So: keep the static scan (it is the only thing that can warn BEFORE a
    // boot), but when the mount table is readable and the module owns nothing in
    // it, say the branch was not taken rather than asserting a mount exists.
    let mounted_modules: std::collections::HashSet<String> = std::fs::read_to_string(
        "/proc/self/mountinfo",
    )
    .ok()
    .map(|body| {
        let rows = crate::absorb::parse_mountinfo(&body);
        let roots = crate::absorb::fs_roots(&rows);
        rows.iter()
            .filter_map(|r| crate::absorb::source_of(r, &roots))
            .filter_map(|src| crate::absorb::module_dir_of(&src))
            .filter_map(|d| d.file_name().map(|n| n.to_string_lossy().into_owned()))
            .collect()
    })
    .unwrap_or_default();
    let mountinfo_readable = std::fs::metadata("/proc/self/mountinfo").is_ok();

    for h in crate::preflight::scan_all("/data/adb/modules", "meta-nomount") {
        // Demote to informational when we can see it did not happen. Never when
        // the table could not be read -- "no evidence" is not "no mount".
        let inert = mountinfo_readable && !mounted_modules.contains(&h.module);
        let (level, check, detail) = match h.habit {
            crate::preflight::MountHabit::Namespace => (
                Level::Warn,
                "mounts into other namespaces",
                format!(
                    "{} uses {} — mounts in other processes' namespaces; absorb cannot \
                     remove those",
                    h.module, h.evidence
                ),
            ),
            crate::preflight::MountHabit::ForeignFs => (
                Level::Warn,
                "mounts its own filesystem",
                format!(
                    "{} sets up {} — absorb cannot re-serve it, so it stays a real mount",
                    h.module, h.evidence
                ),
            ),
            crate::preflight::MountHabit::Pseudo => (
                Level::Info,
                "mounts a pseudo-fs",
                format!(
                    "{} mounts {} — kernel pseudo-fs, no module content", h.module, h.evidence
                ),
            ),
            crate::preflight::MountHabit::Absorbable => (
                Level::Info,
                "self-mounts, absorbed",
                format!(
                    "{} uses {} — absorb takes it over at boot", h.module, h.evidence
                ),
            ),
        };
        // Softened when the module owns no mount on this boot: the branch that
        // would have created one was not taken, and stating it as fact is how a
        // clean device ends up showing a warning nobody can act on.
        let (level, detail) = if inert && level == Level::Warn {
            (
                Level::Info,
                format!(
                    "{detail}. Not on this boot though — {} owns no mount in /proc/mounts,                      so that branch of its scripts did not run.",
                    h.module
                ),
            )
        } else {
            (level, detail)
        };
        f.push(Finding { level, check, detail });
    }

    // A module rewriting the root manager's global settings from its own
    // scripts. Separate from the mount scan because the module that motivated it
    // makes no mount call at all: it drives a susfs binary, so the mount scan is
    // blind to it while it flips kernel_umount on every boot.
    // A SUSFS module on a kernel without SUSFS. This is the case where the
    // advice really is "remove it", not "adjust it": every hiding call it makes
    // is a no-op here, while its side effects -- manager settings, props,
    // mounts -- still apply in full. Checked against the kernel, not assumed, so
    // it stays silent on a SUSFS build where these modules do their job.
    // Only claim something about SUSFS when the manager actually answered. On a
    // manager whose ksud has no `susfs` command (KernelSU Next) the probe says
    // nothing about the kernel, and treating that as "no SUSFS" told a user with a
    // SUSFS kernel to delete a working module (KsuNext_NMS#13). The Suite does not
    // use SUSFS and knows nothing of its internals, so silence is the honest answer
    // when nobody could tell us.
    let susfs = crate::manager::susfs_state();
    if susfs != crate::manager::Susfs::Present {
        for u in crate::preflight::scan_susfs_users("/data/adb/modules", "meta-nomount") {
            // "Remove it" is only right for a module whose PURPOSE is SUSFS
            // hiding. A content module making a best-effort SUSFS call in a
            // fallback branch loses nothing here -- saying remove would cost the
            // user the content they installed it for.
            let known_absent = susfs == crate::manager::Susfs::Absent;
            let (level, detail) = match (u.susfs_is_its_purpose, known_absent) {
                (true, true) => (
                    Level::Warn,
                    format!(
                        "{} is a SUSFS module and this kernel has no SUSFS — it hides \
                         nothing here while its side effects still apply. Remove it",
                        u.module
                    ),
                ),
                // Same module, but we could not confirm the kernel. State the
                // condition, do not assert it, and do not tell anyone to delete
                // something that may well be working.
                (true, false) => (
                    Level::Info,
                    format!(
                        "{} is a SUSFS module. This manager cannot report whether the kernel \
                         has SUSFS — if it does not, the module hides nothing here while its \
                         side effects still apply",
                        u.module
                    ),
                ),
                (false, true) => (
                    Level::Info,
                    format!(
                        "{} makes SUSFS calls (no SUSFS here, so they no-op) but ships its \
                         own content — keep it", u.module
                    ),
                ),
                (false, false) => (
                    Level::Info,
                    format!(
                        "{} makes SUSFS calls but ships its own content — keep it", u.module
                    ),
                ),
            };
            let check = if known_absent { "SUSFS calls, no SUSFS" } else { "SUSFS calls" };
            f.push(Finding { level, check, detail });
        }
    }

    for w in crate::preflight::scan_manager_writes("/data/adb/modules", "meta-nomount") {
        let shown = w.value.clone().unwrap_or_else(|| "<computed>".into());
        let (level, detail) = match w.harm {
            Some(why) => (
                Level::Warn,
                format!(
                    "{} sets {}={} every boot — your manual change will not stick. {}",
                    w.module, w.key, shown, why
                ),
            ),
            None => (
                Level::Info,
                format!(
                    "{} sets {}={} every boot", w.module, w.key, shown
                ),
            ),
        };
        f.push(Finding { level, check: "rewrites manager setting", detail });
    }

    for (part, n) in &fd_note {
        f.push(Finding {
            level: Level::Info,
            check: "not FD-allowlisted for zygote",
            detail: format!(
                "{n} injected file(s) on /{part} — zygote does not preload these; fine"
            ),
        });
    }
    let mut holes: Vec<(&str, Vec<&Path>)> = holes.into_iter().collect();
    holes.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(b.0)));
    for (module, targets) in &holes {
        let shown: Vec<String> = targets.iter().take(3).map(|t| t.display().to_string()).collect();
        let more = targets.len().saturating_sub(shown.len());
        f.push(Finding {
            level: Level::Info,
            check: "whiteout leaves a measurable hole",
            detail: format!(
                "{module}: {} path(s) the engine cannot fully mask — their folder spans several \
                 blocks, so its size still counts the hidden entry. Applied anyway; declining \
                 would silently neuter the module. {}{}",
                targets.len(),
                shown.join(", "),
                if more > 0 { format!(", and {more} more") } else { String::new() }
            ),
        });
    }

    for (marker, module, count) in expansions_by_marker(&plan) {
        let Some(level) = expansion_level(count) else { continue };
        f.push(Finding {
            level,
            check: "wide replacement expansion",
            detail: format!(
                "{module}: {} expands to {count} hides, one per ROM entry it does not ship. \
                 Correct, but a lot from one marker — narrow it if it was meant to cover less.",
                marker.display()
            ),
        });
    }

    let errors = f.iter().filter(|x| x.level == Level::Error).count();
    let warns = f.iter().filter(|x| x.level == Level::Warn).count();
    let infos = f.iter().filter(|x| x.level == Level::Info).count();

    if json {
        use crate::json::J;
        let doc = J::Obj(vec![
            ("kind", J::s("doctor")),
            (
                "summary",
                J::Obj(vec![
                    ("errors", J::Num(errors as i64)),
                    ("warnings", J::Num(warns as i64)),
                    ("informational", J::Num(infos as i64)),
                ]),
            ),
            // The two switches the WebUI banner needs, as booleans rather than as
            // prose for it to regex. That match has already shipped broken once:
            // the kernel-umount half tested for /manager: kernel umount is ON/
            // while this file prints "manager kernel umount ON", so half of a
            // warning that exists because these switches have broken root on real
            // hardware was dead code. A field cannot drift the way a sentence can.
            (
                "manager",
                J::Obj(vec![
                    (
                        "global_umount_on",
                        J::Bool(f.iter().any(|x| x.check == "manager global umount ON")),
                    ),
                    (
                        "kernel_umount_on",
                        J::Bool(f.iter().any(|x| x.check == "manager kernel umount ON")),
                    ),
                ]),
            ),
            (
                "findings",
                J::Arr(
                    f.iter()
                        .map(|x| {
                            J::Obj(vec![
                                (
                                    "level",
                                    J::s(match x.level {
                                        Level::Error => "error",
                                        Level::Warn => "warn",
                                        Level::Info => "info",
                                    }),
                                ),
                                ("check", J::s(x.check)),
                                ("detail", J::s(&x.detail)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]);
        println!("{}", doc.render());
        return Ok(());
    }

    if f.is_empty() {
        println!("[ok] no problems found");
    } else {
        for x in &f {
            let tag = match x.level {
                Level::Error => "error",
                Level::Warn => "warn",
                Level::Info => "info",
            };
            println!("[{tag}] {}: {}", x.check, x.detail);
        }
    }
    if infos > 0 {
        println!("summary: {errors} errors, {warns} warnings, {infos} informational");
    } else {
        println!("summary: {errors} errors, {warns} warnings");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nm::LiveKind;

    fn wo(module: &str, marker: &str, target: &str) -> PlanEntry {
        PlanEntry {
            module: module.to_string(),
            target: PathBuf::from(target),
            source: PathBuf::from(marker),
            kind: PlanKind::Whiteout,
        }
    }

    /// Whiteouts are grouped by the marker that produced them, so one `.replace`
    /// reads as one wide expansion rather than N unrelated rules -- and an inject
    /// sharing the plan is not counted at all.
    #[test]
    fn expansions_are_grouped_by_their_marker() {
        let mut plan = vec![
            wo("m", "/data/adb/modules/m/system/etc/x/.replace", "/system/etc/x/a"),
            wo("m", "/data/adb/modules/m/system/etc/x/.replace", "/system/etc/x/b"),
            wo("m", "/data/adb/modules/m/system/etc/x/.replace", "/system/etc/x/c"),
            // a 0:0 char device is its own source: always a group of one
            wo("m", "/data/adb/modules/m/system/app/Foo", "/system/app/Foo"),
        ];
        plan.push(PlanEntry {
            module: "m".into(),
            target: PathBuf::from("/system/etc/x/mine.xml"),
            source: PathBuf::from("/data/adb/modules/m/system/etc/x/mine.xml"),
            kind: PlanKind::Inject,
        });

        let got = expansions_by_marker(&plan);
        assert_eq!(got.len(), 2, "one .replace group + one char device");
        // widest first
        assert_eq!(got[0].2, 3);
        assert!(got[0].0.ends_with(".replace"));
        assert_eq!(got[1].2, 1);
    }

    /// A report, never a cap: the levels escalate but nothing is ever withheld.
    /// Calibrated on a stock OP15 (~258 live rules): /system/app is 15 entries,
    /// /product/app 75, /system/fonts 224.
    #[test]
    fn expansion_levels_escalate_but_never_refuse() {
        assert_eq!(expansion_level(1), None);
        assert_eq!(expansion_level(15), None); // .replace on /system/app
        assert_eq!(expansion_level(49), None);
        assert_eq!(expansion_level(75), Some(Level::Info)); // /product/app
        assert_eq!(expansion_level(199), Some(Level::Info));
        assert_eq!(expansion_level(224), Some(Level::Warn)); // /system/fonts
    }

    /// Verbatim from `ksud feature get kernel_umount` on OP15 / ReSukiSU.
    /// The parser itself now lives in manager.rs; this keeps the real-device
    /// sample exercising it from here too.
    #[test]
    fn parses_ksud_feature_output() {
        let off = "Feature: kernel_umount (1)\nDescription: Kernel Umount - controls whether \
                   kernel automatically unmounts modules when not needed\nValue: 0\n";
        assert_eq!(crate::manager::parse_feature_value(off), Some(0));
        assert_eq!(crate::manager::parse_feature_value("Feature: x (1)\nValue: 1\n"), Some(1));
        assert_eq!(crate::manager::parse_feature_value("no value here"), None);
    }

    #[test]
    fn partition_of_extracts_top_level() {
        assert_eq!(partition_of(Path::new("/product/overlay/x.apk")).as_deref(), Some("product"));
        assert_eq!(partition_of(Path::new("/system/etc/y.xml")).as_deref(), Some("system"));
        assert_eq!(partition_of(Path::new("/vendor/lib/z.so")).as_deref(), Some("vendor"));
        assert_eq!(partition_of(Path::new("/")), None);
    }

    #[test]
    fn is_partition_root_only_for_bare_roots() {
        assert!(is_partition_root(Path::new("/product")));
        assert!(is_partition_root(Path::new("/system")));
        assert!(!is_partition_root(Path::new("/product/overlay")));
        assert!(!is_partition_root(Path::new("/product/overlay/x.apk")));
    }

    /// The parser itself, and its suffix-peeling, now live with the client that
    /// produces the text (`nm::parse_list`) -- see its tests. What this file still
    /// owns is the reading of those rows, exercised by the checks above.
    #[test]
    fn parse_live_still_yields_the_rows_the_checks_read() {
        let v = parse_live(
            "/product/x.apk -> /data/adb/modules/M/product/x.apk (public)\n\
             /system/y (whiteout)\n",
        );
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].target, PathBuf::from("/product/x.apk"));
        assert_eq!(v[0].source.as_deref(), Some(Path::new("/data/adb/modules/M/product/x.apk")));
        assert_eq!(v[0].kind, LiveKind::Inject);
        assert!(v[0].public);
        assert_eq!(v[1].kind, LiveKind::Whiteout);
        assert_eq!(v[1].source, None);
    }
}
