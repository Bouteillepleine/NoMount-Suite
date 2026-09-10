
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::check::{slug, Check, Section, Verdict};
use crate::mount::{collect_plan, PlanEntry, PlanKind};
use crate::nm::{LiveRule, Nm};

const ZYGOTE_FD_ALLOWLISTED: &[&str] = &[
    "system", "product", "vendor", "system_ext", "odm", "apex", "oem",
];

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Error,
    Unmeasured,
    Warn,
    NotApplicable,
    Info,
}

struct Finding {
    level: Level,
    check: &'static str,
    detail: String,
}

fn verdict_of(level: &Level) -> Verdict {
    match level {
        Level::Error => Verdict::Fail,
        Level::Unmeasured => Verdict::Unmeasured,
        Level::Warn => Verdict::Warn,
        Level::NotApplicable => Verdict::NotApplicable,
        Level::Info => Verdict::Note,
    }
}

fn owner_of(f: &Finding) -> Option<String> {
    const PER_MODULE: &[&str] = &[
        "partition-root target",
        "no such partition",
        "whiteout leaves a measurable hole",
        "wide replacement expansion",
    ];
    if !PER_MODULE.contains(&f.check) {
        return None;
    }
    let head = f.detail.split([' ', ':']).next().unwrap_or("");
    if head.is_empty() || head.len() > 64 {
        None
    } else {
        Some(head.trim_end_matches(':').to_string())
    }
}

#[derive(PartialEq)]
enum GhostSeen {
    Absent,
    Visible,
    XattrLeak,
    Unknown,
}

fn ghost_seen_by(uid: u32, path: &Path) -> GhostSeen {
    use std::os::unix::ffi::OsStrExt;
    let Ok(cpath) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return GhostSeen::Unknown;
    };
    let Ok(attr) = std::ffi::CString::new("security.selinux") else {
        return GhostSeen::Unknown;
    };
    const ABSENT: i32 = 0;
    const VISIBLE: i32 = 1;
    const XLEAK: i32 = 2;
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return GhostSeen::Unknown;
        }
        if pid == 0 {
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

fn reconcile_plan_and_live(
    plan: &[PlanEntry],
    live: &[LiveRule],
    durable: Option<&HashSet<PathBuf>>,
    absorbed: Option<&HashSet<PathBuf>>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let planned: HashMap<&Path, &PlanEntry> = plan
        .iter()
        .filter(|e| e.kind != PlanKind::Bind)
        .map(|e| (e.target.as_path(), e))
        .collect();
    let global: HashMap<&Path, &LiveRule> = live
        .iter()
        .filter(|r| r.uid == 0 && r.kind != crate::nm::LiveKind::VirtualDir)
        .map(|r| (r.target.as_path(), r))
        .collect();

    let mut missing: Vec<String> = Vec::new();
    let mut wrong: Vec<String> = Vec::new();
    for (t, e) in &planned {
        match global.get(t) {
            None => missing.push(format!("{} (from {})", t.display(), e.module)),
            Some(r) => {
                let agrees = match (e.kind, r.kind) {
                    (PlanKind::Inject, crate::nm::LiveKind::Inject) => {
                        r.source.as_deref() == Some(e.source.as_path())
                    }
                    (PlanKind::Whiteout, crate::nm::LiveKind::Whiteout) => true,
                    _ => false,
                };
                if !agrees {
                    wrong.push(format!(
                        "{} (plan: {} from {}; live: {})",
                        t.display(),
                        match e.kind {
                            PlanKind::Whiteout => "whiteout".to_string(),
                            _ => e.source.display().to_string(),
                        },
                        e.module,
                        match (&r.kind, &r.source) {
                            (crate::nm::LiveKind::Inject, Some(s)) => s.display().to_string(),
                            (k, _) => format!("{k:?}"),
                        }
                    ));
                }
            }
        }
    }

    let extra: Option<Vec<String>> = match (durable, absorbed) {
        (Some(d), Some(a)) => Some(
            global
                .iter()
                .filter(|(t, _)| {
                    !planned.contains_key(*t) && !d.contains(**t) && !a.contains(**t)
                })
                .map(|(t, r)| match (&r.kind, &r.source) {
                    (crate::nm::LiveKind::Inject, Some(s)) => {
                        format!("{} -> {}", t.display(), s.display())
                    }
                    _ => format!("{} (whiteout)", t.display()),
                })
                .collect(),
        ),
        _ => None,
    };

    let name = |v: &[String]| -> String {
        let shown: Vec<&str> = v.iter().take(5).map(String::as_str).collect();
        let more = v.len().saturating_sub(shown.len());
        format!(
            "{}{}",
            shown.join(", "),
            if more > 0 { format!(", and {more} more") } else { String::new() }
        )
    };
    if !missing.is_empty() {
        missing.sort();
        out.push(Finding {
            level: Level::Warn,
            check: "planned rule not live",
            detail: format!(
                "{} rule(s) the plan describes are not in the engine, so those files are NOT \
                 being served -- the stock ROM version is what apps see. Run `nomount reload`; \
                 if they do not come back, the add failed. {}",
                missing.len(),
                name(&missing)
            ),
        });
    }
    if !wrong.is_empty() {
        wrong.sort();
        out.push(Finding {
            level: Level::Error,
            check: "live rule disagrees with the plan",
            detail: format!(
                "{} live rule(s) name a different source or kind than the plan resolves for the \
                 same path, so the content being served is not the content the module set \
                 implies. Run `nomount reload`. {}",
                wrong.len(),
                name(&wrong)
            ),
        });
    }
    match extra {
        Some(mut e) if !e.is_empty() => {
            e.sort();
            out.push(Finding {
                level: Level::Warn,
                check: "live rule the plan cannot account for",
                detail: format!(
                    "{} rule(s) are live that no enabled module, durable whiteout or absorbed \
                     mount explains -- a hand-written `nomount vfs add`, or a leftover from a \
                     module removed without a reload. `nomount reload` prunes them. {}",
                    e.len(),
                    name(&e)
                ),
            });
        }
        None => {
            out.push(Finding {
                level: Level::Info,
                check: "live rules not fully accounted for",
                detail: "the durable whiteout list or the absorbed-rule record could not be \
                         read, so live rules were checked for missing entries only -- an extra \
                         rule would not have been reported."
                    .to_string(),
            });
        }
        _ => {}
    }
    out
}

fn expansions_by_marker(plan: &[PlanEntry]) -> Vec<(&Path, &str, usize)> {
    let mut by: HashMap<&Path, (&str, usize)> = HashMap::new();
    for e in plan.iter().filter(|e| e.kind == PlanKind::Whiteout) {
        let slot = by.entry(e.source.as_path()).or_insert((e.module.as_str(), 0));
        slot.1 += 1;
    }
    let mut v: Vec<(&Path, &str, usize)> =
        by.into_iter().map(|(m, (module, n))| (m, module, n)).collect();
    v.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.cmp(b.0)));
    v
}

fn expansion_level(count: usize) -> Option<Level> {
    match count {
        0..=49 => None,
        50..=199 => Some(Level::Info),
        _ => Some(Level::Warn),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Incompat {
    RomWrite,
    MagiskMirror,
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
                 serve this. The module keeps its own mount; the mount checks will report \
                 it, and that report is correct rather than a leak.",
        }
    }
}

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
                let rom_is_source = PARTS.iter().any(|p| {
                    t.find(&format!(" /{p}/")).is_some_and(|at| {
                        t[at..].contains("$MODPATH") || t[at..].contains("$MODDIR")
                    })
                });
                let kind = if (["cp ", "mv ", "ln ", "touch ", " rm "]
                    .iter()
                    .any(|v| t.contains(v))
                    && !rom_is_source
                    && PARTS.iter().any(|p| t.contains(&format!(" /{p}/"))))
                    || (t.contains("remount")
                        && PARTS.iter().any(|p| {
                            t.contains(&format!(" /{p} ")) || t.ends_with(&format!(" /{p}"))
                        }))
                {
                    Some(Incompat::RomWrite)
                } else if t.contains(".magisk/mirror/")
                    || (t.contains("MAGISKTMP") && t.contains("/mirror/"))
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

        if !seen.contains(&Incompat::ImageBacked) {
            if let Some(img) = find_shipped_image(&mdir, &mdir, 0) {
                out.push((id.clone(), "shipped file".to_string(), Incompat::ImageBacked, img));
            }
        }
    }
    out
}

fn find_shipped_image(
    root: &std::path::Path,
    dir: &std::path::Path,
    depth: u32,
) -> Option<String> {
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
            let p = e.path();
            return Some(p.strip_prefix(root).unwrap_or(&p).to_string_lossy().into_owned());
        }
    }
    for d in dirs {
        if let Some(found) = find_shipped_image(root, &d, depth + 1) {
            return Some(found);
        }
    }
    None
}

fn subject_of(f: &Finding) -> Option<&str> {
    fn trim(t: &str) -> &str {
        t.trim_end_matches([',', ':', '.'])
    }
    fn numeric(t: &str) -> bool {
        !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit())
    }
    let head = trim(f.detail.split([' ', ':']).next().unwrap_or(""));
    if !head.is_empty() && !numeric(head) && head.len() <= 128 {
        return Some(head);
    }
    f.detail
        .split_whitespace()
        .map(trim)
        .find(|t| t.starts_with('/') && t.len() > 1 && t.len() <= 128)
}

fn to_checks(findings: Vec<Finding>) -> Vec<Check> {
    let mut seen: HashMap<String, usize> = HashMap::new();
    findings
        .into_iter()
        .map(|x| {
            let owner = owner_of(&x);
            let base = match subject_of(&x) {
                Some(s) => format!("{}-{}", slug(x.check), slug(s)),
                None => slug(x.check),
            };
            let n = seen.entry(base.clone()).or_insert(0);
            *n += 1;
            let id = if *n == 1 { base } else { format!("{base}-{n}") };
            let mut c = Check::new(
                Section::Plan,
                id,
                x.check,
                verdict_of(&x.level),
                x.detail.clone(),
            )
            .meaning(x.detail);
            if let Some(o) = owner {
                c = c.owner(o);
            }
            c
        })
        .collect()
}

pub fn plan_checks() -> Result<(Vec<Check>, Vec<crate::check::Fact>)> {
    let mut fd_note: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
    let mut f: Vec<Finding> = Vec::new();
    let (plan, skipped) = collect_plan()?;

    let mut by_target: HashMap<&Path, Vec<&str>> = HashMap::new();
    let mut holes: HashMap<&str, Vec<&Path>> = HashMap::new();
    for e in &plan {
        by_target
            .entry(e.target.as_path())
            .or_default()
            .push(e.module.as_str());

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

        if e.kind == PlanKind::Whiteout && crate::mount::whiteout_leaves_hole(&e.target) {
            holes.entry(e.module.as_str()).or_default().push(e.target.as_path());
        }

        if e.kind == PlanKind::Inject && !e.source.exists() {
            let detail = match fs::symlink_metadata(&e.source) {
                Ok(m) if m.file_type().is_symlink() => {
                    let dest = fs::read_link(&e.source).unwrap_or_default();
                    format!(
                        "{} -> {} is a symlink to {}, which does not exist. Injection \
                         serves a link's target, so this produces no rule and the path \
                         never appears - an installer that symlinks before its target \
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

    let served: Vec<&Path> = plan
        .iter()
        .filter(|e| e.kind != PlanKind::Whiteout)
        .map(|e| e.target.as_path())
        .collect();

    let ours_set: std::collections::HashSet<&Path> = served
        .iter()
        .flat_map(|t| t.ancestors())
        .collect();

    let ours = |p: &Path| ours_set.contains(p);

    let is_apk_container = |p: &Path| {
        p.ancestors().any(|a| {
            a.parent().and_then(|g| g.file_name()).is_some_and(|n| {
                matches!(n.to_str(), Some("app" | "priv-app" | "overlay" | "framework"))
            })
        })
    };

    let mut by_parent: HashMap<&Path, (Vec<String>, usize)> = HashMap::new();
    for e in &plan {
        if e.kind == PlanKind::Whiteout {
            continue;
        }
        let Some(parent) = e.target.parent() else { continue };
        if is_partition_root(parent) || parent.parent().is_none() || is_apk_container(parent) {
            continue;
        }
        let slot = by_parent.entry(parent).or_insert((Vec::new(), 0));
        slot.0.push(e.module.clone());
        slot.1 += 1;
    }

    let mut invented: HashMap<PathBuf, (Vec<String>, usize)> = HashMap::new();
    for (parent, slot) in by_parent {
        let has_stock = match fs::read_dir(parent) {
            Ok(rd) => rd.flatten().any(|d| !ours(&parent.join(d.file_name()))),
            Err(_) => false,
        };
        if has_stock {
            continue;
        }
        invented.insert(parent.to_path_buf(), slot);
    }

    invented.retain(|_, (_, n)| *n > 1);

    let invented_dirs: std::collections::HashSet<PathBuf> = invented.keys().cloned().collect();
    let mut rolled: Vec<(PathBuf, Vec<String>, usize)> = invented
        .into_iter()
        .filter(|(p, _)| !p.ancestors().skip(1).any(|a| invented_dirs.contains(a)))
        .map(|(p, (mods, n))| {
            let total = served.iter().filter(|t| t.starts_with(&p)).count();
            let mut m = mods;
            m.sort_unstable();
            m.dedup();
            (p, m, total.max(n))
        })
        .collect();
    rolled.sort_by(|a, b| a.0.cmp(&b.0));

    if !rolled.is_empty() {
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
                    format!("{mods}: {} directories ({files} file(s) total)", dirs.len())
                }
            })
            .collect::<Vec<_>>()
            .join("; ");
        f.push(Finding {
            level: Level::Info,
            check: "directory holds only injected files",
            detail: format!(
                "{list}. Injected files carry inode numbers from a band the ROM never \
                 allocates from, so a directory holding several of them and no stock file \
                 groups into one bucket that is entirely yours. Shipping into a directory \
                 that already has stock content removes it. Whether those inodes also \
                 stand out against the WHOLE partition depends on how tightly the ROM \
                 packs them -- measured on one device, most did not. Single-file \
                 directories and app/priv-app/overlay containers are excluded - one inode \
                 is not a bucket, and an APK cannot share a directory."
            ),
        });
    }

    for (module, script, kind, hit) in scan_module_incompat() {
        f.push(Finding {
            level: Level::Warn,
            check: kind.check(),
            detail: format!("{module} ({script}): `{hit}`. {}", kind.explain()),
        });
    }

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

    let kernel_umount = crate::manager::kernel_umount_enabled();
    if kernel_umount == Some(true) {
        f.push(Finding {
            level: Level::Warn,
            check: "manager kernel umount ON",
            detail: "manager \"Kernel umount\" is ON - it hides nothing here (injections are \
                     not mounts). Turn it OFF; use `nomount uid block <uid>` per app."
                .to_string(),
        });
    }

    if kernel_umount.is_none() && crate::manager::ksu_manager_present() {
        f.push(Finding {
            level: Level::Warn,
            check: "check a setting in your root manager",
            detail: "Could not read your root manager's \"Kernel umount\" - so it is UNKNOWN, \
                     not off. That switch strips module files from apps and has broken root. \
                     NoMount never needs it: check it once, in the manager."
                .to_string(),
        });
    }

    let nm = Nm::new();
    let engine = nm.version().ok();
    let live_ok = engine.is_some();
    let hidden_apps = crate::blocklist::read().unwrap_or_default();
    let mut pm_rules = 0usize;
    let mut pm_rules_no_public: Vec<PathBuf> = Vec::new();
    if !live_ok {
        f.push(Finding {
            level: Level::Unmeasured,
            check: "plan cross-checks did not run",
            detail: "the engine did not answer, so the checks that compare the plan against the \
                     live rules were skipped. Everything reported here is the plan alone. Run \
                     `nomount check --device` for the engine's own verdict."
                .to_string(),
        });
    }
    if live_ok {
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
            let live = crate::nm::parse_list(&list);
            let durable: Option<HashSet<PathBuf>> = crate::whiteout::read()
                .ok()
                .map(|v| v.into_iter().map(PathBuf::from).collect());
            let absorbed: Option<HashSet<PathBuf>> =
                crate::absorb::read_absorbed_targets().ok().map(|mut a| {
                    a.extend(crate::absorb::absorbed_tmpfs_targets());
                    a
                });
            f.extend(reconcile_plan_and_live(
                &plan,
                &live,
                durable.as_ref(),
                absorbed.as_ref(),
            ));
            for r in &live {
                let target = &r.target;
                if r.kind == crate::nm::LiveKind::Inject
                    && crate::pmcache::is_pm_published(target)
                {
                    pm_rules += 1;
                    if !r.public {
                        pm_rules_no_public.push(target.clone());
                    }
                }
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
                if let Some(part) = partition_of(target) {
                    if !ZYGOTE_FD_ALLOWLISTED.contains(&part.as_str()) {
                        let is_overlay_apk = target.extension().and_then(|x| x.to_str()) == Some("apk")
                            && target.components().any(|c| c.as_os_str() == "overlay");
                        if is_overlay_apk {
                            f.push(Finding {
                                level: Level::Error,
                                check: "not FD-allowlisted",
                                detail: format!(
                                    "{} lives on /{part} - an overlay APK here aborts forkSystemServer",
                                    target.display()
                                ),
                            });
                        } else {
                            *fd_note.entry(part).or_insert(0usize) += 1;
                        }
                    }
                }
            }
        }
    }

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

    if live_ok && engine_v >= 26 {
        if let Ok(txt) = nm.ghost_list() {
            let (gpaths, guids) = parse_ghost_tables(&txt);
            if let (Some(&uid), false) = (guids.first(), gpaths.is_empty()) {
                const SAMPLE: usize = 16;
                let attempted = gpaths.len().min(SAMPLE);
                let mut visible: Vec<&PathBuf> = Vec::new();
                let mut leaked: Vec<&PathBuf> = Vec::new();
                let mut absent = 0usize;
                let mut unknown = 0usize;
                for p in gpaths.iter().take(SAMPLE) {
                    match ghost_seen_by(uid, p) {
                        GhostSeen::Visible => visible.push(p),
                        GhostSeen::XattrLeak => leaked.push(p),
                        GhostSeen::Absent => absent += 1,
                        GhostSeen::Unknown => unknown += 1,
                    }
                }
                let checked = attempted;
                let name = |v: &[&PathBuf]| -> String {
                    v.iter().take(3).map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
                };
                if !visible.is_empty() {
                    f.push(Finding {
                        level: Level::Error,
                        check: "ghost cloak over-reaches",
                        detail: format!(
                            "{} of {checked} sampled path(s) are still visible to hidden uid {uid} - they \
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
                            "{} of {checked} sampled path(s) hide from `stat` but still leak their label - \
                 the guards are compiled in and not firing on this kernel: {}",
                            leaked.len(),
                            name(&leaked)
                        ),
                    });
                }
                if visible.is_empty() && leaked.is_empty() && absent == 0 {
                    f.push(Finding {
                        level: Level::Unmeasured,
                        check: "ghost cloak not verified",
                        detail: format!(
                            "none of the {attempted} sampled path(s) could be probed (the test process \
             could not run), so the cloak was not tested on this kernel - this is not a pass"
                        ),
                    });
                } else if visible.is_empty() && leaked.is_empty() {
                    f.push(Finding {
                        level: if unknown > 0 { Level::Warn } else { Level::Info },
                        check: if unknown > 0 {
                            "ghost cloak only partly verified"
                        } else {
                            "ghost cloak verified on this kernel"
                        },
                        detail: if unknown > 0 {
                            format!(
                                "{absent} of {attempted} sampled path(s) look exactly like a path that never \
             existed, to uid {uid} - but {unknown} could not be probed, so this is not a complete answer"
                            )
                        } else {
                            format!(
                                "{absent} of {} hidden path(s) sampled: each looks exactly like a path that never \
             existed, to uid {uid}. Measured here, not assumed from the build.",
                                gpaths.len()
                            )
                        },
                    });
                }
            } else {
                f.push(Finding {
                    level: if plan.iter().any(|e| e.kind == PlanKind::Inject) {
                        Level::Unmeasured
                    } else {
                        Level::NotApplicable
                    },
                    check: "ghost cloak not populated",
                    detail: format!(
                        "the engine returned {} hidden path(s) and {} hidden uid(s); both tables must be \
             non-empty for any guard to fire, so nothing was tested - a kernel built without _ghost \
             answers exactly the same way",
                        gpaths.len(),
                        guids.len()
                    ),
                });
            }
        }
    }

    let injects = plan.iter().filter(|e| e.kind == PlanKind::Inject).count();
    let whiteouts = plan.iter().filter(|e| e.kind == PlanKind::Whiteout).count();
    let binds = plan.iter().filter(|e| e.kind == PlanKind::Bind).count();
    let modules = {
        let mut m: Vec<&str> = plan.iter().map(|e| e.module.as_str()).collect();
        m.sort_unstable();
        m.dedup();
        m.len()
    };

    for s in crate::absorb::survey().unwrap_or_default() {
        let (level, check, detail) = match &s.disposition {
            crate::absorb::Disposition::Declined(crate::absorb::Declined::Framework(id)) => (
                Level::Info,
                "module mount left by design",
                format!(
                    "{} <- {} - {id} is a hook framework; absorb leaves it alone",
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
            crate::absorb::Disposition::Redundant => (
                Level::Warn,
                "module mount not absorbed",
                format!(
                    "{} <- {} is still a real mount and visible to any app, but its content is already served by live injections, so the mount is redundant - `nomount absorb` just unmounts it. The owning module is bind-mounting content NoMount already injects; dropping that bind from its post-fs-data.sh stops it coming back at boot",
                    s.target.display(),
                    s.source.display()
                ),
            ),
            crate::absorb::Disposition::Absorb if s.source.is_dir() => (
                Level::Warn,
                "module mount not absorbed",
                format!(
                    "{} <- {} is a directory bind, still a real mount and visible to any \
                     app. A plain `nomount absorb` skips it, because injecting a directory \
                     snapshots its listing and would miss files the module adds later - \
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
                     declined it - run `nomount absorb` (it runs at boot, so this usually \
                     means it failed)",
                    s.target.display(),
                    s.source.display()
                ),
            ),
        };
        f.push(Finding { level, check, detail });
    }

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

    for (part, n) in &fd_note {
        f.push(Finding {
            level: Level::Info,
            check: "not FD-allowlisted for zygote",
            detail: format!(
                "{n} injected file(s) on /{part} - zygote does not preload these; fine"
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
                "{module}: {} path(s) the engine cannot fully mask - their folder spans several \
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
                 Correct, but a lot from one marker - narrow it if it was meant to cover less.",
                marker.display()
            ),
        });
    }

    f.sort_by(|a, b| a.level.cmp(&b.level).then(a.check.cmp(b.check)));

    let facts: Vec<crate::check::Fact> = vec![
        ("modules".to_string(), modules.to_string()),
        ("plan_injects".to_string(), injects.to_string()),
        ("plan_whiteouts".to_string(), whiteouts.to_string()),
        ("plan_binds".to_string(), binds.to_string()),
        ("plan_blocklisted".to_string(), skipped.to_string()),
    ];

    Ok((to_checks(f), facts))
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

    #[test]
    fn expansions_are_grouped_by_their_marker() {
        let mut plan = vec![
            wo("m", "/data/adb/modules/m/system/etc/x/.replace", "/system/etc/x/a"),
            wo("m", "/data/adb/modules/m/system/etc/x/.replace", "/system/etc/x/b"),
            wo("m", "/data/adb/modules/m/system/etc/x/.replace", "/system/etc/x/c"),
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
        assert_eq!(got[0].2, 3);
        assert!(got[0].0.ends_with(".replace"));
        assert_eq!(got[1].2, 1);
    }

    fn inj(module: &str, target: &str, source: &str) -> PlanEntry {
        PlanEntry {
            module: module.to_string(),
            target: PathBuf::from(target),
            source: PathBuf::from(source),
            kind: PlanKind::Inject,
        }
    }

    #[test]
    fn a_plan_and_a_rule_set_that_disagree_are_a_finding() {
        let plan = vec![
            inj("m", "/system/etc/a", "/data/adb/modules/m/system/etc/a"),
            inj("m", "/system/etc/served-by-nobody", "/data/adb/modules/m/system/etc/x"),
        ];
        let live = crate::nm::parse_list(
            "/system/etc/a -> /data/adb/modules/m/system/etc/a
             /system/etc/stray -> /data/adb/modules/gone/system/etc/stray
",
        );
        let empty = HashSet::new();
        let f = reconcile_plan_and_live(&plan, &live, Some(&empty), Some(&empty));
        let checks: Vec<&str> = f.iter().map(|x| x.check).collect();
        assert!(checks.contains(&"planned rule not live"), "{checks:?}");
        assert!(checks.contains(&"live rule the plan cannot account for"), "{checks:?}");
        assert!(!checks.contains(&"live rule disagrees with the plan"), "{checks:?}");
    }

    #[test]
    fn durable_absorbed_and_per_uid_rules_are_not_unexplained() {
        let plan = vec![inj("m", "/system/etc/a", "/data/adb/modules/m/system/etc/a")];
        let live = crate::nm::parse_list(
            "/system/etc/a -> /data/adb/modules/m/system/etc/a
             /system/etc/hidden (whiteout)
             /product/app/X/X.apk -> /data/adb/rvhc/x.apk
             /system/etc/b -> /data/adb/modules/m/system/etc/b [UID: 10123]
             /system/etc/nmt (virtual dir)
",
        );
        let durable: HashSet<PathBuf> = [PathBuf::from("/system/etc/hidden")].into_iter().collect();
        let absorbed: HashSet<PathBuf> =
            [PathBuf::from("/product/app/X/X.apk")].into_iter().collect();
        let f = reconcile_plan_and_live(&plan, &live, Some(&durable), Some(&absorbed));
        assert!(f.is_empty(), "{:?}", f.iter().map(|x| x.detail.as_str()).collect::<Vec<_>>());
    }

    #[test]
    fn a_live_rule_naming_another_source_is_an_error() {
        let plan = vec![inj("winner", "/system/etc/a", "/data/adb/modules/winner/system/etc/a")];
        let live = crate::nm::parse_list("/system/etc/a -> /data/adb/modules/loser/system/etc/a
");
        let empty = HashSet::new();
        let f = reconcile_plan_and_live(&plan, &live, Some(&empty), Some(&empty));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].check, "live rule disagrees with the plan");
        assert_eq!(f[0].level, Level::Error);
    }

    #[test]
    fn an_unreadable_exemption_list_reports_nothing_extra() {
        let plan: Vec<PlanEntry> = Vec::new();
        let live = crate::nm::parse_list("/system/etc/hidden (whiteout)
");
        let f = reconcile_plan_and_live(&plan, &live, None, None);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].check, "live rules not fully accounted for");
        assert_eq!(f[0].level, Level::Info);
    }

    #[test]
    fn expansion_levels_escalate_but_never_refuse() {
        assert_eq!(expansion_level(1), None);
        assert_eq!(expansion_level(15), None);
        assert_eq!(expansion_level(49), None);
        assert_eq!(expansion_level(75), Some(Level::Info));
        assert_eq!(expansion_level(199), Some(Level::Info));
        assert_eq!(expansion_level(224), Some(Level::Warn));
    }

    #[test]
    fn a_shipped_image_is_named_relative_to_its_module() {
        let base = std::env::temp_dir().join("nm-doctor-img-test");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("common")).unwrap();
        std::fs::write(base.join("common/rootfs.img"), b"x").unwrap();
        assert_eq!(
            find_shipped_image(&base, &base, 0).as_deref(),
            Some("common/rootfs.img")
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn plan_findings_never_share_an_id() {
        let f = vec![
            Finding {
                level: Level::Info,
                check: "module mount left by design",
                detail: "/product/app/A.apk <- /data/adb/modules/m/a - m is a hook framework".into(),
            },
            Finding {
                level: Level::Info,
                check: "module mount left by design",
                detail: "/product/app/B.apk <- /data/adb/modules/m/b - m is a hook framework".into(),
            },
            Finding {
                level: Level::Info,
                check: "not FD-allowlisted for zygote",
                detail: "3 injected file(s) on /my_product - zygote does not preload these".into(),
            },
            Finding {
                level: Level::Info,
                check: "not FD-allowlisted for zygote",
                detail: "9 injected file(s) on /my_stock - zygote does not preload these".into(),
            },
            Finding {
                level: Level::Warn,
                check: "target claimed twice",
                detail: "/system/etc/x <- a, b".into(),
            },
            Finding {
                level: Level::Warn,
                check: "target claimed twice",
                detail: "/system/etc/x <- c, d".into(),
            },
        ];
        let n = f.len();
        let checks = to_checks(f);
        assert_eq!(checks.len(), n);
        let mut ids: Vec<&str> = checks.iter().map(|c| c.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), n, "two plan checks share an id: {ids:?}");
        assert!(
            checks[0].id.starts_with("module-mount-left-by-design-product-app-a"),
            "id should carry its subject, got {}",
            checks[0].id
        );
        assert_eq!(checks[2].id, "not-fd-allowlisted-for-zygote-my-product");
        assert_eq!(checks[3].id, "not-fd-allowlisted-for-zygote-my-stock");
        assert_eq!(checks[0].name, "module mount left by design");
        assert_eq!(checks[1].name, "module mount left by design");
    }

    #[test]
    fn a_findings_subject_is_the_head_of_its_detail() {
        let f = |d: &str| Finding { level: Level::Info, check: "c", detail: d.to_string() };
        assert_eq!(subject_of(&f("/product/app/X.apk <- /data/adb/m")), Some("/product/app/X.apk"));
        assert_eq!(subject_of(&f("OxygenCustomizer: 4 path(s) ...")), Some("OxygenCustomizer"));
        assert_eq!(subject_of(&f("3 injected file(s) on /my_product")), Some("/my_product"));
        assert_eq!(
            subject_of(&f("9 injected file(s) on /my_stock - zygote does not preload these")),
            Some("/my_stock")
        );
        assert_eq!(subject_of(&f("12 of 16 sampled look absent to uid 10471")), None);
        assert_eq!(subject_of(&f("")), None);
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

    #[test]
    fn parse_live_still_yields_the_rows_the_checks_read() {
        let v = crate::nm::parse_list(
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
