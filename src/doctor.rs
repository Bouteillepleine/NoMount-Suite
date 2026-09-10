
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::check::{slug, Check, Section, Verdict};
use crate::mount::{collect_plan, is_partition_root, PlanEntry, PlanKind};
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
        "module entry refused",
        "no such partition",
        "whiteout leaves a measurable hole",
        "wide replacement expansion",
        "module content not served",
        "writes into a ROM partition",
        "needs Magisk's mirror",
        "image-backed or chroot module",
        "bind-mounts its own content",
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
    const ABSENT: u32 = 0;
    const VISIBLE: u32 = 1;
    const XLEAK: u32 = 2;
    const UNKNOWN: u32 = 3;
    let seen = crate::audit::probe_as_uid(uid, || unsafe {
        let mut st: libc::stat = std::mem::zeroed();
        if libc::lstat(cpath.as_ptr(), &mut st) == 0 {
            return [VISIBLE];
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return [UNKNOWN];
        }
        let mut buf = [0u8; 256];
        let n = libc::lgetxattr(
            cpath.as_ptr(),
            attr.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        );
        [if n >= 0 { XLEAK } else { ABSENT }]
    });
    match seen {
        Ok([ABSENT]) => GhostSeen::Absent,
        Ok([VISIBLE]) => GhostSeen::Visible,
        Ok([XLEAK]) => GhostSeen::XattrLeak,
        _ => GhostSeen::Unknown,
    }
}

fn hidden_uid_label(uid: u32, redact: bool) -> String {
    if redact {
        "a hidden app".to_string()
    } else {
        format!("hidden uid {uid}")
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
                "{} rule(s) the plan describes are not in the engine, so those files are not \
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
                level: Level::Unmeasured,
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
        _ => Some(Level::Info),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Incompat {
    RomWrite,
    MagiskMirror,
    ImageBacked,
    SelfMount,
}

impl Incompat {
    fn level(self) -> Level {
        match self {
            Incompat::RomWrite | Incompat::MagiskMirror => Level::Warn,
            Incompat::ImageBacked | Incompat::SelfMount => Level::Info,
        }
    }

    fn check(self) -> &'static str {
        match self {
            Incompat::RomWrite => "writes into a ROM partition",
            Incompat::MagiskMirror => "needs Magisk's mirror",
            Incompat::ImageBacked => "image-backed or chroot module",
            Incompat::SelfMount => "bind-mounts its own content",
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
            Incompat::SelfMount =>
                "this module mounts its own content over a ROM path instead of shipping a \
                 tree, so for part of every boot the mount is real and readable by any app. \
                 absorb re-serves it as an injection and unmounts it -- automatically, four \
                 times per boot -- so nothing needs doing. Named here because the module \
                 depends on absorb running: if absorb is disabled or times out, this is one \
                 of the mounts that stays visible.",
        }
    }
}

fn rom_path_vars(script: &str) -> std::collections::HashMap<String, String> {
    const PARTS: &[&str] = crate::pmcache::ROM_PARTITIONS;
    let mut out = std::collections::HashMap::new();
    for line in script.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        let Some(eq) = t.find('=') else { continue };
        let name = &t[..eq];
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            continue;
        }
        let val = t[eq + 1..].trim().trim_matches(['"', '\'']);
        if PARTS.iter().any(|p| val.starts_with(&format!("/{p}/"))) {
            out.insert(name.to_string(), val.to_string());
        }
    }
    out
}

fn expand_rom_vars(line: &str, vars: &std::collections::HashMap<String, String>) -> String {
    let mut names: Vec<&String> = vars.keys().collect();
    names.sort_by_key(|n| std::cmp::Reverse(n.len()));
    let mut acc = line.to_string();
    for n in names {
        let v = &vars[n];
        acc = acc.replace(&format!("${{{n}}}"), v).replace(&format!("${n}"), v);
    }
    acc
}

fn classify_incompat_line(t: &str) -> Option<Incompat> {
    const PARTS: &[&str] = crate::pmcache::ROM_PARTITIONS;
    let t = match t.find(" #") {
        Some(at)
            if t[..at].matches('"').count().is_multiple_of(2)
                && t[..at].matches('\'').count().is_multiple_of(2) =>
        {
            t[..at].trim_end()
        }
        _ => t,
    };
    let probeless = {
        let mut acc = t.to_string();
        for pfx in ["command -v ", "command -V ", "which ", "type -p ", "hash "] {
            while let Some(at) = acc.find(pfx) {
                let rest = &acc[at + pfx.len()..];
                let cut = rest.find(char::is_whitespace).unwrap_or(rest.len());
                acc = format!("{}{}", &acc[..at], &rest[cut..]);
            }
        }
        acc
    };
    let last_path_tok = t
        .replace(['"', '\''], " ")
        .split_whitespace()
        .rfind(|w| w.starts_with('/') || w.starts_with('$'))
        .map(str::to_string);
    let rom_is_source = match &last_path_tok {
        Some(dst) => !PARTS.iter().any(|p| dst.starts_with(&format!("/{p}/"))),
        None => false,
    };
    let removes = t.starts_with("rm ") || t.contains(" rm ");
    let writes_otherwise = ["mkdir ", "sed -i", "install ", "dd "]
        .iter()
        .any(|v| t.starts_with(v) || t.contains(&format!(" {v}")));
    let redirects_into_rom = t.match_indices('>').any(|(at, _)| {
        let rest = t[at + 1..].trim_start_matches('>').trim_start();
        let tok = rest.split_whitespace().next().unwrap_or("");
        PARTS.iter().any(|p| tok.starts_with(&format!("/{p}/")))
    });
    let uses_an_image_tool = {
        let in_command_context = |hay: &str| -> Vec<bool> {
            let (mut dq, mut sq, mut depth) = (false, false, 0usize);
            let b: Vec<char> = hay.chars().collect();
            let mut out = Vec::with_capacity(b.len());
            let mut i = 0;
            while i < b.len() {
                out.push(!(dq || sq) || depth > 0);
                match b[i] {
                    '\\' => {
                        out.push(!(dq || sq) || depth > 0);
                        i += 2;
                        continue;
                    }
                    '\'' if !dq => sq = !sq,
                    '"' if !sq => dq = !dq,
                    '$' if !sq && b.get(i + 1) == Some(&'(') => depth += 1,
                    ')' if !sq && depth > 0 => depth -= 1,
                    _ => {}
                }
                i += 1;
            }
            out.resize(b.len() + 1, !(dq || sq) || depth > 0);
            out
        };
        let ctx = in_command_context(&probeless);
        let at_word_start = |hay: &str, needle: &str| {
            hay.match_indices(needle).any(|(at, _)| {
                let char_idx = hay[..at].chars().count();
                if !ctx.get(char_idx).copied().unwrap_or(true) {
                    return false;
                }
                at == 0
                    || hay[..at].chars().next_back().is_some_and(|c| {
                        c.is_whitespace() || c == '(' || c == ';' || c == '`' || c == '/'
                    })
            })
        };
        ["losetup", "mount -o loop", "mkfs.ext4", "chroot ", "proot ", "nsenter", "unshare "]
            .iter()
            .any(|n| at_word_start(&probeless, n))
    };
    let binds_without_a_later_umount = {
        let last_bind = ["--bind", "--rbind", "-o bind", "-o rbind", "-t overlay"]
            .iter()
            .filter_map(|m| probeless.rfind(m))
            .max();
        match (last_bind, probeless.rfind("umount")) {
            (Some(b), Some(u)) => u < b,
            (Some(_), None) => true,
            _ => false,
        }
    };
    let writes_into_rom = redirects_into_rom
        || ((removes || writes_otherwise
            || ["cp ", "mv ", "ln ", "touch "].iter().any(|v| t.contains(v)))
        && !rom_is_source
        && PARTS.iter().any(|p| t.contains(&format!(" /{p}/"))))
        || (t.contains("remount")
            && PARTS.iter().any(|p| {
                t.contains(&format!(" /{p} "))
                    || t.contains(&format!(" /{p}/ "))
                    || t.ends_with(&format!(" /{p}"))
                    || t.ends_with(&format!(" /{p}/"))
            }));
    if writes_into_rom {
        Some(Incompat::RomWrite)
    } else if t.contains(".magisk/mirror/")
        || (t.contains("MAGISKTMP") && t.contains("/mirror/"))
        || t.contains("mirror/system")
        || t.contains("mirror/vendor")
    {
        Some(Incompat::MagiskMirror)
    } else if uses_an_image_tool {
        Some(Incompat::ImageBacked)
    } else if binds_without_a_later_umount
        && (probeless.contains("--bind")
            || probeless.contains("--rbind")
            || probeless.contains("-o bind")
            || probeless.contains("-o rbind")
            || probeless.contains("-t overlay"))
        && PARTS.iter().any(|p| {
            let needle = format!("/{p}/");
            probeless.match_indices(&needle).any(|(at, _)| {
                at == 0
                    || probeless[..at]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_whitespace() || c == '"' || c == '\'')
            })
        })
    {
        Some(Incompat::SelfMount)
    } else {
        None
    }
}

fn sourced_scripts(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in body.lines() {
        let t = line.trim();
        if t.starts_with('#') {
            continue;
        }
        for kw in [". ", "source ", "sh ", "bash "] {
            let mut from = 0usize;
            while let Some(at) = t[from..].find(kw) {
                let abs = from + at;
                if abs > 0 && !t.as_bytes()[abs - 1].is_ascii_whitespace() {
                    from = abs + kw.len();
                    continue;
                }
                let rest = t[abs + kw.len()..].trim_start().trim_start_matches(['"', '\'']);
                let tok: String = rest
                    .chars()
                    .take_while(|c| !c.is_whitespace() && *c != ';' && *c != '"' && *c != '\'')
                    .collect();
                let tok = tok.as_str();
                for var in ["$MODDIR/", "$MODPATH/", "${MODDIR}/", "${MODPATH}/"] {
                    if let Some(rel) = tok.strip_prefix(var) {
                        if !rel.is_empty()
                            && !rel.contains("..")
                            && !rel.starts_with('/')
                            && !out.iter().any(|e| e == rel)
                        {
                            out.push(rel.to_string());
                        }
                    }
                }
                from = abs + kw.len();
            }
        }
    }
    out
}

fn my_hookless_writers() -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/data/adb/modules") else { return out };
    let mut dirs: Vec<_> = rd.flatten().collect();
    dirs.sort_by_key(|d| d.file_name());
    for d in dirs {
        let mdir = d.path();
        let Some(id) = mdir.file_name().and_then(|n| n.to_str()) else { continue };
        if id == "meta-nomount" || !mdir.is_dir() {
            continue;
        }
        let Ok(files) = std::fs::read_dir(&mdir) else { continue };
        let mut names: Vec<_> = files.flatten().map(|f| f.path()).collect();
        names.sort();
        for p in names {
            if p.extension().and_then(|e| e.to_str()) != Some("sh") {
                continue;
            }
            if std::fs::read_to_string(&p).is_ok_and(|b| b.contains("my_hookless")) {
                let file = p
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("?")
                    .to_string();
                out.push((id.to_string(), file));
                break;
            }
        }
    }
    out
}

fn marker_returns_when(files: &[String]) -> &'static str {
    if files.iter().any(|f| ENTRY_SCRIPTS.contains(&f.as_str())) {
        "it is written from a boot script, so it returns on the next boot"
    } else {
        "that is not a boot script, so it returns the next time the module runs it \
         (an action button, an update, its WebUI)"
    }
}

fn unserved_reason(markers: &[String], served: bool) -> Option<&'static str> {
    if served || markers.iter().any(|m| m == "disable" || m == "remove") {
        return None;
    }
    if markers.iter().any(|m| m == "skip_mount") {
        Some("skip_mount")
    } else {
        Some("none")
    }
}

fn module_rom_files(mdir: &Path) -> (usize, Vec<String>) {
    let mut n = 0usize;
    let mut parts: Vec<String> = Vec::new();
    let Ok(rd) = std::fs::read_dir(mdir) else { return (0, parts) };
    for e in rd.flatten() {
        let p = e.path();
        let Some(name) = p.file_name().and_then(|s| s.to_str()) else { continue };
        if !crate::pmcache::ROM_PARTITIONS.contains(&name) {
            continue;
        }
        if p.is_symlink() || !p.is_dir() || !Path::new("/").join(name).is_dir() {
            continue;
        }
        let c = count_files(&p, 0);
        if c > 0 {
            n += c;
            parts.push(format!("{name}({c})"));
        }
    }
    (n, parts)
}

fn count_files(dir: &Path, depth: usize) -> usize {
    if depth > 12 {
        return 0;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return 0 };
    let mut n = 0;
    for e in rd.flatten() {
        let p = e.path();
        if p.is_symlink() {
            if !p.is_dir() {
                n += 1;
            }
        } else if p.is_dir() {
            n += count_files(&p, depth + 1);
        } else {
            n += 1;
        }
    }
    n
}

fn fd_note_applies(kind: crate::nm::LiveKind) -> bool {
    kind == crate::nm::LiveKind::Inject
}

const ENTRY_SCRIPTS: [&str; 5] = [
    "post-fs-data.sh", "service.sh", "boot-completed.sh", "post-mount.sh", "customize.sh",
];

fn reached_only_if_sourced(script: &str) -> &'static str {
    if ENTRY_SCRIPTS.contains(&script) {
        return "";
    }
    " NB: this line is in a helper the module SOURCES, not in a script the manager \
     runs, so it only takes effect if the entry script reaches the `.` that pulls \
     it in -- a mode switch or a capability test can leave it dead. Check the \
     module's own config before acting on this."
}

fn scan_module_incompat() -> Vec<(String, String, Incompat, String)> {
    const SCRIPTS: [&str; 5] = ENTRY_SCRIPTS;
    let mut out: Vec<(String, String, Incompat, String)> = Vec::new();
    let Ok(dirs) = std::fs::read_dir(crate::mount::MODULES_DIR) else { return out };
    let mut dirs: Vec<_> = dirs.flatten().collect();
    dirs.sort_by_key(|e| e.file_name());

    for d in dirs {
        let mdir = d.path();
        let stood_down =
            mdir.join("disable").exists() || mdir.join("remove").exists();
        if !mdir.is_dir() || stood_down {
            continue;
        }
        let Some(id) = mdir.file_name().and_then(|n| n.to_str()).map(str::to_string) else {
            continue;
        };
        let mut seen: Vec<Incompat> = Vec::new();
        let mut todo: Vec<String> = SCRIPTS.iter().map(|s| (*s).to_string()).collect();
        for script in SCRIPTS {
            if let Ok(body) = std::fs::read_to_string(mdir.join(script)) {
                for rel in sourced_scripts(&body) {
                    if !todo.contains(&rel) && mdir.join(&rel).is_file() {
                        todo.push(rel);
                    }
                }
            }
        }
        for script in &todo {
            let script = script.as_str();
            let Ok(body) = std::fs::read_to_string(mdir.join(script)) else { continue };
            let vars = rom_path_vars(&body);
            for line in body.lines() {
                let t = line.trim();
                if t.starts_with('#') || t.is_empty() {
                    continue;
                }
                let kind = classify_incompat_line(&expand_rom_vars(t, &vars));
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
    let mut f: Vec<Finding> = Vec::new();
    let (plan, skipped, refused) = collect_plan()?;

    let mut by_target: HashMap<&Path, Vec<&str>> = HashMap::new();
    let mut holes: HashMap<&str, Vec<&Path>> = HashMap::new();
    for e in &plan {
        by_target
            .entry(e.target.as_path())
            .or_default()
            .push(e.module.as_str());

        if e.kind == PlanKind::Whiteout && crate::mount::whiteout_leaves_hole(&e.target) {
            holes.entry(e.module.as_str()).or_default().push(e.target.as_path());
        }

        if e.kind == PlanKind::Inject && !e.source.exists() {
            let detail = match fs::symlink_metadata(&e.source) {
                Ok(m) if m.file_type().is_symlink() => {
                    let dest = fs::read_link(&e.source)
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|err| format!("(unreadable link: {err})"));
                    format!(
                        "{} -> {} is a symlink to {dest}, which does not exist. Injection \
                         serves a link's target, so this produces no rule and the path \
                         never appears - an installer that symlinks before its target \
                         lands hits this",
                        e.target.display(),
                        e.source.display(),
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

    {
        let mut by_module: HashMap<&str, Vec<&crate::mount::Refused>> = HashMap::new();
        for r in &refused {
            by_module.entry(r.module.as_str()).or_default().push(r);
        }
        let mut mods: Vec<&&str> = by_module.keys().collect();
        mods.sort_unstable();
        for m in mods {
            let rs = &by_module[*m];
            let shown: Vec<String> = rs
                .iter()
                .take(3)
                .map(|r| format!("{} ({})", r.target.display(), r.why))
                .collect();
            let more = rs.len().saturating_sub(shown.len());
            f.push(Finding {
                level: Level::Warn,
                check: "module entry refused",
                detail: format!(
                    "{m}: {} entr(ies) the planner refused, so that content is not served and                      nothing else reports it. {}{}",
                    rs.len(),
                    shown.join(", "),
                    if more > 0 { format!(", and {more} more") } else { String::new() }
                ),
            });
        }
    }

    let mut nested: Vec<(&Path, &str)> = Vec::new();
    for e in &plan {
        let mut segs = e.target.components().skip(1).filter_map(|c| c.as_os_str().to_str());
        if let (Some(a), Some(b)) = (segs.next(), segs.next()) {
            if a == b {
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
                "{list}. Injected files take inode numbers from a band the ROM never \
                 allocates, so a directory holding several of them and no stock file is \
                 one cluster that is entirely yours. Ship into a directory that already \
                 has stock content and it disappears."
            ),
        });
    }

    if Path::new(crate::mount::MY_HOOKLESS_MARKER).exists() {
        let writers = my_hookless_writers();
        f.push(Finding {
            level: Level::Info,
            check: "my_* served by injection",
            detail: if writers.is_empty() {
                format!(
                    "my_* partitions are served by injection instead of a real bind, so they \
                     add no mounts. Nothing in any installed module's top-level scripts \
                     mentions the marker, so it is probably your own opt-in - a module could \
                     still be writing it from a helper script. Remove {} to go back to binds.",
                    crate::mount::MY_HOOKLESS_MARKER
                )
            } else {
                format!(
                    "my_* partitions are served by injection instead of a real bind, so they \
                     add no mounts. The Suite never writes the marker - {} did, which is how a \
                     module keeps its own my_* content off the mount table. Remove {} to go \
                     back to binds; {}.",
                    writers
                        .iter()
                        .map(|(id, file)| format!("{id} ({file})"))
                        .collect::<Vec<_>>()
                        .join(", "),
                    crate::mount::MY_HOOKLESS_MARKER,
                    marker_returns_when(
                        &writers.iter().map(|(_, f)| f.clone()).collect::<Vec<_>>()
                    )
                )
            },
        });
    }

    let served_modules: std::collections::HashSet<&str> =
        plan.iter().map(|e| e.module.as_str()).collect();
    if let Ok(rd) = std::fs::read_dir("/data/adb/modules") {
        let mut dirs: Vec<_> = rd.flatten().collect();
        dirs.sort_by_key(|d| d.file_name());
        for d in dirs {
            let mdir = d.path();
            let Some(id) = mdir.file_name().and_then(|n| n.to_str()) else { continue };
            if id == "meta-nomount" || !mdir.is_dir() {
                continue;
            }
            let markers: Vec<String> = ["disable", "remove", "skip_mount"]
                .iter()
                .filter(|m| mdir.join(m).exists())
                .map(|m| (*m).to_string())
                .collect();
            let Some(why) = unserved_reason(&markers, served_modules.contains(id)) else {
                continue;
            };
            let (n, parts) = module_rom_files(&mdir);
            if n == 0 {
                continue;
            }
            f.push(Finding {
                level: Level::Warn,
                check: "module content not served",
                detail: if why == "skip_mount" {
                    format!(
                        "{id} ships {n} file(s) under {} and is served by nothing: it carries a \
                         `skip_mount` marker, so the Suite leaves its tree alone. If you did not \
                         put that marker there, something else did -- a module's own bootloop \
                         guard writes one and never clears it, and the module then stays enabled \
                         and inert indefinitely. Delete /data/adb/modules/{id}/skip_mount to serve \
                         it, unless the module mounts its own content on purpose.",
                        parts.join(" ")
                    )
                } else {
                    format!(
                        "{id} ships {n} file(s) under {} and is served by nothing, with no \
                         disable/remove/skip_mount marker to explain it. That is the Suite's \
                         problem, not the module's: run `nomount plan` for the per-file refusal \
                         reasons.",
                        parts.join(" ")
                    )
                },
            });
        }
    }

    for (module, script, kind, hit) in scan_module_incompat() {
        f.push(Finding {
            level: kind.level(),
            check: kind.check(),
            detail: format!(
                "{module} ({script}): `{hit}`. {}{}",
                kind.explain(),
                reached_only_if_sourced(&script)
            ),
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

    if let (Ok(raw), Ok(hide)) = (
        std::fs::read_to_string("/data/adb/nomount/blocklist"),
        crate::blocklist::read(),
    ) {
        let hidden: std::collections::HashSet<String> = hide.into_iter().collect();
        let stale: Vec<String> = raw
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .filter(|l| !Path::new("/data/adb/modules").join(l).is_dir())
            .filter(|l| hidden.contains(*l))
            .map(str::to_string)
            .collect();
        if !stale.is_empty() {
            let names = if crate::blocklist::redact_hide_list() {
                "names redacted".to_string()
            } else {
                stale.join(", ")
            };
            f.push(Finding {
                level: Level::Info,
                check: "stale legacy blocklist entries",
                detail: format!(
                    "{} entry/entries in /data/adb/nomount/blocklist are hidden apps ({}). They moved \
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
            level: Level::Info,
            check: "manager kernel umount ON",
            detail: match crate::bind::tracked_result() {
                Ok(v) if v.is_empty() => "your manager's \"Kernel umount\" is ON. Nothing the \
                     Suite serves on this device is a mount, so it has nothing to unmount. Hide \
                     per app with `nomount uid block <pkg>`."
                    .to_string(),
                Ok(v) => {
                    let binds = v.len();
                    format!(
                        "your manager's \"Kernel umount\" is ON, and this device has {binds} \
                         bind mount(s) of ours - my_* is served by a real bind unless the \
                         my_hookless trial is on. The switch does hide those from an app's \
                         mount table, and it is the only thing that does; it cannot touch the \
                         injections, which are not mounts."
                    )
                }
                Err(e) => format!(
                    "your manager's \"Kernel umount\" is ON. Whether this device carries bind \
                     mounts of ours could not be read ({} - {e}), so it is unknown whether the \
                     switch has anything to unmount here. Either way it cannot touch the \
                     injections, which are not mounts.",
                    crate::bind::BINDS_LIST
                ),
            },
        });
    }

    if kernel_umount.is_none() && crate::manager::ksu_manager_present() {
        f.push(Finding {
            level: Level::Info,
            check: "manager kernel umount unknown",
            detail: match crate::bind::tracked_result() {
                Ok(v) if v.is_empty() => "your manager's \"Kernel umount\" could not be read, so \
                     it is UNKNOWN rather than off. Nothing the Suite serves on this device is a \
                     mount, so it has nothing to unmount either way."
                    .to_string(),
                Ok(v) => {
                    let binds = v.len();
                    format!(
                        "your manager's \"Kernel umount\" could not be read, so it is UNKNOWN \
                         rather than off - and this device has {binds} bind mount(s) of ours \
                         (my_* is served by a real bind unless the my_hookless trial is on). \
                         That switch is the only thing that hides those from an app's mount \
                         table, so it is worth checking in your manager."
                    )
                }
                Err(e) => format!(
                    "your manager's \"Kernel umount\" could not be read, so it is UNKNOWN rather \
                     than off, and neither could this device's bind record ({} - {e}), so \
                     whether there is anything for it to unmount is unknown too. The injections \
                     are unaffected either way; they are not mounts.",
                    crate::bind::BINDS_LIST
                ),
            },
        });
    }

    let nm = Nm::new();
    let engine = nm.version().ok();
    let live_ok = engine.is_some();
    let mut hide_list_unreadable = false;
    let hidden_apps = match crate::blocklist::read() {
        Ok(v) => v,
        Err(e) => {
            hide_list_unreadable = true;
            f.push(Finding {
                level: Level::Unmeasured,
                check: "hide list not readable",
                detail: format!(
                    "the per-app hide list could not be read ({e:#}), so the checks that ask whether a hidden app is served consistently did not run."
                ),
            });
            Vec::new()
        }
    };
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
                level: Level::Unmeasured,
                check: "plan live-rule checks did not run",
                detail: format!(
                    "the engine answered its version but would not list its rules ({e:#}), so \
                     the checks that compare the plan against the live rules were skipped. The \
                     device section reports the dump failure itself; run `nomount check --device` \
                     if you only ran the plan."
                ),
            });
        }
        if let Ok(list) = listed {
            let live = crate::nm::parse_list(&list);
            let durable: Option<HashSet<PathBuf>> = crate::whiteout::read()
                .ok()
                .map(|v| v.into_iter().map(PathBuf::from).collect());
            let absorbed: Option<HashSet<PathBuf>> =
                match (
                    crate::absorb::read_absorbed_targets(),
                    crate::absorb::read_absorbed_tmpfs_targets(),
                ) {
                    (Ok(mut a), Ok(t)) => {
                        a.extend(t);
                        Some(a)
                    }
                    _ => None,
                };
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
                if let Some(part) = partition_of(target).filter(|_| fd_note_applies(r.kind)) {
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

    if live_ok && !hidden_apps.is_empty() && pm_rules > 0 && (15..17).contains(&engine_v) {
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
        let listed = nm.ghost_list();
        if let Err(e) = &listed {
            f.push(Finding {
                level: Level::Unmeasured,
                check: "ghost cloak could not be read",
                detail: format!(
                    "the engine would not list its hidden paths ({e:#}), so the existence cloak was not tested on this kernel. This is not a pass."
                ),
            });
        }
        if let Ok(txt) = &listed {
            let (gpaths, guids) = parse_ghost_tables(txt);
            if !txt.trim().is_empty() && gpaths.is_empty() && guids.is_empty() {
                f.push(Finding {
                    level: Level::Unmeasured,
                    check: "ghost cloak list could not be parsed",
                    detail: format!(
                        "the engine answered `nm l g` with {} byte(s), but no line matched the                          expected `p /abs/path` or `u <uid>` grammar, so the existence cloak was                          not tested. The kernel's ghost_get_rule() has probably changed format.                          This is not a pass.",
                        txt.trim().len()
                    ),
                });
            }
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
                let who = hidden_uid_label(uid, crate::blocklist::redact_hide_list());
                if !visible.is_empty() {
                    f.push(Finding {
                        level: Level::Error,
                        check: "ghost cloak over-reaches",
                        detail: format!(
                            "{} of {checked} sampled path(s) are still visible to {who} - they \
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
                if unknown > 0 && !(visible.is_empty() && leaked.is_empty()) {
                    f.push(Finding {
                        level: Level::Unmeasured,
                        check: "ghost cloak only partly sampled",
                        detail: format!(
                            "{unknown} of {attempted} sampled path(s) could not be probed at                              all, so the finding(s) above speak for {} path(s), not the whole                              sample",
                            attempted - unknown
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
                        level: if unknown > 0 { Level::Unmeasured } else { Level::Info },
                        check: if unknown > 0 {
                            "ghost cloak only partly verified"
                        } else {
                            "ghost cloak verified on this kernel"
                        },
                        detail: if unknown > 0 {
                            format!(
                                "{absent} of {attempted} sampled path(s) look exactly like a path that never \
             existed, to {who} - but {unknown} could not be probed, so this is not a complete answer"
                            )
                        } else {
                            format!(
                                "{absent} of {} hidden path(s) sampled: each looks exactly like a path that never \
             existed, to {who}. Measured here, not assumed from the build.",
                                gpaths.len()
                            )
                        },
                    });
                }
            } else {
                let nothing_hidden = hidden_apps.is_empty() && !hide_list_unreadable;
                let nothing_injected = !plan.iter().any(|e| e.kind == PlanKind::Inject);
                f.push(Finding {
                    level: if nothing_hidden || nothing_injected {
                        Level::NotApplicable
                    } else {
                        Level::Unmeasured
                    },
                    check: "ghost cloak not populated",
                    detail: if nothing_hidden {
                        "nothing is hidden on this device, so the existence cloak has nothing \
                         to guard - it is only armed for apps on the hide list. Nothing to test."
                            .to_string()
                    } else if hide_list_unreadable {
                        "the hide list could not be read, so whether anything should be cloaked \
                         is unknown - not a pass, and not a \"nothing to test\" either."
                            .to_string()
                    } else {
                        format!(
                            "the engine returned {} hidden path(s) and {} hidden uid(s); both tables must be \
             non-empty for any guard to fire, so nothing was tested - a kernel built without _ghost \
             answers exactly the same way",
                            gpaths.len(),
                            guids.len()
                        )
                    },
                });
            }
        }
    }

    {
        let hidden_any = !hidden_apps.is_empty();
        let mode = crate::blocklist::hide_isolated();
        if hidden_any {
            f.push(Finding {
                level: if mode == 0 { Level::Warn } else { Level::Info },
                check: "isolated-process pools",
                detail: match mode {
                    0 => "hiding covers neither isolated pool. A hidden app can read through its own isolated child and see every injection, which is the leak the pools exist to close. `nomount uid isolated both` unless you specifically want the other side of this trade."
                        .to_string(),
                    3 => "hiding covers both isolated pools (the default): a hidden app cannot read through its own isolated child, but an unblocked app can tell its own view apart from its isolated child's and prove injection that way. `nomount uid isolated none` takes the other side of the trade."
                        .to_string(),
                    m => format!(
                        "hiding covers {} only. Same trade as the default, on one pool.",
                        if m == 1 { "the app-zygote pool" } else { "the platform pool" }
                    ),
                },
            });
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

    let surveyed = crate::absorb::survey();
    if let Err(e) = &surveyed {
        f.push(Finding {
            level: Level::Unmeasured,
            check: "mount table not readable",
            detail: format!(
                "the mount table could not be read ({e:#}), so NO mount check ran. This is not \"no mounts\": a module mount left standing is visible to any app that reads its own /proc/self/mountinfo."
            ),
        });
    }
    for s in surveyed.unwrap_or_default() {
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
                 blocks, so its size still counts the hidden entry. An app that checks the \
                 folder's size can tell something was removed from it. There is nothing to \
                 fix: the module works, and refusing to hide these would break it. {}{}",
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

    #[test]
    fn only_the_silently_broken_kinds_are_loud() {
        assert_eq!(Incompat::RomWrite.level(), Level::Warn);
        assert_eq!(Incompat::MagiskMirror.level(), Level::Warn);
        assert_eq!(Incompat::ImageBacked.level(), Level::Info);
        assert_eq!(verdict_of(&Level::Info).severity(), "info");
        assert_eq!(verdict_of(&Level::Warn).severity(), "attention");
    }

    #[test]
    fn a_capability_probe_is_not_an_image_backed_module() {
        assert_eq!(
            classify_incompat_line("if command -v nsenter >/dev/null 2>&1 \\"),
            None,
            "probing for a tool must not be reported as using it"
        );
        for probe in [
            "command -v losetup >/dev/null",
            "which nsenter >/dev/null 2>&1",
            "type -p unshare",
            "hash chroot 2>/dev/null",
            "if ! command -v losetup; then return; fi",
        ] {
            assert_eq!(classify_incompat_line(probe), None, "probe reported as use: {probe}");
        }
    }

    #[test]
    fn a_sourced_helper_is_followed() {
        assert_eq!(sourced_scripts(". $MODDIR/sh/compatible.sh"), vec!["sh/compatible.sh"]);
        assert_eq!(sourced_scripts("source ${MODPATH}/util_functions.sh"), vec!["util_functions.sh"]);
        assert_eq!(sourced_scripts(r#"sh "$MODDIR/rmlwk.sh" --update-hosts"#), vec!["rmlwk.sh"]);
        assert_eq!(
            sourced_scripts(". $MODDIR/a.sh
source $MODPATH/a.sh"),
            vec!["a.sh"]
        );
    }

    #[test]
    fn sourced_scripts_stays_inside_the_module() {
        for quiet in [
            ". /system/etc/somewhere.sh",       // absolute, not module-relative
            ". $MODDIR/../../etc/passwd",       // traversal
            "# . $MODDIR/commented.sh",         // comment
            "wish $MODDIR/notakeyword.sh",      // `sh ` inside another word
            "echo 'nothing to source here'",
        ] {
            assert!(sourced_scripts(quiet).is_empty(), "should not follow: {quiet}");
        }
    }

    #[test]
    fn a_module_that_binds_over_the_rom_is_named() {
        for real in [
            r#"mount --bind "$MODDIR/system/etc/hosts" /system/etc/hosts"#,
            "mount -o bind $MODDIR/hosts /system/etc/hosts",
            "mount -t overlay overlay -o lowerdir=/system/etc:$MODDIR/etc /system/etc",
            "mount --rbind $MODDIR/fonts /system/fonts",
        ] {
            assert_eq!(
                classify_incompat_line(real),
                Some(Incompat::SelfMount),
                "missed a real self-mount: {real}"
            );
        }
    }

    #[test]
    fn a_bind_through_a_variable_is_resolved() {
        let script = concat!(
            "#!/system/bin/sh
",
            "system_hosts=\"/system/etc/hosts\"
",
            "hosts_file=\"$MODDIR/system/etc/hosts\"
",
            "mount --bind \"$hosts_file\" \"$system_hosts\" || {
",
        );
        let vars = rom_path_vars(script);
        assert_eq!(vars.get("system_hosts").map(String::as_str), Some("/system/etc/hosts"));
        assert!(!vars.contains_key("hosts_file"), "a module-tree path must not be taken for a ROM path");

        let line = r#"mount --bind "$hosts_file" "$system_hosts" || {"#;
        assert_eq!(classify_incompat_line(line), None, "precondition: unresolved, it is invisible");
        assert_eq!(
            classify_incompat_line(&expand_rom_vars(line, &vars)),
            Some(Incompat::SelfMount),
            "resolved, Re-Malwack's real bind must be named"
        );
    }

    #[test]
    fn overlapping_variable_names_expand_longest_first() {
        let vars = rom_path_vars("hosts=/system/etc/hosts
hosts_file=/system/etc/hosts.d/x
");
        assert_eq!(
            expand_rom_vars("mount --bind $hosts_file /tmp/x", &vars),
            "mount --bind /system/etc/hosts.d/x /tmp/x"
        );
    }

    #[test]
    fn the_fd_allowlist_tally_counts_only_injects() {
        assert!(fd_note_applies(crate::nm::LiveKind::Inject));
        assert!(
            !fd_note_applies(crate::nm::LiveKind::Whiteout),
            "a whiteout is a deletion, not an injected file"
        );
        assert!(
            !fd_note_applies(crate::nm::LiveKind::VirtualDir),
            "a virtual dir is a directory the engine made, not an injected file"
        );
    }

    #[test]
    fn a_convergence_symlink_is_not_counted_as_shipped_content() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        std::fs::create_dir_all(root.join("product/app")).unwrap();
        std::fs::write(root.join("product/app/Foo"), b"x").unwrap();
        std::fs::create_dir_all(root.join("system")).unwrap();
        symlink("../product", root.join("system/product")).unwrap();
        symlink("Foo", root.join("product/app/Bar")).unwrap();

        assert_eq!(
            count_files(&root.join("product"), 0),
            2,
            "one file plus one leaf symlink"
        );
        assert_eq!(
            count_files(&root.join("system"), 0),
            0,
            "a symlink to a directory is the convergence link, not shipped content"
        );
    }

    #[test]
    fn a_dangling_symlink_still_counts_as_shipped_content() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("product")).unwrap();
        symlink("nowhere", d.path().join("product/Gone")).unwrap();
        assert_eq!(count_files(&d.path().join("product"), 0), 1);
    }

    #[test]
    fn a_hit_inside_a_sourced_helper_is_marked_conditional() {
        for entry in ENTRY_SCRIPTS {
            assert_eq!(
                reached_only_if_sourced(entry),
                "",
                "{entry} is run by the manager; nothing is conditional about it"
            );
        }
        for helper in ["mountify.sh", "sh/compatible.sh", "lib/mount.sh"] {
            assert!(
                reached_only_if_sourced(helper).contains("SOURCES"),
                "{helper} is only reached through a `.`, and the report has to say so"
            );
        }
    }

    #[test]
    fn the_ghost_table_parser_separates_empty_from_unparseable() {
        let (p, u) = parse_ghost_tables("u 10123
p /system/app/Foo/Foo.apk
p /product/x.apk
");
        assert_eq!(u, vec![10123]);
        assert_eq!(p.len(), 2, "both p-lines parse");

        let (p, u) = parse_ghost_tables("");
        assert!(p.is_empty() && u.is_empty(), "empty input yields empty tables");

        let drift = "path=/system/app/Foo/Foo.apk
uid=10123
";
        let (p, u) = parse_ghost_tables(drift);
        assert!(
            p.is_empty() && u.is_empty(),
            "drifted grammar parses to nothing - the caller cannot tell this from 'no ghosts'              without checking the raw text, and doctor.rs does"
        );
        assert!(!drift.trim().is_empty(), "...and the raw text is what distinguishes them");

        let (p, _) = parse_ghost_tables("p not/absolute
");
        assert!(p.is_empty(), "only absolute paths are accepted");
    }

    #[test]
    fn the_kernel_umount_note_depends_on_whether_binds_exist() {
        let src = include_str!("doctor.rs");
        let at = src
            .find("check: \"manager kernel umount ON\",")
            .expect("finding gone or renamed");
        let unknown_at = src
            .find("check: \"manager kernel umount unknown\",")
            .expect("finding gone or renamed");
        let end = unknown_at
            + src[unknown_at..]
                .find("    let nm = Nm::new();")
                .expect("the statement after the umount findings moved; re-bind this test");
        assert!(
            end - unknown_at < 4_000,
            "the 'unknown' block measured {} bytes - that is the whole function again, not one \
             finding, so the assertions below prove nothing",
            end - unknown_at
        );
        for (what, block) in [("ON", &src[at..unknown_at]), ("unknown", &src[unknown_at..end])] {
            assert!(
                block.contains("crate::bind::tracked_result()"),
                "{what}: the note must read the live bind record, not assert that there are \
                 none -- and through the FALLIBLE reader, so an unreadable binds.list is not \
                 rendered as zero binds"
            );
            assert!(
                block.contains("Err(e) =>"),
                "{what}: an unreadable binds.list needs its own arm. This string is the WebUI \
                 manager banner's whole text, and a read error must not print as \"Nothing the \
                 Suite serves on this device is a mount\""
            );
        }
        assert!(
            src[at..unknown_at].contains("hide those") || src[at..unknown_at].contains("does hide"),
            "with binds present it must say the switch would hide them"
        );
    }

    #[test]
    fn findings_no_detector_can_see_are_notes() {
        let src = include_str!("doctor.rs");
        for name in [
            "my_* served by injection",
            "manager kernel umount ON",
            "manager kernel umount unknown",
        ] {
            let at = src
                .find(&format!("check: \"{name}\","))
                .unwrap_or_else(|| panic!("{name}: finding gone or renamed - keep the rule with it"));
            let before = &src[at.saturating_sub(200)..at];
            assert!(
                before.contains("level: Level::Info,"),
                "{name} is invisible to every detector and changes nothing an app can \
                 observe; it must not be a warning"
            );
        }
    }

    #[test]
    fn when_the_my_hookless_marker_comes_back_depends_on_the_writer() {
        assert!(
            marker_returns_when(&["post-fs-data.sh".into()]).contains("next boot"),
            "a boot script really does re-create it every boot"
        );
        assert!(
            marker_returns_when(&["service.sh".into(), "stage_overrides.sh".into()])
                .contains("next boot"),
            "any boot script among the writers means it comes back at boot"
        );
        let helper = marker_returns_when(&["stage_overrides.sh".into()]);
        assert!(
            !helper.contains("next boot"),
            "an action helper must not be described as a boot script: {helper}"
        );
        assert!(
            helper.contains("action button"),
            "say what does bring it back instead: {helper}"
        );
    }

    #[test]
    fn a_module_that_ships_content_and_serves_nothing_is_named() {
        assert_eq!(unserved_reason(&["skip_mount".into()], false), Some("skip_mount"));
        assert_eq!(unserved_reason(&[], false), Some("none"));
    }

    #[test]
    fn a_disabled_or_served_module_is_not_a_finding() {
        assert_eq!(unserved_reason(&["disable".into()], false), None);
        assert_eq!(unserved_reason(&["remove".into()], false), None);
        assert_eq!(unserved_reason(&[], true), None);
        assert_eq!(unserved_reason(&["skip_mount".into()], true), None);
        assert_eq!(unserved_reason(&["skip_mount".into(), "remove".into()], false), None);
    }

    #[test]
    fn my_partitions_are_not_invisible() {
        assert_eq!(
            classify_incompat_line(
                "mount --bind $MODDIR/my_product/media/bootanimation/ /my_product/media/bootanimation/"
            ),
            Some(Incompat::SelfMount),
            "the real OP11 line that went unreported"
        );
        assert_eq!(
            classify_incompat_line("cp /data/x /my_stock/etc/foo.xml"),
            Some(Incompat::RomWrite)
        );
        assert_eq!(
            classify_incompat_line("rm -rf /my_region/app/Bar"),
            Some(Incompat::RomWrite)
        );
        assert_eq!(
            classify_incompat_line("mount -o rw,remount /my_bigball"),
            Some(Incompat::RomWrite)
        );
        let vars = rom_path_vars("boot_dir=\"/my_product/media/bootanimation\"\n");
        assert_eq!(vars.get("boot_dir").map(String::as_str), Some("/my_product/media/bootanimation"));
    }

    #[test]
    fn a_wider_partition_list_does_not_over_match() {
        for quiet in [
            "mount --bind /data/x /systemfoo/y",
            "mount --bind /data/x /my_productfoo/y",
            "cp /data/x /notsystem/y",
            "mount --bind $MODDIR/my_product/a $MODDIR/my_product/b",
        ] {
            assert_eq!(classify_incompat_line(quiet), None, "over-counted: {quiet}");
        }
        assert_eq!(
            classify_incompat_line("mount --bind $MODDIR/x /system_ext/etc/y"),
            Some(Incompat::SelfMount)
        );
    }

    #[test]
    fn self_mount_does_not_over_count() {
        for quiet in [
            r#"ui_print "- Setting up mount hosts...""#,
            r#"echo "failed to mount $hosts_file to $system_hosts""#,
            "# mount IDs start with 500k or 2b",
            "umount /system/etc/hosts",
            "mount --bind /dev/null /system/etc/hosts && umount /system/etc/hosts",
            "mount --bind $MODDIR/a $MODDIR/b",
            "mount -o bind /data/adb/foo /data/adb/bar",
            "mount --bind /data/x /systemfoo/y",
        ] {
            assert_eq!(classify_incompat_line(quiet), None, "over-counted: {quiet}");
        }
    }

    #[test]
    fn the_incompat_scanner_sees_what_it_missed_and_stops_accusing_what_it_should_not() {
        let real = "umount /system/etc/hosts 2>/dev/null; mount --bind $MODDIR/hosts /system/etc/hosts";
        assert_eq!(classify_incompat_line(real), Some(Incompat::SelfMount), "missed: {real}");
        for real in [
            "mkdir -p /system/etc/foo",
            "echo 1 > /system/etc/foo",
            "printf 'x' >> /system/build.prop",
            "sed -i s/a/b/ /system/build.prop",
            "install -m 644 $MODDIR/x /system/etc/x",
            "mount -o remount,rw /system/",
        ] {
            assert_eq!(classify_incompat_line(real), Some(Incompat::RomWrite), "missed: {real}");
        }

        for quiet in [
            r#"cp "$MODDIR/foo" "$TMPDIR/foo"   # replaces /system/etc/foo"#,
            r#"ui_print "nsenter is not available""#,
            r#"echo "run losetup first""#,
        ] {
            assert_eq!(classify_incompat_line(quiet), None, "over-counted: {quiet}");
        }

        for real in [
            "/system/bin/nsenter --mount=/proc/1/ns/mnt sh",
            "LOOP=\"$(/system/bin/losetup -sf \"$F\")\"",
        ] {
            assert_eq!(classify_incompat_line(real), Some(Incompat::ImageBacked), "missed: {real}");
        }
    }

    #[test]
    fn an_nsenter_replicated_bind_stays_image_backed() {
        assert_eq!(
            classify_incompat_line("nsenter -t 1 -m -- mount --bind $MODDIR/etc /system/etc"),
            Some(Incompat::ImageBacked)
        );
        assert_eq!(
            classify_incompat_line(
                "/system/bin/nsenter --mount=/proc/$zp/ns/mnt -- /bin/mount --rbind $SYS_CERT /system/etc/security/cacerts"
            ),
            Some(Incompat::ImageBacked)
        );
    }

    #[test]
    fn real_image_backed_modules_are_still_named() {
        assert_eq!(
            classify_incompat_line("mount -o loop $MODDIR/so.img /data/adb/tmp/so_mount"),
            Some(Incompat::ImageBacked)
        );
        assert_eq!(
            classify_incompat_line("LOOP_DEV=\"$(/system/bin/losetup -sf \"$MODFILEMOUNTED\")\""),
            Some(Incompat::ImageBacked)
        );
        for real in ["chroot /data/local/tmp/rootfs sh", "nsenter --mount=/proc/1/ns/mnt sh", "mkfs.ext4 img"] {
            assert_eq!(classify_incompat_line(real), Some(Incompat::ImageBacked), "missed: {real}");
        }
    }

    #[test]
    fn probing_then_using_on_one_line_still_counts() {
        assert_eq!(
            classify_incompat_line("command -v losetup >/dev/null && losetup -sf $IMG"),
            Some(Incompat::ImageBacked)
        );
    }

    #[test]
    fn no_explanation_carries_a_raw_newline() {
        for k in [
            Incompat::RomWrite,
            Incompat::MagiskMirror,
            Incompat::ImageBacked,
            Incompat::SelfMount,
        ] {
            assert!(
                !k.explain().contains('\n'),
                "{:?}.explain() carries a raw newline - use a `\\` continuation, not `\\n`",
                k
            );
            assert!(!k.check().contains('\n'), "{k:?}.check() carries a raw newline");
            assert!(!k.explain().contains("   "), "{k:?}.explain() carries collapsed indentation");
        }
    }

    #[test]
    fn rm_is_seen_at_the_start_of_a_line_and_after_a_word() {
        assert_eq!(
            classify_incompat_line("rm -rf /system/app/Foo"),
            Some(Incompat::RomWrite),
            "a line that begins with rm was the miss"
        );
        assert_eq!(
            classify_incompat_line("su -c rm -rf /system/app/Foo"),
            Some(Incompat::RomWrite)
        );
        assert_eq!(classify_incompat_line("set_perm /system/bin/foo 0 0 0755"), None);
        assert_eq!(classify_incompat_line("perm /system/bin/foo"), None);
        assert_eq!(classify_incompat_line("rm -rf /data/adb/foo"), None);
    }

    #[test]
    fn the_older_precision_fixes_still_hold() {
        assert_eq!(classify_incompat_line("set_perm /system/bin/foo 0 0 0755"), None);
        assert_eq!(
            classify_incompat_line("cp /system/etc/hosts $MODPATH/system/etc/hosts"),
            None
        );
        assert_eq!(
            classify_incompat_line("cp /data/x /system/etc/hosts"),
            Some(Incompat::RomWrite)
        );
    }

    #[test]
    fn copying_out_of_the_rom_is_not_a_rom_write() {
        assert_eq!(
            classify_incompat_line(
                r#"su -c "cp -r /system/system/etc/device_features/* /data/adb/HyperUnlocked/bakxml/""#
            ),
            None
        );
        assert_eq!(classify_incompat_line("cp -r /product/etc/x /data/local/tmp/"), None);
        assert_eq!(
            classify_incompat_line("cp $MODDIR/system/etc/security/cacerts/* /system/etc/security/cacerts/"),
            Some(Incompat::RomWrite)
        );
        assert_eq!(
            classify_incompat_line("mount -o rw,remount -t auto /system || mount /system;"),
            Some(Incompat::RomWrite)
        );
    }

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
    fn an_unreadable_exemption_list_is_unmeasured_not_clean() {
        let plan: Vec<PlanEntry> = Vec::new();
        let live = crate::nm::parse_list("/system/etc/hidden (whiteout)
");
        let f = reconcile_plan_and_live(&plan, &live, None, None);
        assert_eq!(f.len(), 1, "no extra-rule accusation may be made: {:?}", f[0].detail);
        assert_eq!(f[0].check, "live rules not fully accounted for");
        assert_eq!(f[0].level, Level::Unmeasured);
        assert_eq!(
            verdict_of(&f[0].level),
            Verdict::Unmeasured,
            "and it must reach the report as Unmeasured, so `complete()` goes false"
        );
    }

    #[test]
    fn expansion_levels_escalate_but_never_refuse() {
        assert_eq!(expansion_level(1), None);
        assert_eq!(expansion_level(15), None);
        assert_eq!(expansion_level(49), None);
        assert_eq!(expansion_level(75), Some(Level::Info));
        assert_eq!(expansion_level(199), Some(Level::Info));
        assert_eq!(expansion_level(224), Some(Level::Info));
        assert_eq!(expansion_level(20_000), Some(Level::Info), "no count is an alarm");
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
                check: "whiteout leaves a measurable hole",
                detail: "mod_a: 3 path(s) the engine cannot fully mask".into(),
            },
            Finding {
                level: Level::Info,
                check: "whiteout leaves a measurable hole",
                detail: "mod_b: 9 path(s) the engine cannot fully mask".into(),
            },
            Finding {
                level: Level::Info,
                check: "no such partition",
                detail: "7 rule(s) target /mi_ext which does not exist".into(),
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
        assert_eq!(checks[2].id, "whiteout-leaves-a-measurable-hole-mod-a");
        assert_eq!(checks[3].id, "whiteout-leaves-a-measurable-hole-mod-b");
        assert_eq!(checks[4].id, "no-such-partition-mi-ext");
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
    fn redaction_covers_the_doctor_readers() {
        assert_eq!(hidden_uid_label(10422, false), "hidden uid 10422");
        let redacted = hidden_uid_label(10422, true);
        assert_eq!(redacted, "a hidden app");
        assert!(!redacted.contains("10422"), "the appid must not survive redaction");
        for uid in [10000u32, 10384, 10471, 1_010_471, 99_999] {
            assert!(
                !hidden_uid_label(uid, true).contains(&uid.to_string()),
                "uid {uid} leaked through redaction"
            );
        }
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
        assert!(is_partition_root(Path::new("/")), "the filesystem root is one too");
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
