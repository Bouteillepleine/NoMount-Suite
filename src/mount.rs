//! Metamodule mount pass for the NoMount Suite

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

fn is_whiteout_marker(ft: &fs::FileType, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    ft.is_char_device()
        && fs::symlink_metadata(path).map(|m| m.rdev() == 0).unwrap_or(false)
}

fn is_opaque_dir(p: &Path) -> bool {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    let (Ok(path), Ok(name)) = (
        CString::new(p.as_os_str().as_bytes()),
        CString::new("trusted.overlay.opaque"),
    ) else {
        return false;
    };
    let mut buf = [0u8; 4];
    let n = unsafe {
        libc::lgetxattr(path.as_ptr(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len())
    };
    n > 0 && buf[0] == b'y'
}

use anyhow::{Context, Result};

use crate::nm::Nm;

pub(crate) const MODULES_DIR: &str = "/data/adb/modules";
const PASS_LOCK: &str = "/data/adb/nomount/pass.lock";

/// RAII holder for the pass lock; the flock releases when it drops
pub(crate) struct PassLock(std::fs::File);

/// How long a pass will wait for another pass before giving up and running unserialised
pub(crate) const PASS_LOCK_WAIT: u64 = 25;

/// The bootloop guard's marker: present means the Suite parked itself
pub const DISABLED_MARKER: &str = "/data/adb/nomount/disabled";

/// Has the bootloop guard parked the Suite?
pub fn guard_tripped() -> bool {
    Path::new(DISABLED_MARKER).exists()
}

/// Take the process-wide pass lock. Timing out and proceeding unserialised is the lesser
/// evil: the passes are idempotent, and stalling the boot is not.
pub(crate) fn pass_lock() -> Option<PassLock> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let f = match fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(PASS_LOCK)
    {
        Ok(f) => f,
        Err(e) => {
            eprintln!(
                "nomount: cannot open {PASS_LOCK} ({e}); continuing unserialised rather than \
                 stalling the boot -- a concurrent pass can observe the engine empty across \
                 `nm clear`"
            );
            return None;
        }
    };
    for _ in 0..(PASS_LOCK_WAIT * 10) {
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Some(PassLock(f));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    eprintln!(
        "nomount: another pass still holds {PASS_LOCK} after {PASS_LOCK_WAIT}s; \
         continuing unserialised rather than stalling the boot"
    );
    None
}

impl Drop for PassLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

const BUILTIN_BLOCKLIST: &[&str] = &["kernelnosu", "scene_swap_controller", "AAaTempSpoof"];
const BLOCKLIST_FILE: &str = "/data/adb/nomount/blocklist";

const NON_PARTITION_ROOTS: &[&str] = &[
    "data", "data_mirror", "mnt", "dev", "proc", "sys", "cache", "metadata", "config",
    "storage", "sdcard", "apex", "tmp", "debug_ramdisk", "linkerconfig",
    "postinstall", "second_stage_resources", "bin", "sbin", "d",
];

fn is_partition_dir(name: &str) -> bool {
    is_real_partition(name)
}

fn is_root_symlink(name: &str) -> bool {
    !name.is_empty()
        && fs::symlink_metadata(format!("/{name}"))
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
}

fn is_real_partition(name: &str) -> bool {
    !name.is_empty()
        && !NON_PARTITION_ROOTS.contains(&name)
        && fs::symlink_metadata(format!("/{name}"))
            .map(|m| m.is_dir())
            .unwrap_or(false)
}

fn resolve_target_path(relative: &Path) -> Option<PathBuf> {
    let s = relative.to_str()?;
    if s.is_empty() {
        return None;
    }
    if let Some(rest) = s.strip_prefix("system/") {
        let x = rest.split('/').next().unwrap_or("");
        if is_real_partition(x) {
            return Some(PathBuf::from(format!("/{rest}")));
        }
    }
    Some(PathBuf::from(format!("/{s}")))
}

fn is_my_partition(target: &Path) -> bool {
    target
        .components()
        .nth(1)
        .and_then(|c| c.as_os_str().to_str())
        .map(|s| s.starts_with("my_"))
        .unwrap_or(false)
}

fn my_hookless_enabled() -> bool {
    Path::new(MY_HOOKLESS_MARKER).exists()
}

/// The `my_*` injection trial's opt-in marker
pub const MY_HOOKLESS_MARKER: &str = "/data/adb/nomount/my_hookless";

/// True if `target` is a partition root (`/product`, `/system`, `/vendor`, ...) rather
pub(crate) fn is_partition_root(target: &Path) -> bool {
    target.components().skip(1).count() <= 1
}

/// How a target may be served - the single answer both the native module plan and `absorb`
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Serve {
    Inject,
    Bind,
    Refuse(&'static str),
}

pub(crate) fn serve_mode(target: &Path) -> Serve {
    let Some(root) = target.components().nth(1).and_then(|c| c.as_os_str().to_str()) else {
        return Serve::Refuse("not a path under a partition");
    };
    if NON_PARTITION_ROOTS.contains(&root) {
        return Serve::Refuse("not a ROM partition");
    }
    if is_partition_root(target) {
        return Serve::Refuse("a bare partition root (injecting one bootloops zygote)");
    }
    if let Some(second) = target.components().nth(2).and_then(|c| c.as_os_str().to_str()) {
        if second == root {
            return Serve::Refuse(
                "the path repeats a partition name -- the module ships both `<part>/` and \
                 `system/<part>/`, and the installer nested one inside the other",
            );
        }
    }
    if is_my_partition(target) && !my_hookless_enabled() {
        return Serve::Bind;
    }
    Serve::Inject
}

/// May a whiteout be applied to `target`?
pub(crate) fn can_whiteout(target: &Path) -> Result<(), &'static str> {
    let Some(root) = target.components().nth(1).and_then(|c| c.as_os_str().to_str()) else {
        return Err("not a path under a partition");
    };
    if NON_PARTITION_ROOTS.contains(&root) {
        return Err("not a ROM partition");
    }
    if is_partition_root(target) {
        return Err("a bare partition root (masking one bootloops zygote)");
    }
    Ok(())
}

fn inject_would_mask_dir(target: &Path) -> bool {
    target.is_dir()
}

/// Must this target be unmounted before we serve it?
pub(crate) fn needs_unmount_before_serving(kind: PlanKind) -> bool {
    matches!(kind, PlanKind::Inject | PlanKind::Whiteout)
}

/// The order the engine must be fed: every inject, then every whiteout, each in plan order
pub(crate) fn apply_order(plan: &[PlanEntry]) -> Vec<&PlanEntry> {
    plan.iter()
        .filter(|e| e.kind == PlanKind::Inject)
        .chain(plan.iter().filter(|e| e.kind == PlanKind::Whiteout))
        .collect()
}

/// Is this path representable in the engine's wire format?
pub(crate) fn path_is_representable(p: &Path) -> Result<(), &'static str> {
    let Some(s) = p.to_str() else {
        return Err("its name is not valid UTF-8, which the rule format cannot carry");
    };
    if s.contains('\n') || s.contains('\r') {
        return Err("its name contains a newline, which would forge a second rule in `nm list`");
    }
    if s.contains('\t') {
        return Err("its name contains a tab, which is the separator in binds.list");
    }
    if s != s.trim() {
        return Err("its name begins or ends with whitespace, which `nm list` trims off -- \
                    the rule would read back as a different path that no prune could delete");
    }
    if s.contains(" -> ") {
        return Err("its name contains ` -> `, the separator between target and source");
    }
    if s.contains(" [UID:") {
        return Err("its name contains ` [UID:`, which `nm list` uses to split the uid off");
    }
    for suffix in [" (whiteout)", " (public)", " (virtual dir)"] {
        if s.ends_with(suffix) {
            return Err("its name ends in a marker `nm list` strips as a rule suffix");
        }
    }
    Ok(())
}

fn source_resolves(e: &PlanEntry) -> bool {
    e.kind != PlanKind::Inject || e.source.exists()
}

fn resolved_source_is_untrusted(resolved: &Path) -> bool {
    (resolved.starts_with("/data/") && !resolved.starts_with("/data/adb/"))
        || crate::health::is_shared_storage(resolved)
}

pub(crate) fn module_enabled(dir: &Path) -> bool {
    !dir.join("disable").exists()
        && !dir.join("remove").exists()
        && !dir.join("skip_mount").exists()
}

fn load_blocklist() -> HashSet<String> {
    let mut set: HashSet<String> = BUILTIN_BLOCKLIST.iter().map(|s| (*s).to_string()).collect();
    if let Ok(contents) = fs::read_to_string(BLOCKLIST_FILE) {
        for line in contents.lines() {
            let id = line.trim();
            if !id.is_empty() && !id.starts_with('#') {
                set.insert(id.to_string());
            }
        }
    }
    set
}

struct Stats {
    applied: u32,
    failed: u32,
    whiteouts: u32,
}

/// What the Suite intends to do for one module entry
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PlanKind {
    Inject,
    Whiteout,
    Bind,
}

/// One module entry the plan REFUSED, and why. Kept so `check --plan` can report it: the
/// refusal used to reach stderr and nowhere else, so a module that lost content this way
/// still produced a "clean" report. Two live modules on the audit device were in exactly
/// that state.
pub(crate) struct Refused {
    pub module: String,
    pub target: PathBuf,
    pub why: &'static str,
}

/// One intended operation, resolved but not yet applied
pub(crate) struct PlanEntry {
    pub module: String,
    pub target: PathBuf,
    pub source: PathBuf,
    pub kind: PlanKind,
}

fn expand_replacement(
    module: &str,
    stock_dir: &Path,
    module_dir: &Path,
    marker: &Path,
    depth: u32,
    out: &mut Vec<PlanEntry>,
) {
    if depth > 16 {
        eprintln!(
            "nomount: {module}: giving up expanding {} past depth 16",
            stock_dir.display()
        );
        return;
    }
    let stock_entries = match fs::read_dir(stock_dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    let mut entries: Vec<_> = stock_entries.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let name = entry.file_name();
        let stock_child = stock_dir.join(&name);
        let module_child = module_dir.join(&name);

        let shipped = fs::symlink_metadata(&module_child).ok();
        let stock_is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);

        match shipped {
            Some(m) if m.is_dir() && stock_is_dir => {
                expand_replacement(module, &stock_child, &module_child, marker, depth + 1, out);
            }
            Some(_) => {}
            None => {
                if can_whiteout(&stock_child).is_err() {
                    continue;
                }
                out.push(PlanEntry {
                    module: module.to_string(),
                    target: stock_child,
                    source: marker.to_path_buf(),
                    kind: PlanKind::Whiteout,
                });
            }
        }
    }
}

/// One target claimed by more than one module: the winner, and who it beat
pub(crate) struct Collision {
    pub target: PathBuf,
    pub winner: String,
    pub losers: Vec<String>,
}

/// Collapse entries claiming the same target, keeping the last
pub(crate) fn dedupe_by_target(plan: Vec<PlanEntry>) -> (Vec<PlanEntry>, Vec<Collision>) {
    let mut last: HashMap<PathBuf, usize> = HashMap::new();
    for (i, e) in plan.iter().enumerate() {
        last.insert(e.target.clone(), i);
    }
    if last.len() == plan.len() {
        return (plan, Vec::new());
    }
    let mut losers: HashMap<PathBuf, Vec<String>> = HashMap::new();
    for (i, e) in plan.iter().enumerate() {
        if last.get(&e.target) != Some(&i) {
            losers.entry(e.target.clone()).or_default().push(e.module.clone());
        }
    }
    let mut collisions: Vec<Collision> = Vec::new();
    let mut kept = Vec::with_capacity(last.len());
    for (i, e) in plan.into_iter().enumerate() {
        if last.get(&e.target) != Some(&i) {
            continue;
        }
        if let Some(mut l) = losers.remove(&e.target) {
            l.retain(|m| m != &e.module);
            l.sort_unstable();
            l.dedup();
            if !l.is_empty() {
                collisions.push(Collision {
                    target: e.target.clone(),
                    winner: e.module.clone(),
                    losers: l,
                });
            }
        }
        kept.push(e);
    }
    collisions.sort_by(|a, b| a.target.cmp(&b.target));
    (kept, collisions)
}

fn plan_tree(
    module: &str,
    module_root: &Path,
    dir: &Path,
    out: &mut Vec<PlanEntry>,
    refused: &mut Vec<Refused>,
) -> std::io::Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)?.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        let source = entry.path();
        let rel = match source.strip_prefix(module_root) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let Some(target) = resolve_target_path(rel) else {
            eprintln!(
                "nomount: {module}: skipping {} - its name is not valid UTF-8",
                source.display()
            );
            continue;
        };
        let unrepresentable = path_is_representable(&target)
            .err()
            .map(|w| ("target", w))
            .or_else(|| path_is_representable(&source).err().map(|w| ("source", w)));
        if let Some((what, why)) = unrepresentable {
            eprintln!(
                "nomount: {module}: skipping {} - {what} {why}",
                source.display()
            );
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();

        if ft.is_dir() {
            if is_opaque_dir(&source) && can_whiteout(&target).is_ok() {
                expand_replacement(module, &target, &source, &source, 0, out);
            }
            plan_tree(module, module_root, &source, out, refused)?;
        } else if name == ".replace" {
            if let Some(parent) = target.parent() {
                if can_whiteout(parent).is_err() {
                    continue;
                }
                if let Some(module_dir) = source.parent() {
                    expand_replacement(module, parent, module_dir, &source, 0, out);
                }
            }
        } else if is_whiteout_marker(&ft, &source) {
            if can_whiteout(&target).is_err() {
                continue;
            }
            out.push(PlanEntry {
                module: module.to_string(),
                target,
                source,
                kind: PlanKind::Whiteout,
            });
        } else {
            if ft.is_symlink() {
                let resolved = fs::canonicalize(&source).ok();
                if resolved.as_deref().map(resolved_source_is_untrusted).unwrap_or(false) {
                    eprintln!(
                        "nomount: {module}: skipping {} - it is a symlink resolving outside \
                         /data/adb; the engine follows it, so a non-root process would control \
                         the bytes served at {}",
                        source.display(),
                        target.display()
                    );
                    continue;
                }
                if resolved.as_deref().map(Path::is_dir).unwrap_or(false) {
                    eprintln!(
                        "nomount: {module}: skipping {} - it is a symlink to a directory, which \
                         the engine follows, so this would install a directory rule at {}. \
                         Ship the files individually.",
                        source.display(),
                        target.display()
                    );
                    continue;
                }
            }
            match serve_mode(&target) {
                Serve::Refuse(why) => {
                    eprintln!("nomount: {module}: skipping {} - {why}", target.display());
                    refused.push(Refused {
                        module: module.to_string(),
                        target: target.clone(),
                        why,
                    });
                }
                Serve::Bind => {
                    out.push(PlanEntry {
                        module: module.to_string(),
                        target,
                        source,
                        kind: PlanKind::Bind,
                    });
                }
                Serve::Inject if inject_would_mask_dir(&target) => {
                    eprintln!(
                        "nomount: {module}: skipping {} - it resolves to a live directory/mountpoint; \
                         injecting a file there would mask the whole directory (a module may only \
                         inject over a file)",
                        target.display()
                    );
                }
                Serve::Inject => out.push(PlanEntry {
                    module: module.to_string(),
                    target,
                    source,
                    kind: PlanKind::Inject,
                }),
            }
        }
    }
    Ok(())
}

fn unmount_before_serving(targets: &std::collections::HashSet<PathBuf>, target: &Path) -> bool {
    if !targets.contains(target) {
        return true;
    }
    if crate::absorb::umount_detach(target) {
        eprintln!("nomount: unmounted {} before serving it", target.display());
    }
    let gone = !crate::absorb::still_mounted(target);
    if !gone {
        eprintln!(
            "nomount: {} is still mounted and will not unmount; serving it anyway would strand \
             that mount in mountinfo, so it is left unserved",
            target.display()
        );
    }
    gone
}

/// Does applying this whiteout leave a measurable hole?
pub(crate) fn whiteout_leaves_hole(target: &Path) -> bool {
    if !crate::whiteout::measurable_hole(target) {
        return false;
    }
    static FORCED: std::sync::OnceLock<HashSet<PathBuf>> = std::sync::OnceLock::new();
    let forced = FORCED.get_or_init(|| {
        crate::whiteout::read().unwrap_or_default().into_iter().map(PathBuf::from).collect()
    });
    !forced.contains(target)
}

fn warn_whiteout_hole(target: &Path, module: &str) {
    if whiteout_leaves_hole(target) {
        eprintln!(
            "nomount: applying whiteout {} from {module}: its parent is multi-block erofs (or \
             the engine predates v13), so the size and link count still count the hidden entry \
             and cannot be recomputed. Applied because declining it would make {module} a \
             no-op; see `nomount check --plan`.",
            target.display()
        );
    }
}

/// Build the full plan for every enabled, non-blocklisted module
pub(crate) fn collect_plan() -> Result<(Vec<PlanEntry>, u32, Vec<Refused>)> {
    let blocklist = load_blocklist();
    let mut plan = Vec::new();
    let mut refused: Vec<Refused> = Vec::new();
    let mut skipped = 0u32;
    let dirs = fs::read_dir(MODULES_DIR)
        .with_context(|| format!("cannot enumerate {MODULES_DIR} -- refusing to treat that as \"no modules installed\", which would clear every rule"))?;
    let mut dirs: Vec<_> = dirs.flatten().collect();
    dirs.sort_by_key(|e| e.file_name());
    for entry in dirs {
        let mdir = entry.path();
        if !mdir.is_dir() || !module_enabled(&mdir) {
            continue;
        }
        let Some(id) = mdir.file_name().and_then(|n| n.to_str()) else {
            eprintln!(
                "nomount: skipping the module at {} - its directory name is not valid UTF-8",
                mdir.display()
            );
            continue;
        };
        if id.starts_with('.') {
            eprintln!("nomount: skipping {id} - a dot-prefixed module id is not a valid module");
            continue;
        }
        if blocklist.contains(id) {
            skipped += 1;
            continue;
        }
        let id = id.to_string();
        if let Ok(entries) = fs::read_dir(&mdir) {
            let mut entries: Vec<_> = entries.flatten().collect();
            entries.sort_by_key(|e| e.file_name());
            for e in entries {
                if !e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    continue;
                }
                let name = e.file_name();
                let Some(name) = name.to_str() else {
                    continue;
                };
                if !is_partition_dir(name) {
                    if is_root_symlink(name) {
                        eprintln!(
                            "nomount: {id}: skipping {name}/ - /{name} is a symlink, not a \
                             partition. Ship this content under the partition it resolves to \
                             (usually system/{name}/) so it lands on one target rather than two."
                        );
                    }
                    continue;
                }
                plan_tree(&id, &mdir, &e.path(), &mut plan, &mut refused).with_context(|| {
                    format!(
                        "cannot walk {}/{name} -- refusing to return a partial plan, because \
                         `reload` diffs it against the live rules and would prune every rule \
                         this module owns as an intentional unload",
                        mdir.display()
                    )
                })?;
            }
        }
    }
    Ok((plan, skipped, refused))
}

/// Print the resolved plan without applying it: target, kind, source, module
pub fn run_plan() -> Result<()> {
    let (plan, skipped, refused) = collect_plan()?;
    let (plan, _) = dedupe_by_target(plan);
    for e in &plan {
        let k = match e.kind {
            PlanKind::Inject => "inject",
            PlanKind::Whiteout => "whiteout",
            PlanKind::Bind => "bind",
        };
        let note = if !source_resolves(e) {
            "  << UNSERVABLE: source does not resolve, no rule will be created"
        } else if e.kind == PlanKind::Whiteout && whiteout_leaves_hole(&e.target) {
            "  << applied, but the parent's size/nlink still count it (multi-block erofs)"
        } else {
            ""
        };
        println!("{k:8} {} <- {} [{}]{note}", e.target.display(), e.source.display(), e.module);
    }
    for r in &refused {
        println!(
            "REFUSED  {} <- (nothing) [{}]  << {}",
            r.target.display(),
            r.module,
            r.why
        );
    }
    let binds = plan.iter().filter(|e| e.kind == PlanKind::Bind).count();
    let dead = plan.iter().filter(|e| !source_resolves(e)).count();
    let declined = plan.iter()
        .filter(|e| e.kind == PlanKind::Whiteout && whiteout_leaves_hole(&e.target))
        .count();
    let mut extra = String::new();
    if dead > 0 { extra.push_str(&format!(", {dead} unservable")); }
    if declined > 0 { extra.push_str(&format!(", {declined} whiteout(s) leaving a measurable hole")); }
    if !refused.is_empty() {
        extra.push_str(&format!(", {} refused", refused.len()));
    }
    println!("({} entries: {} binds, {skipped} blocklisted{extra})", plan.len(), binds);
    Ok(())
}

enum LiveRule {
    Inject(PathBuf),
    Whiteout,
}

fn parse_live_rules(list: &str) -> HashMap<(PathBuf, u32), LiveRule> {
    crate::nm::parse_list(list)
        .into_iter()
        .filter_map(|r| {
            let kind = match r.kind {
                crate::nm::LiveKind::Inject => LiveRule::Inject(r.source?),
                crate::nm::LiveKind::Whiteout => LiveRule::Whiteout,
                crate::nm::LiveKind::VirtualDir => return None,
            };
            Some(((r.target, r.uid), kind))
        })
        .collect()
}

fn prune_order(live: &HashMap<(PathBuf, u32), LiveRule>) -> Vec<&(PathBuf, u32)> {
    let mut stale: Vec<&(PathBuf, u32)> = live.keys().collect();
    stale.sort_by_key(|(t, uid)| (std::cmp::Reverse(t.components().count()), t.clone(), *uid));
    stale
}

fn prunable(
    target: &Path,
    uid: u32,
    wanted: bool,
    durable_whiteouts: &HashSet<PathBuf>,
    absorbed: &HashSet<PathBuf>,
) -> bool {
    uid == 0 && !wanted && !durable_whiteouts.contains(target) && !absorbed.contains(target)
}

/// `nomount reload`: gap-free hot load/unload
pub fn run_reload() -> Result<()> {
    let _pass = pass_lock();
    let nm = Nm::new();
    nm.version()
        .context("hookless NoMount engine not responding - is the CONFIG_NOMOUNT kernel loaded?")?;

    let (plan, skipped, _refused) = collect_plan()?;
    let (plan, collisions) = dedupe_by_target(plan);
    for c in &collisions {
        eprintln!(
            "nomount: {} claimed by {} -- serving {}, skipping {}",
            c.target.display(),
            c.losers.len() + 1,
            c.winner,
            c.losers.join(", ")
        );
    }

    if let Err(e) = write_module_summary(&plan) {
        eprintln!("nomount: could not write {MODULE_SUMMARY}: {e} - per-module badges will be stale");
    }

    let mut desired_hookless: HashMap<&Path, &PlanEntry> = HashMap::new();
    let mut desired_bind_src: HashMap<&Path, &Path> = HashMap::new();
    for e in &plan {
        match e.kind {
            PlanKind::Bind => {
                desired_bind_src.insert(e.target.as_path(), e.source.as_path());
            }
            _ => {
                desired_hookless.insert(e.target.as_path(), e);
            }
        }
    }

    let live_txt = nm.list().context("nm list failed during reload")?;
    let live = parse_live_rules(&live_txt);

    let durable_whiteouts: HashSet<PathBuf> = crate::whiteout::read()
        .context("cannot read the durable whiteout list - refusing to reload, because an empty list here would prune every whiteout")?
        .into_iter()
        .map(PathBuf::from)
        .collect();
    let mut absorbed = crate::absorb::read_absorbed_targets()
        .context("cannot read the absorbed-rule record - refusing to reload, because an empty record here would prune every absorbed rule")?;
    absorbed.extend(
        crate::absorb::read_absorbed_tmpfs_targets()
            .context("cannot read the ROM-tmpfs takeover record - refusing to reload, because an empty record here would prune every takeover whiteout")?,
    );

    let (mut added, mut changed, mut removed, mut failed) = (0u32, 0u32, 0u32, 0u32);
    let mounted = crate::absorb::mounted_targets().context(
        "cannot read /proc/self/mountinfo - refusing to serve, because assuming \"nothing is mounted\" injects over live mounts and strands each one in mountinfo until reboot",
    )?;
    let mut applied_apks: Vec<(PathBuf, PathBuf)> = Vec::new();
    for e in apply_order(&plan) {
        let t = e.target.as_path();
        let up_to_date = match live.get(&(t.to_path_buf(), 0)) {
            Some(LiveRule::Inject(src)) => {
                e.kind == PlanKind::Inject && src.as_path() == e.source.as_path()
            }
            Some(LiveRule::Whiteout) => e.kind == PlanKind::Whiteout,
            None => false,
        };
        if up_to_date {
            if e.kind == PlanKind::Inject {
                applied_apks.push((e.target.clone(), e.source.clone()));
            }
            continue;
        }
        if !source_resolves(e) {
            failed += 1;
            continue;
        }
        if !unmount_before_serving(&mounted, &e.target) {
            failed += 1;
            continue;
        }
        let existed = live.contains_key(&(t.to_path_buf(), 0));
        let r = match e.kind {
            PlanKind::Inject => nm.add(&e.target, &e.source),
            PlanKind::Whiteout => {
                warn_whiteout_hole(&e.target, &e.module);
                nm.whiteout(&e.target)
            }
            PlanKind::Bind => unreachable!(),
        };
        match r {
            Ok(_) => {
                if existed {
                    changed += 1;
                } else {
                    added += 1;
                }
                if e.kind == PlanKind::Inject {
                    applied_apks.push((e.target.clone(), e.source.clone()));
                }
            }
            Err(_) => failed += 1,
        }
    }
    for w in &durable_whiteouts {
        if crate::whiteout::validate(&w.to_string_lossy()).is_err() {
            eprintln!("nomount: skipping invalid whiteout entry {}", w.display());
            failed += 1;
            continue;
        }
        let live_rule = live.contains_key(&(w.clone(), 0));
        if live_rule && !w.exists() {
            continue;
        }
        match nm.whiteout(w) {
            Ok(()) => {
                if !live_rule {
                    added += 1;
                }
            }
            Err(_) => failed += 1,
        }
    }

    for (t, uid) in prune_order(&live) {
        let wanted = desired_hookless.contains_key(t.as_path());
        if !prunable(t, *uid, wanted, &durable_whiteouts, &absorbed) {
            continue;
        }
        if nm.del(t).is_ok() {
            removed += 1;
        } else {
            failed += 1;
        }
    }

    let live_binds = crate::bind::tracked();
    let (mut bind_added, mut bind_removed) = (0u32, 0u32);
    for (t, s) in &live_binds {
        if desired_bind_src.get(t.as_path()).copied() != Some(s.as_path()) {
            if crate::bind::umount_one(t) {
                bind_removed += 1;
            } else {
                failed += 1;
            }
        }
    }
    let live_ok: HashSet<&Path> = live_binds
        .iter()
        .filter(|(t, s)| {
            desired_bind_src.get(t.as_path()).copied() == Some(s.as_path())
                && crate::absorb::still_mounted(t)
        })
        .map(|(t, _)| t.as_path())
        .collect();
    for e in plan.iter().filter(|e| e.kind == PlanKind::Bind) {
        if live_ok.contains(e.target.as_path()) {
            applied_apks.push((e.target.clone(), e.source.clone()));
            continue;
        }
        match crate::bind::apply(&e.source, &e.target) {
            Ok(crate::bind::BindOutcome::Bound) => {
                bind_added += 1;
                applied_apks.push((e.target.clone(), e.source.clone()));
            }
            Ok(crate::bind::BindOutcome::AlreadyMounted) => {
                applied_apks.push((e.target.clone(), e.source.clone()));
            }
            Err(_) => failed += 1,
        }
    }

    let pm = crate::pmcache::sync(&served_apks_applied(
        &applied_apks,
        &crate::absorb::absorbed_pairs(),
    ));
    crate::pmcache::add_pending(&pm);

    println!(
        "nomount reload: +{added} ~{changed} -{removed} rules, +{bind_added} -{bind_removed} binds, \
         {failed} failed, {skipped} blocklisted (gap-free)"
    );
    if !pm.is_empty() {
        let shown: Vec<String> =
            pm.iter().take(3).map(|p| p.display().to_string()).collect();
        println!(
            "nomount: {} system APK(s) changed - REBOOT REQUIRED: {}{}",
            pm.len(),
            shown.join(", "),
            if pm.len() > 3 { ", ..." } else { "" }
        );
        println!(
            "         PackageManager parsed the old bytes; its cache is dropped but only \
             re-read at the next scan. Apps over these APKs can force-close until then."
        );
    }
    crate::ghost::sync_after_pass(&nm);
    Ok(())
}

/// Metamodule entry point (`nomount mount`): rebuild rules from the current set of enabled
pub(crate) const MODULE_SUMMARY: &str = "/data/adb/nomount/modules.tsv";

fn write_module_summary(plan: &[PlanEntry]) -> std::io::Result<()> {
    use std::collections::BTreeMap;
    let mut per: BTreeMap<&str, (usize, bool, bool)> = BTreeMap::new();
    for e in plan {
        let row = per.entry(e.module.as_str()).or_insert((0, false, false));
        row.0 += 1;
        if is_rro_apk(&e.target) {
            row.1 = true;
        } else {
            row.2 = true;
        }
    }
    let mut body = String::new();
    for (id, (n, ov, vfs)) in per {
        if id.contains('\t') || id.contains('\n') || id.contains('\r') {
            eprintln!(
                "nomount: {id}: no per-module badge - its id contains a tab or a newline, \
                 which would forge a row in {MODULE_SUMMARY}"
            );
            continue;
        }
        body.push_str(&format!("{id}\t{n}\t{}\t{}\n", u8::from(ov), u8::from(vfs)));
    }
    crate::statefile::write_atomic(std::path::Path::new(MODULE_SUMMARY), &body)
}

fn is_rro_apk(target: &std::path::Path) -> bool {
    target.extension().is_some_and(|e| e == "apk")
        && target.components().any(|c| c.as_os_str() == "overlay")
}

pub fn run_mount() -> Result<()> {
    let _pass = pass_lock();
    let nm = Nm::new();
    nm.version()
        .context("hookless NoMount engine not responding - is the CONFIG_NOMOUNT kernel loaded?")?;

    let (plan, skipped, _refused) = collect_plan()?;

    let (plan, collisions) = dedupe_by_target(plan);
    for c in &collisions {
        eprintln!(
            "nomount: {} claimed by {} -- serving {}, skipping {}",
            c.target.display(),
            c.losers.len() + 1,
            c.winner,
            c.losers.join(", ")
        );
    }

    if let Err(e) = write_module_summary(&plan) {
        eprintln!("nomount: could not write {MODULE_SUMMARY}: {e} - per-module badges will be stale");
    }

    if crate::dirshape::rom_dirs_are_dirent_packed() {
        if let Err(e) = nm.set_dir_shape(true) {
            eprintln!("nomount: could not set the directory-shape knob: {e:#}");
        }
    }

    let mounted = crate::absorb::mounted_targets().context(
        "cannot read /proc/self/mountinfo - refusing to serve, because assuming \"nothing is mounted\" injects over live mounts and strands each one in mountinfo until reboot",
    )?;

    if !crate::bind::teardown_all() {
        eprintln!(
            "nomount: at least one my_* bind from the previous pass is still mounted; it \
             stays recorded in binds.list and the next pass will retry it"
        );
    }
    nm.clear()
        .context("could not clear the engine before rebuilding - rules from uninstalled or updated modules would survive the pass")?;
    let hidden = crate::cli::handlers::reapply_blocklist(&nm, true);
    let recorded = match crate::absorb::read_absorbed_pairs() {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "nomount: could not read the absorbed-rule record ({e}) -- re-serving \
                 nothing from it this pass and leaving the file alone, because rewriting \
                 it from an empty read would lose every patched-APK rule for good"
            );
            Vec::new()
        }
    };
    if !recorded.is_empty() {
        let n = crate::absorb::reapply_absorbed_pairs(&nm, &recorded);
        if n > 0 {
            println!("nomount: re-served {n} absorbed APK rule(s) from the record");
        }
    }

    let mut served: HashSet<&str> = HashSet::new();
    let mut binds = 0u32;
    let mut st = Stats {
        applied: 0,
        failed: 0,
        whiteouts: 0,
    };
    let mut applied_apks: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut injects: Vec<(&Path, &Path)> = Vec::new();
    let mounted = crate::absorb::mounted_targets().unwrap_or(mounted);

    let mut blocked: std::collections::HashSet<&Path> = std::collections::HashSet::new();
    for e in &plan {
        served.insert(e.module.as_str());
        if e.kind == PlanKind::Inject && !source_resolves(e) {
            st.failed += 1;
            continue;
        }
        if needs_unmount_before_serving(e.kind) && !unmount_before_serving(&mounted, &e.target) {
            st.failed += 1;
            blocked.insert(e.target.as_path());
            continue;
        }
        match e.kind {
            PlanKind::Inject => injects.push((e.target.as_path(), e.source.as_path())),
            PlanKind::Whiteout | PlanKind::Bind => {}
        }
    }
    {
        let failed: std::collections::HashSet<&Path> =
            nm.add_many(&injects).into_iter().map(|(t, _)| t).collect();
        for (t, r) in &injects {
            if failed.contains(t) {
                st.failed += 1;
            } else {
                st.applied += 1;
                applied_apks.push(((*t).to_path_buf(), (*r).to_path_buf()));
            }
        }
    }
    for e in &plan {
        if blocked.contains(e.target.as_path()) {
            continue;
        }
        match e.kind {
            PlanKind::Whiteout => {
                warn_whiteout_hole(&e.target, &e.module);
                match nm.whiteout(&e.target) {
                    Ok(()) => st.whiteouts += 1,
                    Err(_) => st.failed += 1,
                }
            }
            PlanKind::Bind => match crate::bind::apply(&e.source, &e.target) {
                Ok(crate::bind::BindOutcome::Bound) => {
                    binds += 1;
                    applied_apks.push((e.target.clone(), e.source.clone()));
                }
                Ok(crate::bind::BindOutcome::AlreadyMounted) => {
                    applied_apks.push((e.target.clone(), e.source.clone()));
                }
                Err(_) => st.failed += 1,
            },
            PlanKind::Inject => {}
        }
    }
    let tmpfs_hidden = crate::absorb::reapply_tmpfs_whiteouts(&nm);

    let pm = crate::pmcache::sync(&served_apks_applied(&applied_apks, &recorded));
    crate::pmcache::clear_pending();

    let modules = served.len();
    let surface = if binds > 0 { "hookless + my_* bind" } else { "mountless (RRO via hookless)" };

    println!(
        "nomount(suite): {modules} modules | {} rules, {} whiteouts, {binds} my_* binds, {} failed, \
         {skipped} skipped | {} hidden{} | {surface}",
        st.applied,
        st.whiteouts,
        st.failed,
        hidden.hidden,
        if hidden.failed > 0 { format!(", {} hide failed", hidden.failed) } else { String::new() }
    );
    if tmpfs_hidden > 0 {
        println!(
            "nomount: re-applied {tmpfs_hidden} ROM directory hide(s) taken over from a module tmpfs"
        );
    }
    if st.failed > 0 {
        println!(
            "nomount: WARNING {} rule(s) failed to apply - the injection set is incomplete",
            st.failed
        );
    }
    if !pm.is_empty() {
        println!("nomount: re-parsed {} changed system APK(s) (package cache)", pm.len());
    }
    crate::ghost::sync_after_pass(&nm);
    Ok(())
}

fn served_apks_applied(
    applied: &[(PathBuf, PathBuf)],
    absorbed: &[(PathBuf, PathBuf)],
) -> Vec<(PathBuf, PathBuf)> {
    applied
        .iter()
        .cloned()
        .chain(absorbed.iter().cloned())
        .filter(|(t, _)| crate::pmcache::is_rom_apk(t))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_the_wire_format_cannot_carry_is_refused() {
        let forge = Path::new("/system/etc/A\n/data/app/~~AA==/com.victim-BB==/base.apk");
        assert!(path_is_representable(forge).is_err(), "the rule-forgery vector");

        for bad in [
            "/system/etc/a\rb",
            "/system/etc/a\tb",
            "/system/etc/x -> /data/adb/modules/evil/x",
            "/system/etc/x (whiteout)\n/system/bin/su",
            "/system/etc/x [UID: 0] y",
            "/system/etc/x (whiteout)",
            "/system/etc/x (public)",
            "/system/etc/x (virtual dir)",
            "/system/etc/x (whiteout) ",
            "/system/etc/x (public) ",
            "/system/etc/x ",
            "/system/etc/x\u{a0}",
        ] {
            assert!(
                path_is_representable(Path::new(bad)).is_err(),
                "must refuse: {bad}"
            );
        }
        for ok in [
            "/system/etc/a b/c.conf",
            "/system/etc/it's.conf",
            "/product/app/Foo \u{1F600}/Foo.apk",
            "/system/etc/x [UID] y",
            "/system/etc/x (whiteout) y",
        ] {
            assert!(
                path_is_representable(Path::new(ok)).is_ok(),
                "must accept: {ok}"
            );
        }
    }

    #[test]
    fn only_engine_served_kinds_are_unmounted_first() {
        assert!(needs_unmount_before_serving(PlanKind::Inject));
        assert!(needs_unmount_before_serving(PlanKind::Whiteout));
        assert!(
            !needs_unmount_before_serving(PlanKind::Bind),
            "binding over a live mount strands nothing; stealing another module's bind does"
        );
    }

    #[test]
    fn injects_are_applied_before_whiteouts_in_plan_order() {
        let mut plan = vec![
            entry("a_mod", "/system/etc/foo", "/data/adb/modules/a_mod/system/etc/foo"),
            entry("b_mod", "/system/etc/foo/bar", "/data/adb/modules/b_mod/system/etc/foo/bar"),
            entry("c_mod", "/system/etc/baz", "/data/adb/modules/c_mod/system/etc/baz"),
        ];
        plan[0].kind = PlanKind::Whiteout;
        plan[2].kind = PlanKind::Bind;

        let order: Vec<_> = apply_order(&plan)
            .into_iter()
            .map(|e| (e.kind, e.target.clone()))
            .collect();
        assert_eq!(
            order,
            vec![
                (PlanKind::Inject, PathBuf::from("/system/etc/foo/bar")),
                (PlanKind::Whiteout, PathBuf::from("/system/etc/foo")),
            ],
            "the inject under the whiteout must land first, and binds are not in this order at all"
        );
    }

    const LIB: &str = include_str!("../module/lib.sh");
    const SERVICE: &str = include_str!("../module/service.sh");

    #[test]
    fn the_manager_card_excludes_whiteouts_from_its_rule_count() {
        let line = LIB
            .lines()
            .find(|l| l.trim_start().starts_with("_rules=$("))
            .expect("lib.sh: no _rules= line in nm_rule_counts");
        assert!(
            line.contains("virtual dir") && line.contains("whiteout"),
            "the card's rule count must exclude both virtual dirs and whiteouts, \
             or it disagrees with health.txt: {line}"
        );
        for (name, src) in [("service.sh", SERVICE), ("metamount.sh", METAMOUNT_SRC)] {
            assert!(
                !src.contains("_rules=$("),
                "{name} computes its own rule count again; call nm_rule_counts instead"
            );
        }
    }

    const METAMOUNT_SRC: &str = include_str!("../module/metamount.sh");

    #[test]
    fn the_case_sweep_gate_is_wired_into_ci() {
        const BUILD_YAML: &str = include_str!("../.github/workflows/build.yaml");
        const SWEEP: &str = include_str!("../scripts/case-sweep.py");

        assert!(
            BUILD_YAML.contains("scripts/case-sweep.py"),
            "build.yaml no longer invokes scripts/case-sweep.py - the case-only gate is off,              and the bulk-rewrite class it catches (HEAD -> head, ARCH -> arch) is silent"
        );
        assert!(
            BUILD_YAML.contains("fetch-depth: 0"),
            "the sweep diffs the pushed range, so the test job's checkout needs full history;              with the default depth-1 checkout it has no predecessor to diff and checks nothing"
        );
        assert!(
            SWEEP.contains(r#"SKIP_MARKER = "[case-ok]""#),
            "case-sweep.py's escape-hatch marker changed; the failure message it prints and              this contract must name the same string"
        );
    }

    #[test]
    fn the_webui_harness_still_has_its_stub_and_replays_every_command() {
        const HARNESS: &str = include_str!("../scripts/webui-harness.py");

        assert!(
            HARNESS.contains("\nSTUB = \"\"\""),
            "webui-harness.py references STUB but no longer defines it - `build` cannot run. \
             Recover it with: git show <before-the-strip>:scripts/webui-harness.py"
        );

        let block = |head: &str, end: &str| -> &str {
            let at = HARNESS.find(head).unwrap_or_else(|| panic!("{head} is gone or renamed"));
            let rest = &HARNESS[at + head.len()..];
            &rest[..rest.find(end).expect("unterminated block")]
        };
        let commands = block("COMMANDS = {", "\n}");
        let stub = block("STUB = \"\"\"", "\"\"\"");

        let keys: Vec<&str> = commands
            .lines()
            .map(str::trim)
            .filter_map(|l| l.strip_prefix('"'))
            .filter_map(|l| l.split_once("\":"))
            .map(|(k, _)| k)
            .collect();
        assert!(keys.len() > 10, "COMMANDS parsed as {} keys - the parser has drifted", keys.len());
        for k in keys {
            assert!(
                stub.contains(&format!("key = '{k}'")),
                "COMMANDS has {k:?} and the stub has no branch for it, so the page gets rc=1 \
                 for that command and renders its unreadable path instead of the captured one"
            );
        }
    }

    #[test]
    fn the_two_ci_toolchain_pins_agree() {
        const BUILD_YAML: &str = include_str!("../.github/workflows/build.yaml");
        let pins: Vec<&str> = BUILD_YAML
            .lines()
            .filter_map(|l| l.trim().strip_prefix("toolchain:"))
            .map(str::trim)
            .collect();
        assert_eq!(
            pins.len(),
            2,
            "expected exactly two pinned `toolchain:` values (host test job, cross build job),              got {pins:?} - a job added or removed without pinning floats on whatever stable              was released that morning"
        );
        assert_eq!(
            pins[0], pins[1],
            "the two CI jobs pin different rustc versions ({pins:?}) - the binary that ships              would be built by a compiler the tests never ran under"
        );
        assert!(
            pins[0].chars().next().is_some_and(|c| c.is_ascii_digit()),
            "the pin must be an exact version, not a floating channel like `stable`: {:?}",
            pins[0]
        );
    }

    #[test]
    fn the_manager_card_consults_the_check_verdict() {
        let uses: Vec<&str> = SERVICE
            .lines()
            .filter(|l| l.contains("$_hv") || l.contains("_hv="))
            .collect();
        assert!(
            uses.iter().any(|l| l.contains("_health=")),
            "the card ladder must branch on the verdict, not only log it: {uses:?}"
        );
        assert!(
            SERVICE.contains("_sum_get unmeasured"),
            "the card must read the plan's unmeasured count"
        );
    }

    const PAGE: &str = include_str!("../module/webroot/index.html");
    const HARNESS_SRC: &str = include_str!("../scripts/webui-harness.py");

    #[test]
    fn the_webui_matches_the_strings_absorb_actually_prints() {
        const ABSORB: &str = include_str!("absorb.rs");
        for (matcher, producer) in [
            (r#"[/^would skip directory bind /"#, r#""would skip directory bind {} <- {}"#),
            (r#"[/^would drop redundant mount /"#, r#""would drop redundant mount {} <- {}"#),
            (r#"[/^would absorb /"#, r#""would absorb {} <- {}""#),
            (r#"[/^would empty /"#, r#""would empty {} mountlessly"#),
            (r#"[/^redundant /"#, r#""redundant {} <- {}"#),
            (r#"[/^nomount: LEAK /"#, r#""nomount: LEAK "#),
        ] {
            assert!(
                PAGE.contains(matcher),
                "index.html no longer carries the matcher {matcher} - if absorb's wording moved, \
                 move the matcher with it rather than deleting this row"
            );
            assert!(
                ABSORB.contains(producer),
                "absorb.rs no longer prints {producer}, but index.html still matches on it: \
                 the Absorb scan card will render that line untagged"
            );
        }
    }

    #[test]
    fn the_sucompat_probe_greps_for_the_case_ksud_actually_prints() {
        assert!(
            PAGE.contains("grep su_compat | grep -q ENABLED"),
            "index.html's sucompat probe must grep for ENABLED, the spelling ksud emits"
        );
        assert!(
            !PAGE.contains("grep -q enabled"),
            "a lowercase `enabled` grep never matches ksud's output"
        );
    }

    #[test]
    fn the_harness_runs_the_same_probes_the_page_does() {
        for frag in [
            r#"grep su_compat "#,
            r#"| grep -q ENABLED && echo 1 || echo 0)"; "#,
            r#"echo "ksud=$([ -x /data/adb/ksud ] && echo 1 || echo 0)"; "#,
            r#"echo "root_nm=$(grep -c \'^nomount_\' /proc/self/mounts 2>/dev/null)"; "#,
            r#"echo "fp=$(getprop ro.build.fingerprint 2>/dev/null)"; "#,
            r#"echo "se=$(getenforce 2>/dev/null)""#,
        ] {
            assert!(PAGE.contains(frag), "index.html's stealth probe lost: {frag:?}");
            assert!(
                HARNESS_SRC.contains(frag),
                "webui-harness.py's `stealth` command lost {frag:?}, so the harness feeds the \
                 page a fixture the page's own command would never have produced"
            );
        }
    }

    fn entry(module: &str, target: &str, source: &str) -> PlanEntry {
        PlanEntry {
            module: module.to_string(),
            target: PathBuf::from(target),
            source: PathBuf::from(source),
            kind: PlanKind::Inject,
        }
    }

    #[test]
    fn dedupe_keeps_the_last_claim() {
        let plan = vec![
            entry("a_mod", "/system/etc/x", "/data/adb/modules/a_mod/system/etc/x"),
            entry("b_mod", "/system/etc/x", "/data/adb/modules/b_mod/system/etc/x"),
            entry("c_mod", "/system/etc/y", "/data/adb/modules/c_mod/system/etc/y"),
        ];
        let (kept, collisions) = dedupe_by_target(plan);
        assert_eq!(kept.len(), 2, "one rule per target");
        let x = kept.iter().find(|e| e.target == Path::new("/system/etc/x")).unwrap();
        assert_eq!(x.module, "b_mod", "last plan entry wins, as documented");
        assert_eq!(collisions.len(), 1);
        assert_eq!(collisions[0].winner, "b_mod");
        assert_eq!(collisions[0].losers, vec!["a_mod".to_string()]);
    }

    #[test]
    fn dedupe_is_a_noop_without_collisions() {
        let plan = vec![
            entry("a", "/system/etc/one", "/data/adb/modules/a/system/etc/one"),
            entry("b", "/system/etc/two", "/data/adb/modules/b/system/etc/two"),
        ];
        let (kept, collisions) = dedupe_by_target(plan);
        assert_eq!(kept.len(), 2);
        assert!(collisions.is_empty());
        assert_eq!(kept[0].module, "a");
        assert_eq!(kept[1].module, "b");
    }

    #[test]
    fn serve_mode_refuses_repeated_partition_name() {
        assert!(matches!(
            serve_mode(Path::new("/product/product/etc/nmt/x.txt")),
            Serve::Refuse(_)
        ));
        assert!(matches!(
            serve_mode(Path::new("/system/system/etc/x")),
            Serve::Refuse(_)
        ));
        assert_eq!(serve_mode(Path::new("/product/etc/product/x")), Serve::Inject);
        assert_eq!(serve_mode(Path::new("/system/etc/system/x")), Serve::Inject);
    }

    #[test]
    fn serve_mode_refuses_what_plan_tree_refuses() {
        assert_eq!(serve_mode(Path::new("/system/bin/x")), Serve::Inject);
        assert_eq!(serve_mode(Path::new("/product/etc/foo.xml")), Serve::Inject);
        if !my_hookless_enabled() {
            assert_eq!(serve_mode(Path::new("/my_product/app/Foo/Foo.apk")), Serve::Bind);
        }
        assert!(matches!(serve_mode(Path::new("/apex/com.android.art/x")), Serve::Refuse(_)));
        assert!(matches!(serve_mode(Path::new("/data/adb/x")), Serve::Refuse(_)));
        assert!(matches!(serve_mode(Path::new("/system")), Serve::Refuse(_)));
        assert!(matches!(serve_mode(Path::new("/")), Serve::Refuse(_)));
        assert!(matches!(serve_mode(Path::new("/d/tracing/x")), Serve::Refuse(_)));
        assert!(can_whiteout(Path::new("/d/tracing/x")).is_err());
    }

    #[test]
    fn replace_expands_to_the_unshipped_entries_only() {
        let Some(base) = test_base("replace-expand") else { return };
        let stock = base.join("stock");
        let module = base.join("module");

        fs::create_dir_all(stock.join("sub")).unwrap();
        fs::create_dir_all(stock.join("extra")).unwrap();
        fs::write(stock.join("a.xml"), b"stock").unwrap();
        fs::write(stock.join("b.xml"), b"stock").unwrap();
        fs::write(stock.join("sub/c.xml"), b"stock").unwrap();
        fs::write(stock.join("sub/d.xml"), b"stock").unwrap();

        fs::create_dir_all(module.join("sub")).unwrap();
        fs::write(module.join("a.xml"), b"mine").unwrap();
        fs::write(module.join("sub/d.xml"), b"mine").unwrap();

        let mut out = Vec::new();
        expand_replacement("m", &stock, &module, &module.join(".replace"), 0, &mut out);
        let mut got: Vec<String> =
            out.iter().map(|e| e.target.strip_prefix(&stock).unwrap().display().to_string()).collect();
        got.sort();

        assert_eq!(got, vec!["b.xml".to_string(), "extra".to_string(), "sub/c.xml".to_string()]);
        assert!(out.iter().all(|e| e.kind == PlanKind::Whiteout));
        assert!(out.iter().all(|e| e.target != stock));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn replace_does_not_descend_where_the_module_ships_a_file() {
        let Some(base) = test_base("replace-file-over-dir") else { return };
        let stock = base.join("stock");
        let module = base.join("module");
        fs::create_dir_all(stock.join("thing")).unwrap();
        fs::write(stock.join("thing/inner.xml"), b"stock").unwrap();
        fs::create_dir_all(&module).unwrap();
        fs::write(module.join("thing"), b"mine").unwrap();

        let mut out = Vec::new();
        expand_replacement("m", &stock, &module, &module.join(".replace"), 0, &mut out);
        assert!(out.is_empty(), "expected no whiteouts, got {} entries", out.len());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn replace_on_a_directory_the_rom_does_not_have_is_a_no_op() {
        let Some(base) = test_base("replace-absent") else { return };
        let module = base.join("module");
        fs::create_dir_all(&module).unwrap();
        fs::write(module.join("mine.xml"), b"mine").unwrap();

        let mut out = Vec::new();
        expand_replacement("m", &base.join("no-such-stock"), &module, &module.join(".replace"), 0, &mut out);
        assert!(out.is_empty());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn replace_expansion_stops_at_the_depth_guard() {
        let Some(base) = test_base("replace-depth") else { return };
        let stock = base.join("stock");
        let mut d = stock.clone();
        let module = base.join("module");
        let mut m = module.clone();
        for _ in 0..20 {
            d = d.join("x");
            m = m.join("x");
        }
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("deep.xml"), b"stock").unwrap();
        fs::create_dir_all(&m).unwrap();

        let mut out = Vec::new();
        expand_replacement("m", &stock, &module, &module.join(".replace"), 0, &mut out);
        assert!(out.iter().all(|e| !e.target.ends_with("deep.xml")));

        let _ = fs::remove_dir_all(&base);
    }

    fn test_base(tag: &str) -> Option<PathBuf> {
        let home = std::env::var("HOME").ok()?;
        let base = PathBuf::from(home).join(format!(".nomount-test-{tag}"));
        if can_whiteout(&base.join("probe")).is_err() {
            eprintln!("skipping: {} is not a whiteoutable base", base.display());
            return None;
        }
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).ok()?;
        Some(base)
    }

    #[test]
    fn only_a_zero_zero_char_device_is_a_whiteout_marker() {
        let real = Path::new("/dev/null");
        if let Ok(md) = fs::symlink_metadata(real) {
            assert!(md.file_type().is_char_device(), "/dev/null should be a char device");
            assert!(
                !is_whiteout_marker(&md.file_type(), real),
                "/dev/null has a non-zero rdev and is not a deletion marker"
            );
        }
        let Some(base) = test_base("whiteout-marker") else { return };
        let f = base.join("plain");
        fs::write(&f, b"x").unwrap();
        let md = fs::symlink_metadata(&f).unwrap();
        assert!(!is_whiteout_marker(&md.file_type(), &f));
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn whiteout_allowed_on_my_partitions() {
        assert!(can_whiteout(Path::new("/my_stock/app/OplusOperationManual")).is_ok());
        assert!(can_whiteout(Path::new("/my_product/app/Foo")).is_ok());
        assert!(can_whiteout(Path::new("/product/app/AIMemory")).is_ok());
        assert!(can_whiteout(Path::new("/system/priv-app/Foo")).is_ok());
    }

    #[test]
    fn whiteout_refuses_partition_roots_and_non_rom() {
        assert!(can_whiteout(Path::new("/my_stock")).is_err());
        assert!(can_whiteout(Path::new("/product")).is_err());
        assert!(can_whiteout(Path::new("/system")).is_err());
        assert!(can_whiteout(Path::new("/data/adb/modules/x")).is_err());
        assert!(can_whiteout(Path::new("/apex/com.android.art/x")).is_err());
        assert!(can_whiteout(Path::new("/")).is_err());
    }

    #[test]
    fn reload_never_prunes_durable_or_absorbed_rules() {
        let durable: HashSet<PathBuf> = ["/system/etc/tell.conf"].iter().map(PathBuf::from).collect();
        let absorbed: HashSet<PathBuf> = ["/system/etc/absorbed.xml"].iter().map(PathBuf::from).collect();
        let none = HashSet::new();

        assert!(!prunable(Path::new("/system/etc/tell.conf"), 0, false, &durable, &absorbed));
        assert!(!prunable(Path::new("/system/etc/absorbed.xml"), 0, false, &durable, &absorbed));
        assert!(!prunable(Path::new("/system/app/Foo.apk"), 0, true, &none, &none));
        assert!(prunable(Path::new("/system/app/Gone.apk"), 0, false, &durable, &absorbed));
    }

    #[test]
    fn reload_never_prunes_per_uid_rules() {
        let none = HashSet::new();
        let t = Path::new("/system/app/Gone.apk");
        assert!(prunable(t, 0, false, &none, &none));
        assert!(!prunable(t, 10471, false, &none, &none));
        assert!(!prunable(t, 1000, false, &none, &none));
    }

    #[test]
    fn stale_rules_are_pruned_deepest_first() {
        let live = parse_live_rules(
            "/system/etc/d -> /m/d\n\
             /system/etc/d/a/b -> /m/d/a/b\n\
             /system/etc/d/a -> /m/d/a\n\
             /system/etc/z -> /m/z\n",
        );
        let order: Vec<String> =
            prune_order(&live).iter().map(|(t, _)| t.display().to_string()).collect();
        assert_eq!(
            order,
            vec![
                "/system/etc/d/a/b".to_string(),
                "/system/etc/d/a".to_string(),
                "/system/etc/d".to_string(),
                "/system/etc/z".to_string(),
            ],
            "children first, then their parent; equal depth breaks by path"
        );
    }

    #[test]
    fn an_inject_source_resolving_into_app_writable_data_is_untrusted() {
        for bad in [
            "/data/local/tmp/x",
            "/data/media/0/Download/x.apk",
            "/data/data/com.evil/files/payload",
            "/data/app/~~AA==/com.evil-BB==/base.apk",
            "/storage/emulated/0/Download/x.apk",
            "/sdcard/Download/x.apk",
            "/mnt/media_rw/1234-5678/x.apk",
            "/mnt/expand/abcd/x.apk",
            "/mnt/user/0/emulated/0/x.apk",
            "/mnt/runtime/write/emulated/0/x.apk",
        ] {
            assert!(resolved_source_is_untrusted(Path::new(bad)), "must refuse: {bad}");
        }
        for ok in [
            "/data/adb/modules/OxygenCustomizer/product/etc/x",
            "/data/adb/nomount/x",
            "/product/etc/x",
            "/system/etc/x",
            "/my_product/app/Foo/Foo.apk",
            "/database/x",
            "/storageroom/x",
            "/data/adb/modules/M/system/etc/x",
        ] {
            assert!(!resolved_source_is_untrusted(Path::new(ok)), "must accept: {ok}");
        }
    }

    #[test]
    fn live_rules_are_keyed_including_uid() {
        let m = parse_live_rules("/a -> /b\n/a -> /c [UID: 1000]\n/d (whiteout)\n/e (virtual dir)\n");
        assert_eq!(m.len(), 3);
        assert!(m.contains_key(&(PathBuf::from("/a"), 0)));
        assert!(m.contains_key(&(PathBuf::from("/a"), 1000)));
        assert!(m.contains_key(&(PathBuf::from("/d"), 0)));
    }

    #[test]
    fn both_rro_layouts_are_overlays() {
        assert!(is_rro_apk(Path::new("/product/overlay/Foo.apk")), "flat");
        assert!(is_rro_apk(Path::new("/product/overlay/Foo/Foo.apk")), "one directory per package");
        assert!(
            is_rro_apk(Path::new("/system/product/overlay/A/B/C.apk")),
            "depth under overlay/ is not the question"
        );
        assert!(!is_rro_apk(Path::new("/product/app/Foo/Foo.apk")), "an ordinary app APK");
        assert!(
            !is_rro_apk(Path::new("/product/overlay/Foo/lib/libx.so")),
            "a non-APK under overlay/ is still a file redirect"
        );
    }
}
