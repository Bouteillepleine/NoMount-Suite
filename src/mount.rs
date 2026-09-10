
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

pub(crate) struct PassLock(std::fs::File);

pub(crate) const PASS_LOCK_WAIT: u64 = 25;

pub(crate) fn pass_lock() -> Option<PassLock> {
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    let f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .mode(0o600)
        .open(PASS_LOCK)
        .ok()?;
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
    !name.is_empty()
        && !NON_PARTITION_ROOTS.contains(&name)
        && Path::new(&format!("/{name}")).is_dir()
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
    std::env::var_os("NM_MY_HOOKLESS")
        .map(|v| v != "0" && !v.is_empty())
        .unwrap_or(false)
        || Path::new("/data/adb/nomount/my_hookless").exists()
}

fn is_partition_root(target: &Path) -> bool {
    target.components().skip(1).count() <= 1
}

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
        if second == root && is_partition_root(Path::new(&format!("/{root}"))) {
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

fn source_resolves(e: &PlanEntry) -> bool {
    e.kind != PlanKind::Inject || e.source.exists()
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PlanKind {
    Inject,
    Whiteout,
    Bind,
}

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

pub(crate) struct Collision {
    pub target: PathBuf,
    pub winner: String,
    pub losers: Vec<String>,
}

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

fn plan_tree(module: &str, module_root: &Path, dir: &Path, out: &mut Vec<PlanEntry>) {
    let mut entries: Vec<_> = match fs::read_dir(dir) {
        Ok(e) => e.flatten().collect(),
        Err(_) => return,
    };
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
            continue;
        };
        let name = entry.file_name();
        let name = name.to_string_lossy();

        if ft.is_dir() {
            if is_opaque_dir(&source) && can_whiteout(&target).is_ok() {
                expand_replacement(module, &target, &source, &source, 0, out);
            }
            plan_tree(module, module_root, &source, out);
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
            match serve_mode(&target) {
                Serve::Refuse(why) => {
                    eprintln!("nomount: {module}: skipping {} - {why}", target.display());
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

pub(crate) fn collect_plan() -> Result<(Vec<PlanEntry>, u32)> {
    let blocklist = load_blocklist();
    let mut plan = Vec::new();
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
            continue;
        };
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
                    continue;
                }
                plan_tree(&id, &mdir, &e.path(), &mut plan);
            }
        }
    }
    Ok((plan, skipped))
}

pub fn run_plan() -> Result<()> {
    let (plan, skipped) = collect_plan()?;
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
    let binds = plan.iter().filter(|e| e.kind == PlanKind::Bind).count();
    let dead = plan.iter().filter(|e| !source_resolves(e)).count();
    let declined = plan.iter()
        .filter(|e| e.kind == PlanKind::Whiteout && whiteout_leaves_hole(&e.target))
        .count();
    let mut extra = String::new();
    if dead > 0 { extra.push_str(&format!(", {dead} unservable")); }
    if declined > 0 { extra.push_str(&format!(", {declined} whiteout(s) leaving a measurable hole")); }
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

fn prunable(
    target: &Path,
    uid: u32,
    wanted: bool,
    durable_whiteouts: &HashSet<PathBuf>,
    absorbed: &HashSet<PathBuf>,
) -> bool {
    uid == 0 && !wanted && !durable_whiteouts.contains(target) && !absorbed.contains(target)
}

pub fn run_reload() -> Result<()> {
    let _pass = pass_lock();
    let nm = Nm::new();
    nm.version()
        .context("hookless NoMount engine not responding - is the CONFIG_NOMOUNT kernel loaded?")?;

    let (plan, skipped) = collect_plan()?;
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
    absorbed.extend(crate::absorb::absorbed_tmpfs_targets());

    let (mut added, mut changed, mut removed, mut failed) = (0u32, 0u32, 0u32, 0u32);
    let mounted = crate::absorb::mounted_targets().context(
        "cannot read /proc/self/mountinfo - refusing to serve, because assuming \"nothing is mounted\" injects over live mounts and strands each one in mountinfo until reboot",
    )?;
    for (t, e) in &desired_hookless {
        let up_to_date = match live.get(&((*t).to_path_buf(), 0)) {
            Some(LiveRule::Inject(src)) => {
                e.kind == PlanKind::Inject && src.as_path() == e.source.as_path()
            }
            Some(LiveRule::Whiteout) => e.kind == PlanKind::Whiteout,
            None => false,
        };
        if up_to_date {
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
        let existed = live.contains_key(&((*t).to_path_buf(), 0));
        if existed {
            let _ = nm.del(&e.target);
        }
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

    for (t, uid) in live.keys() {
        let wanted = desired_hookless.contains_key(t.as_path())
            || desired_bind_src.contains_key(t.as_path());
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
        .filter(|(t, s)| desired_bind_src.get(t.as_path()).copied() == Some(s.as_path()))
        .map(|(t, _)| t.as_path())
        .collect();
    for e in plan.iter().filter(|e| e.kind == PlanKind::Bind) {
        if !live_ok.contains(e.target.as_path()) {
            match crate::bind::apply(&e.source, &e.target) {
                Ok(crate::bind::BindOutcome::Bound) => bind_added += 1,
                Ok(crate::bind::BindOutcome::AlreadyMounted) => {}
                Err(_) => failed += 1,
            }
        }
    }

    let pm = crate::pmcache::sync(&served_apks(&plan, &crate::absorb::absorbed_pairs()));
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
    Ok(())
}

pub fn run_mount() -> Result<()> {
    let _pass = pass_lock();
    let nm = Nm::new();
    nm.version()
        .context("hookless NoMount engine not responding - is the CONFIG_NOMOUNT kernel loaded?")?;

    let (plan, skipped) = collect_plan()?;

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

    if crate::dirshape::rom_dirs_are_dirent_packed() {
        if let Err(e) = nm.set_dir_shape(true) {
            eprintln!("nomount: could not set the directory-shape knob: {e:#}");
        }
    }

    let mounted = crate::absorb::mounted_targets().context(
        "cannot read /proc/self/mountinfo - refusing to serve, because assuming \"nothing is mounted\" injects over live mounts and strands each one in mountinfo until reboot",
    )?;

    nm.clear()
        .context("could not clear the engine before rebuilding - rules from uninstalled or updated modules would survive the pass")?;
    let hidden = crate::cli::handlers::reapply_blocklist(&nm, true);
    if !crate::bind::teardown_all() {
        eprintln!(
            "nomount: at least one my_* bind from the previous pass is still mounted; it \
             stays recorded in binds.list and the next pass will retry it"
        );
    }
    let (recorded, record_readable) = match crate::absorb::read_absorbed_pairs() {
        Ok(v) => (v, true),
        Err(e) => {
            eprintln!(
                "nomount: could not read the absorbed-rule record ({e}) -- re-serving \
                 nothing from it this pass and LEAVING THE FILE ALONE, because rewriting \
                 it from an empty read would lose every patched-APK rule for good"
            );
            (Vec::new(), false)
        }
    };
    if record_readable {
        crate::absorb::set_absorbed_pairs(&recorded);
    }
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
    for e in &plan {
        served.insert(e.module.as_str());
        if !unmount_before_serving(&mounted, &e.target) {
            st.failed += 1;
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
            PlanKind::Inject if !source_resolves(e) => st.failed += 1,
            PlanKind::Inject => match nm.add(&e.target, &e.source) {
                Ok(()) => {
                    st.applied += 1;
                    applied_apks.push((e.target.clone(), e.source.clone()));
                }
                Err(_) => st.failed += 1,
            },
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
    Ok(())
}

fn served_apks(plan: &[PlanEntry], absorbed: &[(PathBuf, PathBuf)]) -> Vec<(PathBuf, PathBuf)> {
    plan.iter()
        .filter(|e| matches!(e.kind, PlanKind::Inject | PlanKind::Bind))
        .map(|e| (e.target.clone(), e.source.clone()))
        .chain(absorbed.iter().cloned())
        .filter(|(t, _)| crate::pmcache::is_rom_apk(t))
        .collect()
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
    fn live_rules_are_keyed_including_uid() {
        let m = parse_live_rules("/a -> /b\n/a -> /c [UID: 1000]\n/d (whiteout)\n/e (virtual dir)\n");
        assert_eq!(m.len(), 3);
        assert!(m.contains_key(&(PathBuf::from("/a"), 0)));
        assert!(m.contains_key(&(PathBuf::from("/a"), 1000)));
        assert!(m.contains_key(&(PathBuf::from("/d"), 0)));
    }
}
