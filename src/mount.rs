
use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

fn is_whiteout_node(ft: &fs::FileType, rdev: u64) -> bool {
    ft.is_char_device() && rdev == 0
}

fn is_whiteout_marker(ft: &fs::FileType, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    ft.is_char_device()
        && fs::symlink_metadata(path)
            .map(|m| is_whiteout_node(&m.file_type(), m.rdev()))
            .unwrap_or(false)
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

pub const DISABLED_MARKER: &str = "/data/adb/nomount/disabled";

pub fn guard_tripped() -> bool {
    Path::new(DISABLED_MARKER).exists()
}

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

pub const MY_HOOKLESS_MARKER: &str = "/data/adb/nomount/my_hookless";

pub(crate) fn is_partition_root(target: &Path) -> bool {
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

/// The dlkm three are here for their `lib/modules` payload: they are standard top-level
/// partitions from Android 12 on, `NON_PARTITION_ROOTS` does not list them, so a whiteout
/// on `/vendor_dlkm/lib/modules/*.ko` was accepted, written to whiteouts.txt and
/// re-applied on every boot -- a kernel module made absent, which is the dead-boot shape
/// this list exists to refuse.
const BOOT_CRITICAL_PARTITIONS: &[&str] = &[
    "system", "system_ext", "vendor", "odm", "product", "vendor_dlkm", "system_dlkm",
    "odm_dlkm",
];
const BOOT_CRITICAL_DIRS: &[&str] = &["bin", "lib", "lib64", "framework", "etc", "apex"];
/// The subset of those where nothing INSIDE may be made absent either, at any depth.
///
/// A shared library or an apex payload is replaced by injecting over it, never by hiding
/// it, and hiding one does not break a feature -- it stops the device booting.
///
/// `bin`, `etc` and `framework` stay out deliberately. The first two are what this
/// mechanism is for (`/system/bin/install-recovery.sh`, `/vendor/etc/foo.conf`), and
/// `/system/framework` holds OEM jars that debloating legitimately removes -- pinned by
/// whiteout_refuses_what_init_the_linker_and_zygote_need. Note that leaves the core jars
/// in that directory acceptable to whiteout; refusing those needs a name list, not a
/// subtree rule.
const BOOT_CRITICAL_SUBTREES: &[&str] = &["lib", "lib64", "apex"];
const ZYGOTE_BINARIES: &[&str] = &["app_process", "app_process32", "app_process64"];

fn is_boot_critical(target: &Path) -> bool {
    let parts: Vec<&str> = target
        .components()
        .skip(1)
        .map(|c| c.as_os_str().to_str().unwrap_or(""))
        .collect();
    match parts.as_slice() {
        [part, dir] => BOOT_CRITICAL_PARTITIONS.contains(part) && BOOT_CRITICAL_DIRS.contains(dir),
        // The arm above matches EXACTLY two components, so everything one level deeper
        // fell straight through to false: `/system/lib64/libc.so` was accepted, written to
        // whiteouts.txt and re-applied on every boot, which costs three failed boots
        // before the guard parks the Suite and leaves recovery as the only way back.
        [part, dir, ..]
            if BOOT_CRITICAL_PARTITIONS.contains(part) && BOOT_CRITICAL_SUBTREES.contains(dir) =>
        {
            true
        }
        ["system", "bin", name] => name.starts_with("linker") || ZYGOTE_BINARIES.contains(name),
        // The linker reads these before anything links; an absent one is a dead boot.
        ["system", "etc", name] => name.starts_with("ld.config"),
        _ => false,
    }
}

/// `/system/system_ext/…` read as `/system_ext/…`: on a device where that partition is a
/// directory of /system (or /odm one of /vendor), the name-based refusals saw only the
/// literal path and let a whole partition or its libraries be hidden.
fn fold_nested_partition(target: &Path) -> Option<PathBuf> {
    let mut parts = target.components();
    parts.next()?;
    let outer = parts.next()?.as_os_str().to_str()?;
    let inner = parts.next()?.as_os_str().to_str()?;
    let nested = match outer {
        "system" => ["system_ext", "product", "vendor"].contains(&inner),
        "vendor" => inner == "odm",
        _ => false,
    };
    nested.then(|| Path::new("/").join(inner).join(parts.as_path()))
}

pub(crate) fn can_whiteout(target: &Path) -> Result<(), &'static str> {
    can_whiteout_with(target, &|p: &Path| fs::symlink_metadata(p).is_ok_and(|m| m.is_dir()))
}

/// `real_dir`: the path is a directory, not a symlink to one.
pub(crate) fn can_whiteout_with(
    target: &Path,
    real_dir: &dyn Fn(&Path) -> bool,
) -> Result<(), &'static str> {
    let Some(root) = target.components().nth(1).and_then(|c| c.as_os_str().to_str()) else {
        return Err("not a path under a partition");
    };
    if NON_PARTITION_ROOTS.contains(&root) {
        return Err("not a ROM partition");
    }
    if is_partition_root(target) {
        return Err("a bare partition root (masking one bootloops zygote)");
    }
    // A bare nested root (`/system/vendor`) is a stub or debloat directory only while a real
    // partition sits at `/vendor`. Where `/system_ext` is the symlink (a device upgraded from
    // Android 10) or absent, `/system/system_ext` IS the partition, and canonicalising in
    // validate() cannot see that; plan_tree's markers never go through validate() at all.
    let folded = fold_nested_partition(target);
    if let Some(f) = folded.as_deref().filter(|f| is_partition_root(f)) {
        if !(real_dir(target) && real_dir(f)) {
            return Err("a bare partition root (masking one bootloops zygote)");
        }
    }
    if std::iter::once(target).chain(folded.as_deref()).any(is_boot_critical) {
        return Err("a path init, the linker or zygote cannot start without (masking it \
                    bootloops the device)");
    }
    Ok(())
}

fn inject_would_mask_dir(target: &Path) -> bool {
    target.is_dir()
}

pub(crate) fn needs_unmount_before_serving(kind: PlanKind) -> bool {
    matches!(kind, PlanKind::Inject | PlanKind::Whiteout)
}

pub(crate) fn apply_order(plan: &[PlanEntry]) -> Vec<&PlanEntry> {
    plan.iter()
        .filter(|e| e.kind == PlanKind::Inject)
        .chain(plan.iter().filter(|e| e.kind == PlanKind::Whiteout))
        .collect()
}

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
    // `nm list` renders a rule on one line and appends its markers, and the consumer
    // (nm::parse_line) cuts the line at the first of these it finds. The guard covered
    // " [UID:" alone and was never extended when the scope work added [SCOPE: and [DENY:,
    // so a path carrying either truncated the parse -- or forged a scope the rule never
    // had. Matched without the leading space too, because that is how parse_line searches.
    for marker in ["[UID:", "[SCOPE:", "[DENY:"] {
        if s.contains(marker) {
            return Err("its name contains `[UID:`, `[SCOPE:` or `[DENY:`, which `nm list` \
                        uses to split a rule's markers off the path");
        }
    }
    for suffix in [" (whiteout)", " (public)", " (virtual dir)"] {
        if s.ends_with(suffix) {
            return Err("its name ends in a marker `nm list` strips as a rule suffix");
        }
    }
    Ok(())
}

/// Why a module-tree entry must not become a plain injection rule.
///
/// plan_tree applies these when it builds a plan from a module's tree. absorb::inject walks a
/// mounted source directly and reached add_repointing without them, so a tree carrying any of
/// these produced a rule the planner exists to refuse -- most seriously a symlink resolving
/// into a world-writable place (under /data but not /data/adb, or shared storage), where a
/// non-root process would control the bytes served at a ROM path.
/// A FIFO, socket or device node (a 0:0 character device is a whiteout marker, handled
/// before this). The engine serves it with regular-file ops while stat reports the real
/// type, and opening a FIFO blocks with no writer.
fn special_file(ft: &fs::FileType) -> bool {
    ft.is_fifo() || ft.is_socket() || ft.is_block_device() || ft.is_char_device()
}

const SPECIAL_WHY: &str = "it is a FIFO, socket or device node, which the engine would serve \
                           as a regular file while stat still reports its real type";

pub(crate) fn absorb_refusal(source: &Path) -> Option<&'static str> {
    let Ok(md) = fs::symlink_metadata(source) else {
        return Some("its type could not be read");
    };
    let ft = md.file_type();
    if source.file_name().map(|n| n == ".replace").unwrap_or(false) {
        return Some("it is a .replace marker - a directive that only means something inside a \
                     module tree, and would otherwise be served as a literal file at a ROM path");
    }
    if is_whiteout_marker(&ft, source) {
        return Some("it is a character-device whiteout marker, which only means something \
                     inside a module tree");
    }
    if special_file(&ft) {
        return Some(SPECIAL_WHY);
    }
    if ft.is_symlink() {
        let resolved = fs::canonicalize(source).ok();
        if resolved.as_deref().map(resolved_source_is_untrusted).unwrap_or(false) {
            return Some("it is a symlink resolving into a world-writable location; the engine \
                         follows it, so a non-root process would control the bytes served");
        }
        if resolved.as_deref().map(Path::is_dir).unwrap_or(false) {
            return Some("it is a symlink to a directory, which the engine follows, so this \
                         would install a directory rule");
        }
    }
    None
}

fn source_resolves(e: &PlanEntry) -> bool {
    e.kind != PlanKind::Inject || e.source.exists()
}

/// Whether a source, followed to where it really is, sits where a non-root process can
/// write it. An unresolvable source is left to the caller's own existence check.
pub(crate) fn source_is_untrusted(source: &Path) -> bool {
    fs::canonicalize(source).ok().as_deref().map(resolved_source_is_untrusted).unwrap_or(false)
}

fn resolved_source_is_untrusted(resolved: &Path) -> bool {
    (resolved.starts_with("/data/") && !resolved.starts_with("/data/adb/"))
        || resolved.starts_with("/data_mirror")
        || crate::health::is_shared_storage(resolved)
}

pub(crate) fn module_enabled(dir: &Path) -> bool {
    !dir.join("disable").exists()
        && !dir.join("remove").exists()
        && !dir.join("skip_mount").exists()
}

pub(crate) fn load_blocklist() -> HashSet<String> {
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum PlanKind {
    Inject,
    Whiteout,
    Bind,
}

/// Follows symlinks on purpose: the engine follows them too, so what decides this is
/// what the target resolves to, not what sits at the name. A target that does not exist
/// is not a mismatch - the module is adding something new.
fn dir_over_stock_file(target: &Path) -> bool {
    fs::metadata(target).map(|m| !m.is_dir()).unwrap_or(false)
}

pub(crate) struct Refused {
    pub module: String,
    pub target: PathBuf,
    pub why: &'static str,
}

pub(crate) struct PlanEntry {
    pub module: String,
    pub target: PathBuf,
    pub source: PathBuf,
    pub kind: PlanKind,
}

#[derive(Default)]
pub(crate) struct EngineEdits {
    hidden: HashMap<PathBuf, Vec<std::ffi::OsString>>,
    synthesized: HashSet<PathBuf>,
}

impl EngineEdits {
    pub(crate) fn from_list(list: &str) -> Self {
        let mut edits = Self::default();
        for r in crate::nm::parse_list(list) {
            if r.uid != 0 {
                continue;
            }
            match r.kind {
                crate::nm::LiveKind::Whiteout => {
                    if let (Some(dir), Some(name)) = (r.target.parent(), r.target.file_name()) {
                        edits.hidden.entry(dir.to_path_buf()).or_default().push(name.to_os_string());
                    }
                }
                crate::nm::LiveKind::VirtualDir => {
                    edits.synthesized.insert(r.target);
                }
                crate::nm::LiveKind::Inject => {}
            }
        }
        edits
    }

    fn stock_listing(&self, dir: &Path) -> Option<Vec<(std::ffi::OsString, bool)>> {
        let mut names: Vec<(std::ffi::OsString, bool)> = fs::read_dir(dir)
            .ok()?
            .flatten()
            .filter(|e| !self.synthesized.contains(&dir.join(e.file_name())))
            .map(|e| (e.file_name(), e.file_type().map(|t| t.is_dir()).unwrap_or(false)))
            .collect();
        for name in self.hidden.get(dir).into_iter().flatten() {
            if !names.iter().any(|(n, _)| n == name) {
                names.push((name.clone(), false));
            }
        }
        names.sort();
        Some(names)
    }
}

fn expand_replacement(
    module: &str,
    stock_dir: &Path,
    module_dir: &Path,
    marker: &Path,
    depth: u32,
    edits: &EngineEdits,
    out: &mut Vec<PlanEntry>,
) {
    if depth > 16 {
        eprintln!(
            "nomount: {module}: giving up expanding {} past depth 16",
            stock_dir.display()
        );
        return;
    }
    let Some(entries) = edits.stock_listing(stock_dir) else {
        return;
    };
    for (name, stock_is_dir) in entries {
        let stock_child = stock_dir.join(&name);
        let module_child = module_dir.join(&name);

        let shipped = fs::symlink_metadata(&module_child).ok();

        match shipped {
            Some(m) if m.is_dir() && stock_is_dir => {
                expand_replacement(
                    module,
                    &stock_child,
                    &module_child,
                    marker,
                    depth + 1,
                    edits,
                    out,
                );
            }
            Some(_) => {}
            None => {
                if can_whiteout(&stock_child).is_err() {
                    continue;
                }
                if path_is_representable(&stock_child).is_err() {
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

/// An Inject always beats a Whiteout for the same target, whoever claimed it last.
///
/// `.replace` expansion reads the directory as it looks NOW, and on any pass after the
/// first that includes files another module has already injected - so a `.replace`
/// module would emit a whiteout over a path somebody else serves. Letting sort order
/// decide made that a coin toss, and because the whiteout then hid the file from the
/// next pass's listing the two outcomes alternated boot to boot.
fn beats(a: &PlanEntry, b: &PlanEntry) -> bool {
    match (a.kind, b.kind) {
        (PlanKind::Whiteout, PlanKind::Whiteout) => true,
        (PlanKind::Whiteout, _) => false,
        (_, PlanKind::Whiteout) => true,
        _ => true,
    }
}

fn same_rule(a: &PlanEntry, b: &PlanEntry) -> bool {
    a.module == b.module
        && a.kind == b.kind
        && (a.kind == PlanKind::Whiteout || a.source == b.source)
}

pub(crate) fn dedupe_by_target(plan: Vec<PlanEntry>) -> (Vec<PlanEntry>, Vec<Collision>) {
    let mut last: HashMap<PathBuf, usize> = HashMap::new();
    for (i, e) in plan.iter().enumerate() {
        match last.get(&e.target) {
            Some(&j) if !beats(e, &plan[j]) => {}
            _ => {
                last.insert(e.target.clone(), i);
            }
        }
    }
    if last.len() == plan.len() {
        return (plan, Vec::new());
    }
    let mut losers: HashMap<PathBuf, Vec<String>> = HashMap::new();
    for (i, e) in plan.iter().enumerate() {
        let Some(&w) = last.get(&e.target) else { continue };
        if w == i || same_rule(e, &plan[w]) {
            continue;
        }
        losers.entry(e.target.clone()).or_default().push(e.module.clone());
    }
    let mut collisions: Vec<Collision> = Vec::new();
    let mut kept = Vec::with_capacity(last.len());
    for (i, e) in plan.into_iter().enumerate() {
        if last.get(&e.target) != Some(&i) {
            continue;
        }
        if let Some(mut l) = losers.remove(&e.target) {
            let self_claimed = l.iter().any(|m| m == &e.module);
            l.retain(|m| m != &e.module);
            l.sort_unstable();
            l.dedup();
            if self_claimed {
                // One module resolving to the same target twice - e.g. shipping both
                // product/x and system/product/x, which resolve_target_path folds
                // together. Silently keeping whichever sorted last served the wrong
                // file whenever the two differed, with nothing said anywhere.
                l.insert(0, format!("{} (a second claim of its own)", e.module));
            }
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
    edits: &EngineEdits,
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
            refused.push(Refused {
                module: module.to_string(),
                target: source.clone(),
                why: "its name is not valid UTF-8, so no rule can name it",
            });
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
            refused.push(Refused {
                module: module.to_string(),
                target: target.clone(),
                why: if what == "target" {
                    "the wire format cannot carry this target path"
                } else {
                    "the wire format cannot carry this source path"
                },
            });
            continue;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();

        if ft.is_dir() {
            // A module directory over a stock FILE. The walk below would plan injects at
            // paths under that file - targets that cannot exist, so nothing the module
            // ships here is ever served. inject_would_mask_dir() catches the mirror case
            // (a file over a stock directory); this side was planned and then silent.
            if dir_over_stock_file(&target) {
                eprintln!(
                    "nomount: {module}: skipping {} - {} is a file in the stock tree, so \
                     nothing under this directory can be served",
                    source.display(),
                    target.display()
                );
                refused.push(Refused {
                    module: module.to_string(),
                    target: target.clone(),
                    why: "it is a directory over a stock file, so nothing under it can be served",
                });
                continue;
            }
            if is_opaque_dir(&source) && can_whiteout(&target).is_ok() {
                expand_replacement(module, &target, &source, &source, 0, edits, out);
            }
            plan_tree(module, module_root, &source, edits, out, refused)?;
        } else if name == ".replace" {
            if let Some(parent) = target.parent() {
                if can_whiteout(parent).is_err() {
                    eprintln!(
                        "nomount: {module}: skipping {} - {} may not be hidden",
                        source.display(),
                        parent.display()
                    );
                    refused.push(Refused {
                        module: module.to_string(),
                        target: parent.to_path_buf(),
                        why: "a .replace here would hide a path the Suite refuses to hide",
                    });
                    continue;
                }
                if let Some(module_dir) = source.parent() {
                    expand_replacement(module, parent, module_dir, &source, 0, edits, out);
                }
            }
        } else if is_whiteout_marker(&ft, &source) {
            if can_whiteout(&target).is_err() {
                eprintln!(
                    "nomount: {module}: skipping {} - it may not be hidden",
                    target.display()
                );
                refused.push(Refused {
                    module: module.to_string(),
                    target: target.clone(),
                    why: "the Suite refuses to hide this path",
                });
                continue;
            }
            out.push(PlanEntry {
                module: module.to_string(),
                target,
                source,
                kind: PlanKind::Whiteout,
            });
        } else {
            if special_file(&ft) {
                eprintln!("nomount: {module}: skipping {} - {SPECIAL_WHY}", source.display());
                refused.push(Refused {
                    module: module.to_string(),
                    target: target.clone(),
                    why: SPECIAL_WHY,
                });
                continue;
            }
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
                    refused.push(Refused {
                        module: module.to_string(),
                        target: target.clone(),
                        why: "it is a symlink resolving outside /data/adb, so a non-root process \
                              would control the bytes served there",
                    });
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
                    refused.push(Refused {
                        module: module.to_string(),
                        target: target.clone(),
                        why: "it is a symlink to a directory, which would install a directory \
                              rule at the partition root. Ship the files individually.",
                    });
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
                    refused.push(Refused {
                        module: module.to_string(),
                        target: target.clone(),
                        why: "it resolves to a live directory, and injecting a file there would \
                              mask the whole directory",
                    });
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

pub(crate) fn unmount_before_serving(
    targets: &std::collections::HashSet<PathBuf>,
    target: &Path,
) -> bool {
    if !targets.contains(target) {
        // The exact target carries no mount, but hiding a directory with a live mount
        // underneath leaves that mount in every app's mountinfo with no path reaching it -
        // the condition this function exists to prevent, one level down. Inject targets
        // are files, so is_dir() keeps this off that path.
        if target.is_dir() && targets.iter().any(|m| m != target && m.starts_with(target)) {
            eprintln!(
                "nomount: {} has a live mount under it; hiding it would strand that mount \
                 in mountinfo, so it is left unserved",
                target.display()
            );
            return false;
        }
        // `targets` is a SNAPSHOT, taken before teardown_all() and before an apply loop
        // that then runs for hundreds of process spawns with module scripts and ksud
        // live. A mount that appeared after it was taken is simply absent from it, and
        // returning "safe to serve" on that basis injects straight over a live mount --
        // stranding its row in mountinfo with no path reaching it, which is the one
        // outcome this function exists to prevent. Treat the snapshot as a fast path and
        // confirm anything it does not know about against the live table.
        if !crate::absorb::still_mounted(target) {
            return true;
        }
    }
    // Whatever is mounted here is about to be MNT_DETACHed, which no later pass can undo,
    // so establish it is the module system's before touching it. Without this, hiding a
    // path silently destroyed an unrelated mount at the same place -- `whiteout add
    // /system/etc/hosts` taking down an ad-blocker's bind, with no record of what it was.
    // absorb proves ownership this way before every unmount it does; this path did not.
    let depth = match crate::absorb::mounts_here_are_ours(target) {
        Some((true, n)) => n,
        Some((false, _)) => {
            eprintln!(
                "nomount: {} carries a mount the module system did not make; unmounting it \
                 would destroy whatever owns it, so this is left unserved",
                target.display()
            );
            return false;
        }
        // `ownership_of` answers None for two different things: the mount table could not
        // be read, and nothing is mounted at this target at all. Only the first is a reason
        // to refuse. The snapshot is taken before teardown_all(), so a target that carried a
        // module mount when it was taken and is free now arrives here -- and was refused
        // with a message blaming an unreadable table for a path that is simply available.
        //
        // still_mounted() is the right discriminator because it fails the safe way: an
        // unreadable table reads as "mounted" (.unwrap_or(true)), so it cannot turn a
        // read failure into permission to inject over something.
        None if !crate::absorb::still_mounted(target) => return true,
        None => {
            eprintln!(
                "nomount: could not read the mount table to tell who owns the mount on {}, \
                 so it is left unserved rather than unmounted on a guess",
                target.display()
            );
            return false;
        }
    };

    // Pop exactly the stack that was verified, re-checking each time: one umount2 clears
    // one mount, and the old single call left a two-deep stack half-popped -- the top one
    // destroyed, nothing served, and the system in neither the before nor the after state.
    for _ in 0..depth {
        if !crate::absorb::still_mounted(target) {
            break;
        }
        if crate::absorb::mounts_here_are_ours(target).map(|(ours, _)| ours) != Some(true) {
            break;
        }
        if !crate::absorb::umount_detach(target) {
            break;
        }
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

pub(crate) fn collect_plan() -> Result<(Vec<PlanEntry>, u32, Vec<Refused>)> {
    // Not fatal: the boot pass must still serve. Without the listing a `.replace` cannot
    // tell the engine's own entries from stock ones, so say so.
    let edits = match Nm::new().list_retry() {
        Ok(l) => EngineEdits::from_list(&l),
        Err(e) => {
            eprintln!(
                "nomount: nm list failed ({e:#}) - a .replace this pass may count the engine's \
                 own entries as stock ones"
            );
            EngineEdits::default()
        }
    };
    collect_plan_with(&edits)
}

/// The `why` of a module whose root could not be listed. Reload keeps that module's live
/// rules rather than pruning them as an intentional unload.
const UNLISTABLE: &str = "the module directory could not be listed; its live rules are kept";

fn collect_plan_with(edits: &EngineEdits) -> Result<(Vec<PlanEntry>, u32, Vec<Refused>)> {
    let blocklist = load_blocklist();
    let mut plan = Vec::new();
    let mut refused: Vec<Refused> = Vec::new();
    let mut skipped = 0u32;
    let dirs = fs::read_dir(MODULES_DIR)
        .with_context(|| format!("cannot enumerate {MODULES_DIR} -- refusing to treat that as \"no modules installed\", which would clear every rule"))?;
    let mut dirs: Vec<_> = dirs
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("cannot enumerate {MODULES_DIR} in full"))?;
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
        // One unreadable module must not stop the others being served, and it must not read
        // as "this module ships nothing" either: recorded, so reload keeps its rules.
        let listed = fs::read_dir(&mdir).and_then(|d| d.collect::<std::io::Result<Vec<_>>>());
        if let Err(err) = &listed {
            eprintln!(
                "nomount: {id}: cannot list {} ({err}) - its rules are left as they are",
                mdir.display()
            );
            refused.push(Refused { module: id.clone(), target: mdir.clone(), why: UNLISTABLE });
        }
        if let Ok(mut entries) = listed {
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
                plan_tree(&id, &mdir, &e.path(), edits, &mut plan, &mut refused).with_context(|| {
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

/// A plan entry on a target absorb has also recorded, with a different source. Absorbed
/// rules are added first and the plan's replaces them, so the plan source is what serves.
/// The same source is the common, harmless case: a module that ships a file and also
/// binds it. Absorbed rules on ROM targets are never scoped (only /data/app APKs are), so
/// there is no apkscope exposure either way. Reported, not fatal: refusing to serve over
/// a reporting feature would be the worse failure.
fn report_absorbed_overlap(plan: &[PlanEntry]) {
    match crate::absorb::read_absorbed_pairs() {
        Ok(pairs) => {
            for e in plan {
                let Some((_, src)) = pairs.iter().find(|(t, _)| *t == e.target) else {
                    continue;
                };
                if *src == e.source {
                    continue;
                }
                eprintln!(
                    "nomount: {} is served from {} by {}, replacing the absorbed rule for {} on \
                     every pass. Drop it from the module, or from absorbed.list.",
                    e.target.display(),
                    e.source.display(),
                    e.module,
                    src.display()
                );
            }
        }
        Err(e) => eprintln!(
            "nomount: cannot read the absorbed-rule record ({e:#}) - a module plan entry on an \
             absorbed target is not reported this pass"
        ),
    }
}

/// An absorbed inject beats a whiteout on the same path, as `whiteout apply` already has it.
/// Without one precedence the boot pass, reload and absorb took turns replacing each
/// other's rule, so the path flipped between hidden and served on every pass.
fn yield_whiteouts_to_absorbed(plan: Vec<PlanEntry>) -> Vec<PlanEntry> {
    let Ok(absorbed) = crate::absorb::read_absorbed_targets() else {
        return plan;
    };
    plan.into_iter()
        .filter(|e| {
            let yields = e.kind == PlanKind::Whiteout && absorbed.contains(&e.target);
            if yields {
                eprintln!(
                    "nomount: the whiteout on {} from {} yields to its absorbed rule",
                    e.target.display(),
                    e.module
                );
            }
            !yields
        })
        .collect()
}

pub fn run_plan() -> Result<()> {
    let (plan, skipped, refused) = collect_plan()?;
    // `plan` is the diagnostic a user runs to understand what a pass WILL do, and it was
    // the one view that threw the collisions away: two modules claiming one target showed
    // only the winner, with no hint that anything had been dropped. run_mount and
    // run_reload both report them.
    let (plan, collisions) = dedupe_by_target(plan);
    report_absorbed_overlap(&plan);
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
    for c in &collisions {
        println!(
            "COLLIDED {} << claimed by {}, serving {}, skipping {}",
            c.target.display(),
            c.losers.len() + 1,
            c.winner,
            c.losers.join(", ")
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
    if !collisions.is_empty() {
        extra.push_str(&format!(", {} contested target(s)", collisions.len()));
    }
    println!("({} entries: {} binds, {skipped} blocklisted{extra})", plan.len(), binds);
    Ok(())
}

enum LiveRule {
    Inject(PathBuf),
    Whiteout,
}

/// Returns the rules this Suite could own, and a count of the ones it cannot.
///
/// A scoped rule -- a uid range or an exclusion -- was put there by another
/// writer, because the Suite only ever adds legacy-shaped rules. Keeping it out
/// of the reconciler's map is what stops the prune pass from trying to delete
/// it: the delete key is the whole scope, `nm del <path>` sends none of it, so
/// the attempt could never succeed and would be retried on every single pass.
fn parse_live_rules(
    list: &str,
    ours: &HashSet<PathBuf>,
) -> (HashMap<(PathBuf, u32), LiveRule>, u32) {
    let mut foreign = 0u32;
    let map = crate::nm::parse_list(list)
        .into_iter()
        .filter_map(|r| {
            if r.scoped {
                // A scope on a target we absorbed is one WE wrote, under apkscope.
                // Counting it as another writer's would report the Suite's own rule
                // back to the operator as something it must not touch.
                if !ours.contains(&r.target) {
                    foreign += 1;
                }
                return None;
            }
            let kind = match r.kind {
                crate::nm::LiveKind::Inject => LiveRule::Inject(r.source?),
                crate::nm::LiveKind::Whiteout => LiveRule::Whiteout,
                crate::nm::LiveKind::VirtualDir => return None,
            };
            Some(((r.target, r.uid), kind))
        })
        .collect();
    (map, foreign)
}

fn prune_order(live: &HashMap<(PathBuf, u32), LiveRule>) -> Vec<&(PathBuf, u32)> {
    let mut stale: Vec<&(PathBuf, u32)> = live.keys().collect();
    stale.sort_by_key(|(t, uid)| (std::cmp::Reverse(t.components().count()), t.clone(), *uid));
    stale
}

fn durable_not_planned(durable: Vec<PathBuf>, plan: &[PlanEntry]) -> Vec<PathBuf> {
    let planned: HashSet<&Path> = plan.iter().map(|e| e.target.as_path()).collect();
    durable.into_iter().filter(|w| !planned.contains(w.as_path())).collect()
}

/// A module that could not be listed is not unloaded: Some, with whether the rule is an
/// inject whose recorded identity has to go with it. Dropping that row made the next reload
/// read a hot-installed replacement as up to date. A whiteout names no source to attribute,
/// so while any module is unlisted they all stay.
fn held_for_unlisted(rule: Option<&LiveRule>, unlisted: &[PathBuf]) -> Option<bool> {
    if unlisted.is_empty() {
        return None;
    }
    match rule {
        Some(LiveRule::Inject(src)) => unlisted.iter().any(|m| src.starts_with(m)).then_some(true),
        _ => Some(false),
    }
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

    // Read before the live listing: a scoped rule on one of these targets is one WE
    // put there (an absorbed APK rule under apkscope), not another writer's.
    let mut absorbed = crate::absorb::read_absorbed_targets()
        .context("cannot read the absorbed-rule record - refusing to reload, because an empty record here would prune every absorbed rule")?;
    let absorbed_injects = absorbed.clone();
    absorbed.extend(
        crate::absorb::read_absorbed_tmpfs_targets()
            .context("cannot read the ROM-tmpfs takeover record - refusing to reload, because an empty record here would prune every takeover whiteout")?,
    );

    let live_txt = nm.list().context("nm list failed during reload")?;
    let (live, foreign) = parse_live_rules(&live_txt, &absorbed);
    // What the engine was last given per target: a source path can be unchanged
    // while the file behind it is not, and the live rule text cannot show that.
    let last_served = crate::rulestate::read();

    let (plan, skipped, refused) = collect_plan_with(&EngineEdits::from_list(&live_txt))?;
    let plan = yield_whiteouts_to_absorbed(plan);
    let unlisted: Vec<PathBuf> =
        refused.iter().filter(|r| r.why == UNLISTABLE).map(|r| r.target.clone()).collect();
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

    let durable_whiteouts: HashSet<PathBuf> = durable_not_planned(
        crate::whiteout::read()
            .context("cannot read the durable whiteout list - refusing to reload, because an empty list here would prune every whiteout")?
            .into_iter()
            .map(PathBuf::from)
            .filter(|w| !absorbed_injects.contains(w))
            .collect(),
        &plan,
    )
    .into_iter()
    .collect();
    let (mut added, mut changed, mut removed, mut failed) = (0u32, 0u32, 0u32, 0u32);
    let mounted = crate::absorb::mounted_targets().context(
        "cannot read /proc/self/mountinfo - refusing to serve, because assuming \"nothing is mounted\" injects over live mounts and strands each one in mountinfo until reboot",
    )?;
    let mut applied_apks: Vec<(PathBuf, PathBuf)> = Vec::new();
    // Targets this pass could not re-apply. The engine still serves what it served before,
    // so their recorded identity has to survive -- see rulestate::write_keeping.
    let mut kept_identity: Vec<PathBuf> = Vec::new();
    for e in apply_order(&plan) {
        let t = e.target.as_path();
        let up_to_date = match live.get(&(t.to_path_buf(), 0)) {
            Some(LiveRule::Inject(src)) => {
                e.kind == PlanKind::Inject
                    && src.as_path() == e.source.as_path()
                    && !crate::rulestate::is_stale(&last_served, t, &e.source)
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
            keep_identity_of(&mut kept_identity, e);
            continue;
        }
        if !unmount_before_serving(&mounted, &e.target) {
            failed += 1;
            keep_identity_of(&mut kept_identity, e);
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
            Err(_) => {
                failed += 1;
                keep_identity_of(&mut kept_identity, e);
            }
        }
    }
    for w in &durable_whiteouts {
        if crate::whiteout::validate(&w.to_string_lossy()).is_err() {
            eprintln!("nomount: skipping invalid whiteout entry {}", w.display());
            failed += 1;
            continue;
        }
        if !unmount_before_serving(&mounted, w) {
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
        if let Some(inject) = held_for_unlisted(live.get(&(t.clone(), *uid)), &unlisted) {
            if inject {
                kept_identity.push(t.clone());
            }
            continue;
        }
        if nm.del_any(t).is_ok() {
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

    crate::bind::register_try_umount();

    crate::rulestate::write_keeping(
        &injected_pairs(&plan, &applied_apks),
        &last_served,
        &kept_identity,
    );

    let pm = crate::pmcache::sync(&served_apks_applied(
        &applied_apks,
        &crate::absorb::absorbed_pairs(),
    ));
    crate::pmcache::add_pending(&pm);

    // No "(gap-free)" trailer. It was printed unconditionally, next to the pass's own
    // `failed` count, so a reload that failed to apply rules still advertised itself as
    // gap-free -- and nothing in the repository computed or read the string. The honest
    // signal is run_mount's warning, which this pass now prints the same way.
    println!(
        "nomount reload: +{added} ~{changed} -{removed} rules, +{bind_added} -{bind_removed} binds, \
         {failed} failed, {skipped} blocklisted{}",
        if foreign > 0 { format!(", {foreign} left to another writer") } else { String::new() }
    );
    if failed > 0 {
        eprintln!(
            "nomount: WARNING {failed} rule(s) failed to apply - the injection set is incomplete"
        );
    }
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

pub(crate) const MODULE_SUMMARY: &str = "/data/adb/nomount/modules.tsv";

/// Written just before a pass tears everything down, removed once it has rebuilt.
///
/// `run_mount` unmounts every recorded bind, wipes the whole engine rule table and only
/// then rebuilds, with no rollback: killed in between -- and module/lib.sh runs it under
/// `nmto 60`, which SIGKILLs -- the device finishes booting with no rules and no binds,
/// serving nothing, with every whiteout un-applied. A real rollback is not available once
/// the kernel table is cleared, so the next pass at least gets to know it happened instead
/// of reading a half-built state as the truth.
const PASS_INFLIGHT: &str = "/data/adb/nomount/.mount.inflight";

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

    let (mut plan, skipped, _refused) = collect_plan()?;

    let durable: Vec<String> = crate::whiteout::read().context(
        "cannot read the durable whiteout list - refusing to serve, because clearing the table \
         and rebuilding without it would un-hide every path you asked to hide",
    )?;
    let valid: Vec<PathBuf> = durable
        .iter()
        .filter(|w| match crate::whiteout::validate(w) {
            Ok(()) => true,
            Err(why) => {
                eprintln!("nomount: durable whiteout skipped - {why}");
                false
            }
        })
        .map(PathBuf::from)
        .collect();
    for w in durable_not_planned(valid, &plan) {
        plan.push(PlanEntry {
            module: "durable".to_string(),
            target: w,
            source: std::path::PathBuf::new(),
            kind: PlanKind::Whiteout,
        });
    }

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

    let plan = yield_whiteouts_to_absorbed(plan);
    report_absorbed_overlap(&plan);

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

    if std::path::Path::new(PASS_INFLIGHT).exists() {
        eprintln!(
            "nomount: the previous mount pass was cut off between tearing down and \
             rebuilding, so what is on this device now is a partial pass, not a result. \
             This one rebuilds from the plan, which is the recovery."
        );
    }
    let _ = crate::statefile::write_atomic(PASS_INFLIGHT, b"");

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
    let mut reserve_failed = 0u32;
    if !recorded.is_empty() {
        let (n, failed) = crate::absorb::reapply_absorbed_pairs(&nm, &recorded);
        if n > 0 {
            println!("nomount: re-served {n} absorbed APK rule(s) from the record");
        }
        reserve_failed = failed;
    }

    let mut served: HashSet<&str> = HashSet::new();
    let mut binds = 0u32;
    let mut st = Stats {
        applied: 0,
        failed: reserve_failed,
        whiteouts: 0,
    };
    let mut applied_apks: Vec<(PathBuf, PathBuf)> = Vec::new();
    let mut injects: Vec<(&Path, &Path)> = Vec::new();
    let mounted = crate::absorb::mounted_targets().unwrap_or(mounted);

    let mut blocked: std::collections::HashSet<&Path> = std::collections::HashSet::new();
    for e in &plan {
        // `durable` is the sentinel run_mount uses for whiteout rows read off disk, not
        // an installed module; counting it inflates the boot line's module total.
        if e.module != "durable" {
            served.insert(e.module.as_str());
        }
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
                    // Still a live row in every app's mountinfo, so it counts: the boot
                    // line claimed `mountless` while binds.list rows were mounted.
                    binds += 1;
                    applied_apks.push((e.target.clone(), e.source.clone()));
                }
                Err(_) => st.failed += 1,
            },
            PlanKind::Inject => {}
        }
    }
    // Re-read rather than reusing `mounted`: the apply loop above has been unmounting and
    // binding, so the snapshot taken before it is stale by exactly the rows that matter.
    let mounted_now = crate::absorb::mounted_targets().unwrap_or_else(|| mounted.clone());
    let (tmpfs_hidden, tmpfs_failed) = crate::absorb::reapply_tmpfs_whiteouts(&nm, &mounted_now);
    st.failed += tmpfs_failed;
    let (ksu_umount, _) = crate::bind::register_try_umount();

    crate::rulestate::write(&injected_pairs(&plan, &applied_apks));

    let pm = crate::pmcache::sync(&served_apks_applied(&applied_apks, &recorded));
    crate::pmcache::clear_pending();

    let modules = served.len();
    let surface = if binds > 0 {
        if ksu_umount > 0 {
            "hookless + my_* bind (DenyList-unmountable)"
        } else {
            "hookless + my_* bind"
        }
    } else {
        "mountless (RRO via hookless)"
    };

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
    // The pass reached the end, so what is on the device is a whole one.
    let _ = fs::remove_file(PASS_INFLIGHT);
    crate::ghost::sync_after_pass(&nm);
    Ok(())
}

/// The inject half of what was applied -- the pairs whose backing identity a
/// later reload compares against. A bind is reconciled on (target, source)
/// already, and a whiteout has no backing file.
/// Remember an inject the pass could not land, so its rulestate row is not dropped.
fn keep_identity_of(kept: &mut Vec<PathBuf>, e: &PlanEntry) {
    if e.kind == PlanKind::Inject {
        kept.push(e.target.clone());
    }
}

fn injected_pairs(
    plan: &[PlanEntry],
    applied: &[(PathBuf, PathBuf)],
) -> Vec<(PathBuf, PathBuf)> {
    let injects: HashSet<&Path> = plan
        .iter()
        .filter(|e| e.kind == PlanKind::Inject)
        .map(|e| e.target.as_path())
        .collect();
    applied.iter().filter(|(t, _)| injects.contains(t.as_path())).cloned().collect()
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
    use std::sync::LazyLock;

    fn pe(module: &str, target: &str, kind: PlanKind) -> PlanEntry {
        PlanEntry {
            module: module.to_string(),
            target: PathBuf::from(target),
            source: PathBuf::from("/data/adb/modules/x/src"),
            kind,
        }
    }

    #[test]
    fn an_inject_beats_a_whiteout_for_the_same_target_whoever_claimed_it_last() {
        // `.replace` reads the live tree, so a module that sorts LAST can emit a
        // whiteout over a path another module injects. Order must not decide this.
        let (kept, _) = dedupe_by_target(vec![
            pe("a_mod", "/product/etc/x", PlanKind::Inject),
            pe("z_mod", "/product/etc/x", PlanKind::Whiteout),
        ]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].kind, PlanKind::Inject, "the whiteout won, so the file vanishes");
        assert_eq!(kept[0].module, "a_mod");

        // and the same the other way round, so it is not just "first wins"
        let (kept, _) = dedupe_by_target(vec![
            pe("z_mod", "/product/etc/x", PlanKind::Whiteout),
            pe("a_mod", "/product/etc/x", PlanKind::Inject),
        ]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].kind, PlanKind::Inject);
    }

    #[test]
    fn two_whiteouts_on_one_target_still_collapse_to_one() {
        let (kept, _) = dedupe_by_target(vec![
            pe("a_mod", "/product/etc/x", PlanKind::Whiteout),
            pe("z_mod", "/product/etc/x", PlanKind::Whiteout),
        ]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].kind, PlanKind::Whiteout);
    }

    #[test]
    fn a_module_claiming_one_target_twice_is_reported_not_swallowed() {
        // product/x and system/product/x fold to the same target. Keeping whichever
        // sorted last served the wrong file when they differed, and said nothing.
        let (kept, collisions) = dedupe_by_target(vec![
            entry("one_mod", "/product/etc/x", "/data/adb/modules/one_mod/product/etc/x"),
            entry("one_mod", "/product/etc/x", "/data/adb/modules/one_mod/system/product/etc/x"),
        ]);
        assert_eq!(kept.len(), 1);
        assert_eq!(collisions.len(), 1, "a module colliding with itself was dropped silently");
        assert_eq!(collisions[0].winner, "one_mod");
        assert!(
            collisions[0].losers.iter().any(|l| l.contains("one_mod")),
            "the report must name the module: {:?}",
            collisions[0].losers
        );
    }

    #[test]
    fn a_module_expanding_one_directory_twice_is_not_a_collision() {
        let mut outer = pe("m", "/system/etc/permissions/a.xml", PlanKind::Whiteout);
        outer.source = PathBuf::from("/data/adb/modules/m/system/etc/.replace");
        let mut inner = pe("m", "/system/etc/permissions/a.xml", PlanKind::Whiteout);
        inner.source = PathBuf::from("/data/adb/modules/m/system/etc/permissions/.replace");
        let (kept, collisions) = dedupe_by_target(vec![outer, inner]);
        assert_eq!(kept.len(), 1);
        assert!(
            collisions.is_empty(),
            "nested .replace (or .replace plus the opaque xattr) plans the same hide twice; \
             that is one rule, not a module colliding with itself"
        );

        let (_, collisions) = dedupe_by_target(vec![
            pe("m", "/system/etc/x", PlanKind::Whiteout),
            pe("m", "/system/etc/x", PlanKind::Inject),
        ]);
        assert_eq!(collisions.len(), 1, "a hide and a serve from one module still differ");
    }

    #[test]
    fn a_module_directory_over_a_stock_file_is_a_mismatch() {
        let d = tempfile::tempdir().unwrap();
        let file = d.path().join("f");
        std::fs::write(&file, b"stock").unwrap();
        let dir = d.path().join("d");
        std::fs::create_dir(&dir).unwrap();

        assert!(dir_over_stock_file(&file), "a stock file cannot hold children");
        assert!(!dir_over_stock_file(&dir), "a stock directory is the normal case");
        assert!(
            !dir_over_stock_file(&d.path().join("absent")),
            "a target that does not exist is a module adding something, not a mismatch"
        );

        #[cfg(unix)]
        {
            let link = d.path().join("l");
            std::os::unix::fs::symlink(&file, &link).unwrap();
            assert!(
                dir_over_stock_file(&link),
                "the engine follows the link, so what it resolves to decides"
            );
        }
    }

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

    /// The ordinals of the C enum whose body names `first`, keyed by member name with
    /// `prefix` removed. Comments are stripped and `NAME = n` resets the counter, so a
    /// member added with a trailing comment still shifts every number after it.
    fn c_enum_ordinals(src: &str, first: &str, prefix: &str) -> HashMap<String, u32> {
        let mut text = String::new();
        let mut rest = src;
        while let Some(i) = rest.find("/*") {
            text.push_str(&rest[..i]);
            rest = rest[i + 2..].find("*/").map_or("", |j| &rest[i + 2 + j + 2..]);
        }
        text.push_str(rest);
        let text: String = text
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");
        let mut ord = HashMap::new();
        let Some(at) = text.find(first) else { return ord };
        let open = text[..at].rfind('{').map_or(0, |o| o + 1);
        let close = text[at..].find('}').map_or(text.len(), |c| at + c);
        let mut next = 0u32;
        for member in text[open..close].split(',') {
            let member = member.trim();
            if member.is_empty() {
                continue;
            }
            let (name, value) = match member.split_once('=') {
                Some((n, v)) => (n.trim(), v.trim().parse::<u32>().ok()),
                None => (member, None),
            };
            if let Some(v) = value {
                next = v;
            }
            if let Some(short) = name.strip_prefix(prefix) {
                ord.insert(short.to_string(), next);
            }
            next += 1;
        }
        ord
    }

    #[test]
    fn the_enum_reader_counts_commented_and_assigned_members() {
        let src = "enum {\n    X_UNSPEC = 0,\n    X_A,\n    X_NEW, /* added */\n    /* block\n       comment */\n    X_B, // tail\n    X_C = 9,\n    X_D,\n};";
        let o = c_enum_ordinals(src, "X_UNSPEC", "X_");
        let got: Vec<(String, u32)> = ["A", "NEW", "B", "C", "D"]
            .iter()
            .map(|k| (k.to_string(), o.get(*k).copied().unwrap_or(u32::MAX)))
            .collect();
        assert_eq!(
            got,
            [("A", 1), ("NEW", 2), ("B", 3), ("C", 9), ("D", 10)]
                .map(|(k, v)| (k.to_string(), v))
        );
    }

    #[test]
    fn the_wire_attribute_numbers_nm_hardcodes_match_the_engine_enum() {
        const NOMOUNT_H: &str = include_str!("../hookless/src/nomount.h");
        const NM_C: &str = include_str!("../userspace/src/nm.c");

        let ord = c_enum_ordinals(NOMOUNT_H, "NOMOUNT_ATTR_UNSPEC", "NOMOUNT_ATTR_");
        assert!(
            ord.len() > 1,
            "could not read the NOMOUNT_ATTR enum out of hookless/src/nomount.h, so this \
             contract is checking nothing"
        );

        // nm.c is freestanding and does not include the engine's header: it addresses every
        // attribute by bare integer (`at[n].type = 4`, `get_attr(rx, 5, 4)`). Nothing else
        // in the repo compares the two -- the compile matrix builds the engine WITHOUT nm,
        // and nm is built by zig but never run against an engine. Insert a member anywhere
        // above DENY_APPIDS and every literal below it addresses the wrong attribute, on a
        // wire that still parses and with no build error on either side.
        for (name, want) in [
            ("VIRTUAL_PATH", 1u32),
            ("REAL_PATH", 2),
            ("FLAGS", 3),
            ("UID", 4),
            ("VERSION", 5),
            ("PAYLOAD", 6),
            ("MODVER", 7),
            ("KNOBS", 8),
            ("UID_END", 9),
            ("DENY_APPIDS", 10),
        ] {
            assert_eq!(
                ord.get(name).copied(),
                Some(want),
                "NOMOUNT_ATTR_{name} is no longer {want} in hookless/src/nomount.h. \
                 userspace/src/nm.c hardcodes that number, so change the two together or \
                 the client starts addressing a different attribute"
            );
        }

        // ...and the literals are still the ones nm.c sends, so the pin above is not
        // guarding numbers nothing uses any more.
        for lit in [
            "at[n].type = 1;",
            "at[n].type = 2;",
            "at[n].type = 3;",
            "at[n].type = 4;",
            "at[n].type = 9;",
            "at[n].type = 10;",
            "get_attr(mem.rx_buf, 5, 4)",
            "get_attr_str(mem.rx_buf, 7)",
            "get_attr(mem.rx_buf, 8, 4)",
        ] {
            assert!(
                NM_C.contains(lit),
                "userspace/src/nm.c no longer contains `{lit}`; the ordinals pinned in this \
                 test are not the ones it puts on the wire"
            );
        }
    }

    #[test]
    fn the_command_and_knob_numbers_nm_hardcodes_match_the_engine_enums() {
        const NOMOUNT_H: &str = include_str!("../hookless/src/nomount.h");
        const NM_C: &str = include_str!("../userspace/src/nm.c");

        // nm.c sends both by bare integer, and these two enums have already been through a
        // retire/un-retire cycle with nothing but a comment guarding the numbers.
        let cmd = c_enum_ordinals(NOMOUNT_H, "NM_CMD_UNSPEC", "NM_CMD_");
        for (name, want) in [
            ("GET_VERSION", 1u32),
            ("ADD_RULE", 2),
            ("DEL_RULE", 3),
            ("CLEAR_ALL", 4),
            ("ADD_UID", 5),
            ("DEL_UID", 6),
            ("GET_LIST", 7),
            ("GET_UIDS", 8),
            ("SET_KNOB", 9),
            ("GET_PATHHIDE", 10),
            ("GET_GHOST", 11),
        ] {
            assert_eq!(
                cmd.get(name).copied(),
                Some(want),
                "NM_CMD_{name} is no longer {want} in hookless/src/nomount.h, and \
                 userspace/src/nm.c sends that number"
            );
        }
        let knob = c_enum_ordinals(NOMOUNT_H, "NM_KNOB_RESERVED_0", "NM_KNOB_");
        for (name, want) in
            [("VDIR_EROFS_SIZE", 4u32), ("HIDE_ISOLATED", 5), ("PATHHIDE", 6), ("GHOST", 7)]
        {
            assert_eq!(
                knob.get(name).copied(),
                Some(want),
                "NM_KNOB_{name} is no longer {want} in hookless/src/nomount.h, and \
                 userspace/src/nm.c sends that number"
            );
        }
        for lit in [
            "int target_cmd = 2 + (cmd == 'd');",
            "do_nm_cmd(fd,6 - (cmd == 'b'), 4,",
            "do_nm_cmd(fd, 9, 6,",
            "do_nm_cmd(fd,4, 0,",
            "do_nm_cmd_multi(fd, (cmd == 'A') ? 2 : 3,",
            "do_nm_cmd(fd, 1, 0,",
            "is_gh ? 11 : is_ph ? 10 : is_uids ? 8 : 7",
            "{ \"d\", 4 }, { \"i\", 5 }, { \"p\", 6 }, { \"g\", 7 },",
        ] {
            assert!(
                NM_C.contains(lit),
                "userspace/src/nm.c no longer contains `{lit}`; the numbers pinned in this \
                 test are not the ones it puts on the wire"
            );
        }
    }

    #[test]
    fn the_case_sweep_gate_is_wired_into_ci() {
        const BUILD_YAML: &str = include_str!("../.github/workflows/build.yaml");
        const SWEEP: &str = include_str!("../scripts/case-sweep.py");

        assert!(
            BUILD_YAML.contains("scripts/case-sweep.py"),
            "build.yaml no longer invokes scripts/case-sweep.py - the case-only gate is off, \
             and the bulk-rewrite class it catches (HEAD -> head, ARCH -> arch) is silent"
        );
        assert!(
            BUILD_YAML.contains("fetch-depth: 0"),
            "the sweep diffs the pushed range, so the test job's checkout needs full history; \
             with the default depth-1 checkout it has no predecessor to diff and checks nothing"
        );
        assert!(
            SWEEP.contains(r#"SKIP_MARKER = "[case-ok]""#),
            "case-sweep.py's escape-hatch marker changed; the failure message it prints and \
             this contract must name the same string"
        );
        // The other three gates the test job runs. Only case-sweep and gate-sweep were
        // pinned, so an edit to build.yaml could drop any of these and every test here
        // would still pass -- a gate nobody runs is indistinguishable from a gate that
        // cannot fail, which is the whole class this block exists to prevent.
        // Whole run lines, not paths: the shellcheck line names gate-sweep.sh and the zig
        // line names nm-parse-check.c, so a path test passed with both gates deleted.
        let runs = |line: &str| BUILD_YAML.lines().any(|l| l.trim() == line);
        for (needle, what) in [
            (
                "run: sh tests/lkm-load.sh",
                "the LKM loader suite: KMI selection, the keep-the-device-.ko-on-update rule \
                 and the prune",
            ),
            (
                "run: sh tests/ovl-layout-check.sh",
                "the LKM's struct ovl_fs layout check: a layout the module was not built for \
                 is refused before last_ino is written",
            ),
            (
                "run: sh tests/tail-gap-check.sh",
                "the engine's listing tail on overlay and erofs: terminal d_off at the entry \
                 count, and every buffer size resumes without a duplicate or a skip",
            ),
            (
                "run: sh tests/guard-reset.sh",
                "the bootloop guard across simulated boots: a late-pass panic still parks the \
                 Suite, two quick reboots do not",
            ),
            (
                "run: node scripts/webui-loadorder.js",
                "the WebUI load-order and built-command gate: every part's dependencies and \
                 whether each command it assembles still parses as shell",
            ),
            (
                "\"$RUNNER_TEMP/nm-parse-check\"",
                "the host check of nm's --uid-excluded parsing, the contract Morphe's \
                 \"NoMount only\" installs depend on, plus do_nm_cmd's single-attribute \
                 bound -- without it an over-length payload overflows tx_buf again",
            ),
            (
                "run: python3 scripts/contract-sweep.py quoting",
                "the WebUI root-call quoting sweep: every value interpolated or \
                 concatenated into a root shell string goes through shq(), which is \
                 otherwise only a convention",
            ),
        ] {
            assert!(
                runs(needle),
                "build.yaml no longer runs {needle}, so {what} stops being checked on every push"
            );
        }
        assert!(
            runs(r#"python3 scripts/case-sweep.py "$base..$sha""#),
            "build.yaml no longer runs the case sweep over the pushed range"
        );
        let test_job = BUILD_YAML
            .split_once("\n  test:")
            .and_then(|(_, rest)| rest.split_once("\n  build:"))
            .map(|(job, _)| job)
            .expect("build.yaml has a test job followed by the build job");
        assert!(
            !test_job.contains("continue-on-error"),
            "a step in the test job may fail without failing the job, so its gate cannot fail"
        );
        let branches = BUILD_YAML
            .lines()
            .find(|l| l.trim_start().starts_with("branches:"))
            .unwrap_or("")
            .to_string();
        for branch in ["prerelease", "main"] {
            assert!(
                branches.contains(branch),
                "build.yaml's push trigger does not name `{branch}`, so pushes to it run no \
                 tests, no shellcheck and no case sweep. Listing prerelease alone is how 13 of \
                 22 commits reached v1.3.180 ungated: {branches:?}"
            );
        }
        for ext in [".html", ".js", ".css"] {
            assert!(
                SWEEP.contains(ext),
                "case-sweep.py stopped covering {ext}, so that part of module/webroot is outside \
                 the gate again - index.html is where `grep -q ENABLED` became `enabled` and \
                 where the `would DROP`/`would SKIP` classifiers were lowercased, and the js/ \
                 files carry both of those classes of string now"
            );
        }
        assert!(
            !SWEEP.contains("zip(dels, adds)"),
            "case-sweep.py is pairing removed lines to added lines by position again. Any hunk \
             that adds a different number of lines than it removes - every prose re-wrap, which \
             is the shape a bulk rewrite makes - shifts the pairs and hides the damage"
        );
        // The ignorable-code-point refusal is RULE-ANCHORED, and nothing but this says so.
        // nm_gp_open_entry() used to call ghost_name_ignorable() on the bare filename and
        // ghost_hidden_path() used it as a standalone verdict, so for a hide-listed uid EVERY
        // path carrying one of those code points answered -ENOENT with no rule naming it --
        // an app could not stat or open an emoji-named file it owns, and open(O_CREAT)
        // returning ENOENT in a directory it had just written to is impossible on a stock
        // kernel, so two syscalls in its own sandbox proved an interposer. Both are one-word
        // reverts, and no host test can execute kernel code, so the contract is pinned as
        // source instead.
        const GP_C: &str = include_str!("../lkm/nm_ghost_probes.c");
        const GHOST_C: &str = include_str!("../lkm/ghost.c");
        assert!(
            GP_C.contains("ghost_hidden_name(*fname)"),
            "nm_gp_open_entry() no longer asks ghost_hidden_name(): if it is back on \
             ghost_name_ignorable(), do_filp_open() refuses every path with an invisible \
             code point for a hide-listed uid, including the caller's own files"
        );
        assert!(
            !GP_C.contains("ghost_name_ignorable(*fname)"),
            "the bare class check is back on the open path -- see ghost_hidden_name()"
        );
        // Counted, not matched: one definition plus the two call sites, in
        // ghost_hidden_path() and ghost_hidden_name(). Either call going missing turns that
        // predicate back into one that cannot see a folded spelling, which is the half of
        // this that keeps the /sdcard/Android/data<U+200B> bypass closed.
        assert!(
            GHOST_C.matches("ghost_strip_ignorable(").count() >= 3,
            "ghost.c has fewer than three mentions of ghost_strip_ignorable (one definition, \
             two calls), so one of the two rule-anchored paths has lost its stripped-form test"
        );
        // The engine's surface to the LKM, pinned against its definitions. lkm/nm_engine.h
        // declares three functions that hookless/src/nomount.c defines, and the two are in
        // different build systems: the module's TUs only ever see the header, the engine's
        // only ever see the definition, and C has no name mangling -- so a signature that
        // drifts still compiles on every board, still links, and first shows up as an
        // argument read from the wrong register on a device. Nothing else compares them.
        // (ghost.c keeps its own weak/pointer declaration on purpose: it is vendored
        // byte-identical in-tree and needs the #ifdef MODULE shim for the arm64 GOT reloc.)
        const NM_ENGINE_H: &str = include_str!("../lkm/nm_engine.h");
        const ENGINE_C: &str = include_str!("../hookless/src/nomount.c");
        let squash = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
        let engine = squash(ENGINE_C);
        for decl in [
            "bool nm_uid_blocked(uid_t uid)",
            "bool nm_inode_hidden_from_caller(const struct inode *inode)",
            "void vfs_map_meta_override(const struct inode *inode, dev_t *dev, unsigned long *ino)",
        ] {
            assert!(
                squash(NM_ENGINE_H).contains(decl),
                "lkm/nm_engine.h no longer declares `{decl}`; the LKM calls it and only this \
                 header says what shape it has"
            );
            // `decl` followed by a BRACE, which is the definition. Matching the bare
            // string matched nothing useful: nomount.c carries its own forward
            // declaration one line above each of these, so a definition that drifted
            // still satisfied `contains` via the stale `;` line next to it. Verified by
            // planting a drift -- this arm did not fire until it was anchored.
            assert!(
                engine.contains(&format!("{decl} {{")),
                "hookless/src/nomount.c no longer DEFINES `{decl}` with that signature, but \
                 lkm/nm_engine.h still declares it that way. Both halves compile and link; \
                 the mismatch only appears as a wrong argument at runtime"
            );
        }
        // Every capability gate must name a version the engine has actually reached.
        // A constant above NOMOUNT_VERSION is a branch that can never be true: the
        // Suite would silently stop warning about something, and because all four of
        // these guard the OLD-engine arm, nothing on a current device would notice.
        // Cheap to check, and the four numbers were bare integers until they were
        // named, so a typo had nothing to catch it.
        const NOMOUNT_H: &str = include_str!("../hookless/src/nomount.h");
        let wire = NOMOUNT_H
            .lines()
            .find_map(|l| l.strip_prefix("#define NOMOUNT_VERSION"))
            .and_then(|v| v.trim().parse::<u32>().ok())
            .expect("nomount.h no longer defines NOMOUNT_VERSION");
        for (name, v) in [
            ("EROFS_DIR_SIZE", crate::nm::caps::EROFS_DIR_SIZE),
            ("PM_REGISTERED_EXEMPT", crate::nm::caps::PM_REGISTERED_EXEMPT),
            ("PUBLIC_ON_READ_PATHS", crate::nm::caps::PUBLIC_ON_READ_PATHS),
            ("GHOST_CONTROL_PLANE", crate::nm::caps::GHOST_CONTROL_PLANE),
            ("UID_SCOPE", crate::nm::caps::UID_SCOPE),
        ] {
            assert!(
                v <= wire,
                "nm::caps::{name} is {v}, above NOMOUNT_VERSION {wire}. Every one of these \
                 gates the OLD-engine arm, so a constant the engine has not reached makes \
                 that arm unreachable and the Suite silently stops warning -- and nothing \
                 on a current device would notice. They were bare integers until they were \
                 named; this is what catches a typo in one"
            );
        }
        let label = NOMOUNT_H
            .lines()
            .find_map(|l| l.strip_prefix("#define NM_MODULE_VERSION"))
            .map(|v| v.trim().trim_matches('"').to_string())
            .expect("nomount.h no longer defines NM_MODULE_VERSION");
        assert_eq!(
            label.split('.').nth(1).and_then(|m| m.parse::<u32>().ok()),
            Some(wire),
            "NM_MODULE_VERSION ({label}) and NOMOUNT_VERSION ({wire}) have drifted. The label is \
             what the kernel builders scrape to name a released kernel and what the engine \
             reports as its build string, and the comment that stated this invariant was \
             deleted by the comment strip - so only this test can catch it"
        );
        // sstrip is vendored from ELFkickers with exactly ONE local change (its README names
        // the commit): readphdrtable() seeks to e_phoff before reading the program header
        // table. Upstream has no such seek and works only because e_phoff happens to equal
        // sizeof(Elf64_Ehdr) for the linkers we use -- so re-extracting the tarball reverts
        // it in silence, and the first linker that places the phdr table elsewhere makes
        // sstrip compute the wrong truncation point on a binary we SHIP. The README says
        // "keep it when refreshing"; this is what makes that more than a note.
        //
        // Counted, not matched: commitchanges() carries upstream's identical seek on the
        // WRITE path, so `contains` passes even with the local change gone. Two is patched,
        // one is reverted.
        // release.yml extracts the CHANGELOG section for the tag it is publishing and now
        // REFUSES to publish without one, so a bump whose newest heading does not match
        // Cargo.toml fails the release AFTER tag.yml has pushed the tag -- and a published
        // version is immutable, so the only remedy is another bump. Caught here instead,
        // before the push. docs/changelog-latest.md is deliberately NOT compared: CI writes
        // it from these same notes after the release, so between a bump and its release the
        // two differ by design and gating them would fail every bump commit.
        const CHANGELOG: &str = include_str!("../CHANGELOG.md");
        let newest = CHANGELOG
            .lines()
            .find_map(|l| l.strip_prefix("## v"))
            .and_then(|l| l.split_whitespace().next())
            .expect("CHANGELOG.md has no `## v<version>` heading for release.yml to extract");
        assert_eq!(
            newest,
            env!("CARGO_PKG_VERSION"),
            "CHANGELOG.md's newest section is v{} but Cargo.toml says {}. Pushing this bumps \
             the tag, and release.yml then refuses to publish with no notes for it - with the \
             version number already burnt",
            newest,
            env!("CARGO_PKG_VERSION")
        );

        // .cargo/config.toml pins a linker per target; package.sh's ABI_TARGET map is the
        // list of ABIs actually shipped. Nothing reconciled the two, so adding an ABI to
        // packaging without a linker fails only on the first machine that cross-builds it.
        // Asserted in one direction on purpose: spare targets in config.toml cost nothing
        // because they apply only if you build them, but a shipped one with no linker does.
        const CARGO_CFG: &str = include_str!("../.cargo/config.toml");
        const PKG_SH: &str = include_str!("../scripts/package.sh");
        let mut shipped = 0;
        for raw in PKG_SH.lines() {
            let t = raw.trim();
            let Some((abi, target)) = t.strip_prefix('[').and_then(|r| r.split_once("]=")) else {
                continue;
            };
            if !target.contains("-linux-android") {
                continue;
            }
            shipped += 1;
            assert!(
                CARGO_CFG.contains(&format!("[target.{target}]")),
                "package.sh ships ABI {abi} as {target}, but .cargo/config.toml configures no \
                 linker for it"
            );
        }
        assert!(shipped > 0, "found no ABI_TARGET entry in package.sh, so this proved nothing");

        const SSTRIP_C: &str = include_str!("../userspace/tools/sstrip/sstrip.c");
        assert_eq!(
            SSTRIP_C.matches("fseek(thefile, ehdr.e_phoff, SEEK_SET)").count(),
            2,
            "sstrip.c must seek to e_phoff in BOTH readphdrtable() and commitchanges(). One \
             occurrence means a tarball refresh reverted the local read-path seek; see \
             userspace/tools/sstrip/README.md"
        );
        const ENGINE_MATRIX: &str = include_str!("../.github/workflows/hookless-matrix.yml");
        for ver in ["4.9", "4.14", "4.19", "5.4", "5.10", "5.15", "6.1", "6.6", "6.12", "6.18"] {
            assert!(
                ENGINE_MATRIX.contains(&format!("ver: '{ver}'")),
                "the engine compile matrix no longer covers {ver}. c223943 deleted this whole \
                 workflow and nothing compile-tested the shipped engine until it was restored; \
                 the LKM branch's gate builds a different engine version and does not cover it"
            );
        }
        // The bindhosts marker is a three-way string contract: service.sh writes it,
        // service.sh greps for it to decide whether the override is still ours, and
        // uninstall.sh greps for it to decide whether removing it is safe. A comment
        // strip already killed this line once; lowercase it in any one of the three and
        // uninstalling NoMount leaves mode_override.sh behind forever, pinning bindhosts
        // to mode 0.
        const UNINSTALL: &str = include_str!("../module/uninstall.sh");
        const BH_MARKER: &str = "NoMount Suite";
        assert!(
            SERVICE.contains(&format!("# Written by the {BH_MARKER}. Safe to delete.")),
            "service.sh no longer writes the bindhosts marker it and uninstall.sh both grep for"
        );
        for (what, src) in [("service.sh", SERVICE), ("uninstall.sh", UNINSTALL)] {
            assert!(
                src.contains(&format!("grep -q '{BH_MARKER}'")),
                "{what} stopped matching the bindhosts marker; uninstall then leaves \
                 /data/adb/bindhosts/mode_override.sh behind and bindhosts stays on mode 0"
            );
        }
        const README: &str = include_str!("../README.md");
        const BUG_TEMPLATE: &str = include_str!("../.github/ISSUE_TEMPLATE/bug_report.md");
        // The nav button's own label is the only name a reporter can actually tap. It was
        // renamed to Checks in the four-tab restructure while the pane heading, the hero
        // prose, the README and the issue template still said Diagnostics - so every
        // "go to X -> Export" instruction named a tab that is not on screen.
        assert!(
            PAGE.contains("<span>Checks</span>"),
            "the diagnostics tab's nav label changed; README and bug_report.md route \
             reporters to it by name and must be updated in the same commit"
        );
        for (what, doc) in [("README.md", README), ("bug_report.md", BUG_TEMPLATE)] {
            assert!(
                !doc.contains("Diagnostics*") && !doc.contains("**Diagnostics"),
                "{what} still routes the Export instructions to a Diagnostics tab; the nav \
                 button says Checks"
            );
        }
        const GATE_SWEEP: &str = include_str!("../scripts/gate-sweep.sh");
        for lit in [
            "^[[:space:]]*#[[:space:]]*(if|ifdef|ifndef|elif)([^A-Za-z0-9_].*)?$",
            r"IS_ENABLED\([[:space:]]*CONFIG_[A-Z0-9_]+",
            // The negative form, matched per token: `!IS_ENABLED(CONFIG_X)` is also matched by
            // the IS_ENABLED grep above, and a line-level match dropped the positive half of
            // `defined(CONFIG_A) && !defined(CONFIG_B)`.
            r"(ifndef[[:space:]]+|![[:space:]]*(defined[[:space:]]*\(?|IS_ENABLED\()[[:space:]]*)CONFIG_[A-Z0-9_]+",
        ] {
            assert!(
                ENGINE_MATRIX.contains(lit) && GATE_SWEEP.contains(lit),
                "the derived config gate is two independent copies - one inline in the \
                 matrix, one in scripts/gate-sweep.sh - and they have drifted on {lit:?}. \
                 Only the script is tested, so a drifted matrix copy is an untested gate, \
                 which is how the original one came to catch 2 of 8 gating forms"
            );
        }
        assert!(
            BUILD_YAML.lines().any(|l| l.trim() == "run: bash scripts/gate-sweep.sh"),
            "nothing runs the config-gate sweep any more, so its copy of the extractor is \
             unexercised and the matrix copy is pinned to an untested reference"
        );
        assert!(
            ENGINE_MATRIX.contains("workflow_dispatch") && ENGINE_MATRIX.contains("push:"),
            "the engine matrix is reachable only through another workflow again. That is how it \
             vanished: removing one `uses:` line silently took all ten versions with it"
        );
        assert!(
            BUILD_YAML.contains("git describe --tags --abbrev=0"),
            "the tag-push fallback is gone. A tag push reports an all-zero `before`, so without \
             a previous-tag fallback the sweep checks the tag commit alone and every other \
             commit in the release ships unswept"
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
        const SYNTHETIC: &str = include_str!("../scripts/webui-fixtures/clean.json");
        for k in keys {
            assert!(
                stub.contains(&format!("key = '{k}'")),
                "COMMANDS has {k:?} and the stub has no branch for it, so the page gets rc=1 \
                 for that command and renders its unreadable path instead of the captured one"
            );
            assert!(
                SYNTHETIC.contains(&format!("\"{k}\":")),
                "COMMANDS has {k:?} and scripts/webui-fixtures/clean.json does not answer it, \
                 so the README screenshots render that command as unreadable"
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
            "expected exactly two pinned `toolchain:` values (host test job, cross build job), \
             got {pins:?} - a job added or removed without pinning floats on whatever stable \
             was released that morning"
        );
        assert_eq!(
            pins[0], pins[1],
            "the two CI jobs pin different rustc versions ({pins:?}) - the binary that ships \
             would be built by a compiler the tests never ran under"
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

    const PAGE_HTML: &str = include_str!("../module/webroot/index.html");

    const PAGE_CSS: &str = include_str!("../module/webroot/css/app.css");
    const JS_PARTS: &[&str] = &[
        "js/00-core.js",
        "js/10-status.js",
        "js/20-chrome.js",
        "js/30-checks.js",
        "js/40-rules.js",
        "js/50-apps.js",
        "js/60-boot.js",
    ];
    const PAGE_JS: &[&str] = &[
        include_str!("../module/webroot/js/00-core.js"),
        include_str!("../module/webroot/js/10-status.js"),
        include_str!("../module/webroot/js/20-chrome.js"),
        include_str!("../module/webroot/js/30-checks.js"),
        include_str!("../module/webroot/js/40-rules.js"),
        include_str!("../module/webroot/js/50-apps.js"),
        include_str!("../module/webroot/js/60-boot.js"),
    ];
    const PAGE_PARTS: &[&str] = &[PAGE_HTML, PAGE_CSS];
    static PAGE: LazyLock<String> =
        LazyLock::new(|| PAGE_PARTS.concat() + &PAGE_JS.concat());

    const PAGE_CSS_SRC: &str = PAGE_CSS;

    fn page_css() -> &'static str {
        PAGE_CSS_SRC.split("</style>").next().unwrap_or("")
    }

    const HARNESS_SRC: &str = include_str!("../scripts/webui-harness.py");

    fn markup_without_comments() -> String {
        let mut out = String::with_capacity(PAGE_HTML.len());
        let mut rest = PAGE_HTML;
        while let Some(a) = rest.find("<!--") {
            out.push_str(&rest[..a]);
            match rest[a..].find("-->") {
                Some(b) => rest = &rest[a + b + 3..],
                None => {
                    rest = "";
                    break;
                }
            }
        }
        out.push_str(rest);
        out
    }

    #[test]
    fn the_csp_still_refuses_inline_script_and_inline_style() {
        let csp = PAGE_HTML
            .split(r#"http-equiv="Content-Security-Policy" content=""#)
            .nth(1)
            .and_then(|t| t.split('"').next())
            .expect("index.html must carry a CSP meta");
        for directive in ["default-src 'none'", "script-src 'self'", "style-src 'self'"] {
            assert!(
                csp.contains(directive),
                "the CSP lost {directive:?}: {csp}"
            );
        }
        assert!(
            !csp.contains("unsafe-inline") && !csp.contains("unsafe-eval"),
            "the CSP allows inline again, so a missed esc() executes instead of being \
             contained - the whole reason the script and the stylesheet are separate files: \
             {csp}"
        );

        let markup = markup_without_comments();
        assert!(
            !markup.contains("style=\""),
            "a style= attribute is back in index.html; style-src 'self' silently drops it, so \
             it renders unstyled. Add a class to css/app.css, or set it through the CSSOM"
        );
        assert!(
            !markup.contains("<style"),
            "an inline <style> block is back in index.html - it would not be applied"
        );
        for part in PAGE_JS {
            assert!(
                !part.contains("style=\""),
                "a js/ part builds markup carrying a style= attribute. Injected through \
                 innerHTML it is still parsed markup, so the CSP drops it and the element \
                 renders unstyled: use a class, or assign .style.* on the element instead"
            );
        }
        let inline_script = markup
            .match_indices("<script")
            .any(|(i, _)| !markup[i..].starts_with("<script src="));
        assert!(
            !inline_script,
            "an inline <script> is back in index.html; under script-src 'self' it will not run"
        );

        let mut sources: Vec<(&str, String)> = vec![("index.html", markup)];
        for (i, part) in PAGE_JS.iter().enumerate() {
            sources.push((JS_PARTS[i], (*part).to_string()));
        }
        for (who, text) in &sources {
            for (i, _) in text.match_indices(" on") {
                let tail = &text[i + 3..];
                let name: String =
                    tail.chars().take_while(|c| c.is_ascii_lowercase()).collect();
                if !name.is_empty() && tail[name.len()..].starts_with("=\"") {
                    panic!(
                        "{who} carries an inline on{name}= handler. script-src 'self' blocks it \
                         exactly as it blocks an inline <script>, and markup a js part builds \
                         and assigns to innerHTML is still parsed markup: the control renders \
                         and does nothing. Give it data-act=\"<name>\" and add <name> to ACTIONS"
                    );
                }
            }
        }
    }

    #[test]
    fn every_utility_class_the_page_uses_has_a_rule() {
        let mut used: Vec<String> = Vec::new();
        let mut collect = |text: &str| {
            for (i, _) in text.match_indices("u-") {
                let boundary = i == 0
                    || matches!(
                        text.as_bytes()[i - 1],
                        b' ' | b'"' | b'\'' | b'\n' | b'\t'
                    );
                if !boundary {
                    continue;
                }
                let name: String = text[i..]
                    .chars()
                    .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '-')
                    .collect();
                let name = name.trim_end_matches('-').to_string();
                if name.len() > 2 && !used.contains(&name) {
                    used.push(name);
                }
            }
        };
        collect(PAGE_HTML);
        for part in PAGE_JS {
            collect(part);
        }
        assert!(!used.is_empty(), "the page names no utility classes at all");

        for name in &used {
            assert!(
                PAGE_CSS.contains(&format!(".{name} ")) || PAGE_CSS.contains(&format!(".{name}{{")),
                "the page uses the class {name:?}, which css/app.css does not define. The \
                 element renders unstyled and nothing else reports it - if it is a hide \
                 class, whatever it was meant to hide is on screen right now"
            );
        }
    }

    #[test]
    fn every_data_act_in_the_markup_resolves_to_an_action() {
        let boot = PAGE_JS
            .last()
            .expect("there must be a boot part");
        let table = boot
            .split("const ACTIONS = {")
            .nth(1)
            .and_then(|t| t.split("\n  };").next())
            .expect("60-boot.js must define ACTIONS");
        let defined: Vec<&str> = table
            .lines()
            .filter_map(|l| l.strip_prefix("    "))
            .filter_map(|l| l.split(':').next())
            .filter(|k| !k.is_empty() && k.chars().all(|c| c.is_alphanumeric() || c == '_'))
            .collect();

        const ATTRS: [&str; 6] = ["data-act=\"", "data-act-input=\"", "data-act-key=\"",
                                  "data-act-down=\"", "data-act-focus=\"",
                                  "data-act-blur=\""];
        let names = |text: &'static str| {
            let mut out: Vec<&str> = Vec::new();
            for attr in ATTRS {
                for part in text.split(attr).skip(1) {
                    if let Some(v) = part.split('"').next() {
                        out.push(v);
                    }
                }
            }
            out
        };

        // index.html is served straight to the page, so every action it names has to be
        // in the global table. Markup a js part builds may instead be handled by one of
        // the container delegates (#wobody, #blocked, #usList), which match the value
        // themselves, so those names are checked the other way only.
        let in_html = names(PAGE_HTML);
        assert!(!in_html.is_empty(), "index.html names no actions at all");
        for name in &in_html {
            assert!(
                defined.contains(name),
                "index.html asks for the action {name:?}, which ACTIONS does not define, so \
                 that control does nothing when tapped"
            );
        }

        let mut anywhere = in_html;
        for part in PAGE_JS {
            anywhere.extend(names(part));
        }
        for name in &defined {
            assert!(
                anywhere.contains(name),
                "ACTIONS defines {name:?} and no control uses it - either the markup lost a \
                 data-act or this entry is dead"
            );
        }
    }

    #[test]
    fn every_webui_part_is_listed_by_index_html_and_every_listing_exists() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/module/webroot/js");
        let mut on_disk: Vec<String> = std::fs::read_dir(dir)
            .expect("module/webroot/js must exist")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".js"))
            .collect();
        on_disk.sort();
        assert!(!on_disk.is_empty(), "no js parts found - the WebUI would not run");

        let listed: Vec<String> = PAGE_HTML
            .split("<script src=\"js/")
            .skip(1)
            .filter_map(|t| t.split('"').next())
            .map(str::to_owned)
            .collect();

        for name in &on_disk {
            assert!(
                listed.contains(name),
                "module/webroot/js/{name} is in the zip but index.html never loads it, so it \
                 ships dead - add the <script src> or delete the file"
            );
        }
        for name in &listed {
            assert!(
                on_disk.contains(name),
                "index.html loads js/{name}, which does not exist - the pane it serves will \
                 be inert with nothing in the log to say why"
            );
        }
        assert_eq!(
            PAGE_JS.len(),
            on_disk.len(),
            "PAGE_JS does not include every part in module/webroot/js, so the assertions \
             below cover less of the WebUI than they appear to"
        );
    }

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
    fn the_diagnostics_never_paint_a_warm_colour() {
        let css = page_css();
        let controls = ["button.act.danger", ".bx:hover", ".bx.save:hover"];
        for (label, needle) in [
            ("amber", "251,191,36"),
            ("red", "248,113,122"),
            ("amber", "#fbbf24"),
            ("red", "#f8717a"),
            ("brown", "#a46a00"),
            ("red", "#d23a44"),
            ("amber", "#d9a441"),
            ("amber", "#ffe6a8"),
            ("brown", "#6b4d00"),
            ("red", "210,58,68"),
            ("red", "#ff6b6b"),
            ("red", "255,90,90"),
        ] {
            for rule in css.split('}').filter(|l| l.contains(needle)) {
                assert!(
                    controls.iter().any(|c| rule.contains(c)),
                    "a {label} literal is back outside a destructive control: {rule}"
                );
            }
        }
        for (var, decl) in [("--warn", "--warn:    var(--info)"), ("--bad", "--bad:     var(--info)")] {
            assert_eq!(
                css.matches(decl).count(),
                2,
                "{var} must resolve to --info in both themes, or a call site this test cannot \
                 enumerate repaints amber"
            );
        }
        assert!(
            !PAGE.contains("needs attention") && !PAGE.contains("things need"),
            "the findings list went back to grading the user"
        );
    }

    #[test]
    fn the_header_states_both_versions_and_can_say_an_update_is_staged() {
        for id in ["\"ver\"", "\"hdreng\"", "\"vstage\""] {
            assert!(
                PAGE.contains(&format!("id={id}")),
                "the header lost {id}; the version line is the only place the Suite and the \
                 engine version are visible without scrolling to the footer"
            );
            assert!(
                PAGE.contains(&format!("$({id})")),
                "{id} is in the markup but nothing writes to it"
            );
        }
        // The line is written to fit a phone at 363 dp; it ellipsises if it grows.
        let staged = PAGE.split("id=\"vstage\"").nth(1).unwrap_or("");
        let text = staged.split('>').nth(1).unwrap_or("").split('<').next().unwrap_or("").trim();
        assert!(
            !text.is_empty() && text.chars().count() <= 12,
            "the staged marker got longer and will be cut off on a phone: {text:?}"
        );
    }

    #[test]
    fn the_hero_and_the_report_count_the_same_findings() {
        let body = PAGE.split("function checkAttention").nth(1).unwrap_or("");
        let head = body.split("}").next().unwrap_or("");
        assert!(
            head.contains("(s.open_failures || 0) + (s.warn || 0)") && !head.contains("s.reboot"),
            "open_failures already includes reboot, so adding it again counts a \
             pending-reboot check twice on the Status hero: {head}"
        );
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
            // Every reading is marked '?' when it could not be taken, and the run ends
            // with a trailer: the exit status of a list of `echo`s is the last echo's, so
            // a probe where nothing resolved still exited 0 and its empty `root_nm` parsed
            // as zero mounts. Those three pieces are what stop that, so pin them here --
            // and pin PATH, because an exec with none is how it happened.
            r#"export PATH=/system/bin:/system/xbin:/vendor/bin; "#,
            r#"case "$n" in ""|*[!0-9]*) n="?";; esac; echo "root_nm=$n"; "#,
            r#"q fp "getprop ro.build.fingerprint"; "#,
            r#"q se "getenforce"; "#,
            r#"echo "done=1""#,
        ] {
            assert!(PAGE.contains(frag), "index.html's stealth probe lost: {frag:?}");
            assert!(
                HARNESS_SRC.contains(frag),
                "webui-harness.py's `stealth` command lost {frag:?}, so the harness feeds the \
                 page a fixture the page's own command would never have produced"
            );
        }
        let mounts = r#"mnt=$(NM_P="/adb/modules/$id" awk \'$4==ENVIRON["NM_P"] || index($4, ENVIRON["NM_P"] "/")==1 {n++} END{print n+0}\' /proc/self/mountinfo 2>/dev/null); "#;
        assert!(
            PAGE.contains(mounts) && HARNESS_SRC.contains(mounts),
            "the page's per-module mount count and webui-harness.py's `modules` command have \
             drifted, so the harness replays counts the page's own command would not produce"
        );
        // The trailer the page refuses a module list without: a harness command that lost
        // it rendered Modules as "could not be read" on every fixture, fresh or not.
        let trailer = r#"echo "$id|$st|$mnt"; done; echo "done=1""#;
        assert!(
            PAGE.contains(trailer) && HARNESS_SRC.contains(trailer),
            "the `modules` command lost its done=1 trailer on one side"
        );
        let absorbed = "[ -e /data/adb/nomount/absorbed.list ] || exit 0; ";
        assert!(
            PAGE.contains(absorbed) && HARNESS_SRC.contains(absorbed),
            "the page's absorbed-list probe and the harness's `absorbedlist` have drifted"
        );
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
        let base = test_base("replace-expand");
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
        expand_replacement("m", &stock, &module, &module.join(".replace"), 0, &EngineEdits::default(), &mut out);
        let mut got: Vec<String> =
            out.iter().map(|e| e.target.strip_prefix(&stock).unwrap().display().to_string()).collect();
        got.sort();

        assert_eq!(got, vec!["b.xml".to_string(), "extra".to_string(), "sub/c.xml".to_string()]);
        assert!(out.iter().all(|e| e.kind == PlanKind::Whiteout));
        assert!(out.iter().all(|e| e.target != stock));

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn replace_expands_against_the_stock_listing_not_the_engine_edited_one() {
        let base = test_base("replace-stock-view");
        let stock = base.join("stock");
        let module = base.join("module");
        fs::create_dir_all(stock.join("vdir")).unwrap();
        fs::write(stock.join("a.xml"), b"stock").unwrap();
        fs::create_dir_all(&module).unwrap();

        let list = format!(
            "{s}/b.xml (whiteout)\n{s}/vdir (virtual dir)\n{s}/c.xml (whiteout) [UID: 10123]\n",
            s = stock.display()
        );
        let mut out = Vec::new();
        expand_replacement(
            "m",
            &stock,
            &module,
            &module.join(".replace"),
            0,
            &EngineEdits::from_list(&list),
            &mut out,
        );
        let mut got: Vec<String> =
            out.iter().map(|e| e.target.strip_prefix(&stock).unwrap().display().to_string()).collect();
        got.sort();
        assert_eq!(
            got,
            vec!["a.xml".to_string(), "b.xml".to_string()],
            "b.xml is hidden by the previous pass and must stay planned, or reload prunes it; \
             vdir exists only because the engine made it"
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn replace_does_not_descend_where_the_module_ships_a_file() {
        let base = test_base("replace-file-over-dir");
        let stock = base.join("stock");
        let module = base.join("module");
        fs::create_dir_all(stock.join("thing")).unwrap();
        fs::write(stock.join("thing/inner.xml"), b"stock").unwrap();
        fs::create_dir_all(&module).unwrap();
        fs::write(module.join("thing"), b"mine").unwrap();

        let mut out = Vec::new();
        expand_replacement("m", &stock, &module, &module.join(".replace"), 0, &EngineEdits::default(), &mut out);
        assert!(out.is_empty(), "expected no whiteouts, got {} entries", out.len());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn replace_on_a_directory_the_rom_does_not_have_is_a_no_op() {
        let base = test_base("replace-absent");
        let module = base.join("module");
        fs::create_dir_all(&module).unwrap();
        fs::write(module.join("mine.xml"), b"mine").unwrap();

        let mut out = Vec::new();
        expand_replacement("m", &base.join("no-such-stock"), &module, &module.join(".replace"), 0, &EngineEdits::default(), &mut out);
        assert!(out.is_empty());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn absorb_refuses_the_entries_the_planner_refuses() {
        let d = tempfile::tempdir().unwrap();

        let plain = d.path().join("libfoo.so");
        std::fs::write(&plain, b"x").unwrap();
        assert!(absorb_refusal(&plain).is_none(), "an ordinary file must still be absorbed");

        let repl = d.path().join(".replace");
        std::fs::write(&repl, b"").unwrap();
        assert!(absorb_refusal(&repl).is_some(), ".replace would be served as a literal file");

        // The untrusted set is "under /data but not /data/adb", plus shared storage - those are
        // the places a non-root process can write. A tempdir is none of them, so the predicate
        // is exercised directly rather than through a symlink a test cannot plant under /data.
        assert!(resolved_source_is_untrusted(Path::new("/data/local/tmp/evil.so")));
        assert!(resolved_source_is_untrusted(Path::new("/data/media/0/evil.so")));
        assert!(!resolved_source_is_untrusted(Path::new("/data/adb/modules/m/lib.so")));

        let dirlink = d.path().join("dirlink");
        std::os::unix::fs::symlink(d.path(), &dirlink).unwrap();
        assert!(absorb_refusal(&dirlink).is_some(), "a symlink to a directory must be refused");

        assert!(absorb_refusal(&d.path().join("nope")).is_some(), "a missing source is refused");

        let fifo = d.path().join("pipe");
        let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
        assert!(absorb_refusal(&fifo).is_some(), "a FIFO would be served as a regular file");
    }

    #[test]
    fn replace_expansion_stops_at_the_depth_guard() {
        let base = test_base("replace-depth");
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
        expand_replacement("m", &stock, &module, &module.join(".replace"), 0, &EngineEdits::default(), &mut out);
        assert!(out.iter().all(|e| !e.target.ends_with("deep.xml")));

        let _ = fs::remove_dir_all(&base);
    }

    fn test_base(tag: &str) -> PathBuf {
        let candidates = [
            std::env::var_os("HOME").map(PathBuf::from),
            Some(PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/target"))),
        ];
        let base = candidates
            .into_iter()
            .flatten()
            .map(|d| d.join(format!(".nomount-test-{tag}")))
            .find(|b| can_whiteout(&b.join("probe")).is_ok())
            .unwrap_or_else(|| {
                panic!(
                    "neither HOME nor {}/target is a directory can_whiteout accepts, so the \
                     .replace tests have nowhere to build a stock tree - refusing to pass \
                     without asserting anything",
                    env!("CARGO_MANIFEST_DIR")
                )
            });
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        base
    }

    #[test]
    fn only_a_zero_zero_char_device_is_a_whiteout_marker() {
        use std::os::unix::fs::MetadataExt;
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("plain");
        fs::write(&f, b"x").unwrap();
        let plain = fs::symlink_metadata(&f).unwrap();
        assert!(!is_whiteout_marker(&plain.file_type(), &f));
        assert!(!is_whiteout_node(&plain.file_type(), 0), "a regular file is never a marker");

        let null = fs::symlink_metadata("/dev/null").expect("/dev/null must exist");
        assert!(null.file_type().is_char_device(), "/dev/null should be a char device");
        assert_ne!(null.rdev(), 0);
        assert!(
            !is_whiteout_marker(&null.file_type(), Path::new("/dev/null")),
            "/dev/null has a non-zero rdev and is not a deletion marker"
        );
        assert!(
            is_whiteout_node(&null.file_type(), 0),
            "a character device numbered 0:0 is the deletion marker"
        );

        let node = d.path().join("gone");
        let c = std::ffi::CString::new(node.as_os_str().as_encoded_bytes()).unwrap();
        if unsafe { libc::mknod(c.as_ptr(), libc::S_IFCHR | 0o600, 0) } == 0 {
            let md = fs::symlink_metadata(&node).unwrap();
            assert!(is_whiteout_marker(&md.file_type(), &node), "a real 0:0 node was not recognised");
        }
    }

    #[test]
    fn an_unlisted_module_keeps_its_rules_and_their_recorded_identity() {
        let unlisted = [PathBuf::from("/data/adb/modules/M")];
        let ours = LiveRule::Inject(PathBuf::from("/data/adb/modules/M/system/etc/x"));
        let other = LiveRule::Inject(PathBuf::from("/data/adb/modules/N/system/etc/x"));
        assert_eq!(held_for_unlisted(Some(&ours), &unlisted), Some(true));
        assert_eq!(held_for_unlisted(Some(&other), &unlisted), None, "N was listed: prunable");
        assert_eq!(held_for_unlisted(Some(&LiveRule::Whiteout), &unlisted), Some(false));
        assert_eq!(held_for_unlisted(Some(&ours), &[]), None);
        let sibling = LiveRule::Inject(PathBuf::from("/data/adb/modules/M2/system/etc/x"));
        assert_eq!(held_for_unlisted(Some(&sibling), &unlisted), None, "a prefix is not a module");
    }

    #[test]
    fn whiteout_allowed_on_my_partitions() {
        assert!(can_whiteout(Path::new("/my_stock/app/OplusOperationManual")).is_ok());
        assert!(can_whiteout(Path::new("/my_product/app/Foo")).is_ok());
        assert!(can_whiteout(Path::new("/product/app/AIMemory")).is_ok());
        assert!(can_whiteout(Path::new("/system/priv-app/Foo")).is_ok());
    }

    #[test]
    fn whiteout_refuses_a_partition_nested_in_system_or_vendor() {
        for p in [
            "/system/system_ext/lib64/libc++.so",
            "/system/product/lib64/libx.so",
            "/vendor/odm/lib64/libfoo.so",
        ] {
            assert!(can_whiteout(Path::new(p)).is_err(), "{p} must be refused");
        }
        assert!(can_whiteout(Path::new("/system/system_ext/app/Foo")).is_ok());
    }

    #[test]
    fn a_bare_nested_root_is_refused_unless_both_it_and_the_partition_are_real_dirs() {
        for p in ["/system/system_ext", "/system/product", "/system/vendor", "/vendor/odm"] {
            let p = Path::new(p);
            assert!(can_whiteout_with(p, &|_| false).is_err(), "{p:?}: no separate partition");
            assert!(
                can_whiteout_with(p, &|q| q != p).is_err(),
                "{p:?}: a symlink onto the partition"
            );
            assert!(
                can_whiteout_with(p, &|q| q == p).is_err(),
                "{p:?}: the partition lives here, the top-level name is the link"
            );
            assert!(
                can_whiteout_with(p, &|_| true).is_ok(),
                "{p:?}: a stub beside a real partition is an ordinary debloat target"
            );
        }
        assert!(can_whiteout_with(Path::new("/system/system_ext/app/Foo"), &|_| false).is_ok());
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
    fn whiteout_refuses_what_init_the_linker_and_zygote_need() {
        for p in [
            "/system/bin",
            "/system/bin/",
            "/system/bin/.",
            "/system/lib",
            "/system/lib64",
            "/system/framework",
            "/system/etc",
            "/system/apex",
            "/system/bin/linker",
            "/system/bin/linker64",
            "/system/bin/linker_hwasan64",
            "/system/bin/app_process",
            "/system/bin/app_process32",
            "/system/bin/app_process64",
            "/system_ext/lib64",
            "/system_ext/framework",
            "/vendor/bin",
            "/vendor/lib",
            "/vendor/lib64",
            "/vendor/etc",
            "/odm/lib64",
            "/product/framework",
            // The dlkm partitions: their whole point is lib/modules, and a .ko made
            // absent is a dead boot, not a debloat.
            "/vendor_dlkm/lib",
            "/vendor_dlkm/lib/modules",
            "/vendor_dlkm/lib/modules/zram.ko",
            "/vendor_dlkm/lib/modules/modules.load",
            "/system_dlkm/lib/modules/foo.ko",
            "/odm_dlkm/lib/modules/foo.ko",
        ] {
            assert!(can_whiteout(Path::new(p)).is_err(), "{p} must be refused");
            assert!(crate::whiteout::validate(p).is_err(), "{p}: whiteout add must refuse it too");
        }
        for p in [
            "/system/app/Foo",
            "/system/priv-app/Foo",
            "/product/app/Foo",
            "/product/priv-app/Foo",
            "/product/overlay/Foo.apk",
            "/system/bin/install-recovery.sh",
            "/system/bin/app_process_xposed64",
            "/system/etc/hosts",
            "/system/etc/permissions",
            "/system/framework/foo.jar",
            "/vendor/etc/foo.conf",
            "/my_product/etc",
        ] {
            assert!(can_whiteout(Path::new(p)).is_ok(), "{p} is an ordinary debloat target");
        }
    }

    #[test]
    fn a_durable_whiteout_yields_to_every_kind_the_plan_serves() {
        let plan = vec![
            pe("m", "/product/overlay/Foo.apk", PlanKind::Inject),
            pe("m", "/my_product/app/Foo/Foo.apk", PlanKind::Bind),
            pe("m", "/system/app/Gone", PlanKind::Whiteout),
        ];
        let durable: Vec<PathBuf> = [
            "/product/overlay/Foo.apk",
            "/my_product/app/Foo/Foo.apk",
            "/system/app/Gone",
            "/system/etc/tell.conf",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        assert_eq!(
            durable_not_planned(durable, &plan),
            vec![PathBuf::from("/system/etc/tell.conf")],
            "mount and reload must drop the same rows, binds included"
        );
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
        let (live, _) = parse_live_rules(
            "/system/etc/d -> /m/d\n\
             /system/etc/d/a/b -> /m/d/a/b\n\
             /system/etc/d/a -> /m/d/a\n\
             /system/etc/z -> /m/z\n",
            &HashSet::new(),
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
            "/data_mirror/data_ce/null/0/com.some.app/files/foo.conf",
            "/data_mirror/data_de/null/0/com.some.app/x",
            "/data_mirror/cur_profiles/0/com.some.app/primary.prof",
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

    /// A scoped rule on a target we absorbed is one the Suite wrote itself, under
    /// apkscope. Counting it as another writer's made reload report the Suite's own
    /// rule back to the operator as untouchable.
    #[test]
    fn our_own_scoped_absorbed_rule_is_not_foreign() {
        let line = "/data/app/x/base.apk -> /data/adb/rvhc/m.apk [SCOPE: 0-4294967295] [DENY: 10397]\n";
        let (_, foreign) = parse_live_rules(line, &HashSet::new());
        assert_eq!(foreign, 1, "with no absorbed record it IS another writer's");

        let ours: HashSet<PathBuf> = [PathBuf::from("/data/app/x/base.apk")].into_iter().collect();
        let (map, foreign) = parse_live_rules(line, &ours);
        assert_eq!(foreign, 0, "a scope on a target we absorbed is ours");
        assert!(
            !map.contains_key(&(PathBuf::from("/data/app/x/base.apk"), 0)),
            "it still stays out of the map: the prune pass has no key for a scoped delete"
        );
    }

    #[test]
    fn live_rules_are_keyed_including_uid() {
        let (m, _) = parse_live_rules(
            "/a -> /b\n/a -> /c [UID: 1000]\n/d (whiteout)\n/e (virtual dir)\n",
            &HashSet::new(),
        );
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
