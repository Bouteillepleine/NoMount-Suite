//! Convert other people's bind mounts into hookless injections.
//!
//! The Suite is mountless, but a third-party module can still run its own
//! `mount --bind` from a boot script, and every such mount is visible in
//! `/proc/*/mountinfo` to any app — which is the entire signal the zero-mount
//! posture exists to deny. Today that only holds because module authors
//! cooperate (OnePlus_Dialer_Universal literally checks for meta-nomount and
//! stands down). A module that does not know about NoMount punches straight
//! through it.
//!
//! Absorption removes the dependency on cooperation: after module scripts have
//! run, every mount whose source lives under `/data/adb` and whose target is on
//! a read-only ROM partition is re-served as a VFS injection and then unmounted.
//! The content stays available the whole time — the injection is added *first*,
//! and the still-present mount simply shadows it until it goes away.
//!
//! This is only possible because injection is mountless: no overlay- or
//! bind-based metamodule can absorb a mount, because it would have to create one.

use std::collections::HashMap;
use std::ffi::CString;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::nm::Nm;

const MOUNTINFO: &str = "/proc/self/mountinfo";
/// Only sources under here are module content we may take over.
const MODULE_ROOT: &str = "/data/adb";
/// Opt-out list: module ids or target path prefixes to leave mounted.
pub const SKIP_FILE: &str = "/data/adb/nomount/absorb-skip";

/// Entries to leave alone: one per line, either a module id (matched against the
/// bind's source) or an absolute target prefix. Blank lines and `#` ignored.
fn skip_list() -> Vec<String> {
    std::fs::read_to_string(SKIP_FILE)
        .map(|s| {
            s.lines()
                .map(|l| l.trim())
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// True if this mount is explicitly excluded.
pub(crate) fn is_skipped(src: &Path, target: &Path, skips: &[String]) -> bool {
    let (s, t) = (src.to_string_lossy(), target.to_string_lossy());
    skips.iter().any(|k| {
        if k.starts_with('/') {
            t.starts_with(k.as_str())
        } else {
            // module id: match the /data/adb/modules/<id>/ path component
            s.contains(&format!("/modules/{k}/"))
        }
    })
}

/// One parsed `/proc/self/mountinfo` row (the fields we need).
#[derive(Debug, Clone)]
pub(crate) struct MountRow {
    pub dev: String,
    /// Path of this mount's root *within its filesystem*, not an absolute path.
    pub root: String,
    pub target: PathBuf,
}

/// Parse mountinfo. Format: `id parent maj:min root mountpoint opts... - fstype source super`.
pub(crate) fn parse_mountinfo(body: &str) -> Vec<MountRow> {
    let mut out = Vec::new();
    for line in body.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f.len() < 5 {
            continue;
        }
        out.push(MountRow {
            dev: f[2].to_string(),
            root: unescape(f[3]),
            target: PathBuf::from(unescape(f[4])),
        });
    }
    out
}

/// mountinfo octal-escapes space, tab, newline and backslash.
fn unescape(s: &str) -> String {
    if !s.contains('\\') {
        return s.to_string();
    }
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() {
            if let Some(v) = std::str::from_utf8(&b[i + 1..i + 4])
                .ok()
                .and_then(|o| u8::from_str_radix(o, 8).ok())
            {
                out.push(v as char);
                i += 4;
                continue;
            }
        }
        out.push(b[i] as char);
        i += 1;
    }
    out
}

/// Map each filesystem (maj:min) to where its ROOT is mounted, so a bind's
/// fs-relative `root` field can be turned back into an absolute path. A bind of
/// `/data/adb/x` reports `root=/adb/x` against the device `/data` is mounted on,
/// so resolving it needs this table — a plain prefix match on `root` is wrong.
pub(crate) fn fs_roots(rows: &[MountRow]) -> HashMap<String, PathBuf> {
    let mut m: HashMap<String, PathBuf> = HashMap::new();
    for r in rows.iter().filter(|r| r.root == "/") {
        m.entry(r.dev.clone())
            .and_modify(|cur| {
                // Shortest mountpoint wins: that is the real fs root, not a
                // later bind of the whole filesystem somewhere else.
                if r.target.as_os_str().len() < cur.as_os_str().len() {
                    *cur = r.target.clone();
                }
            })
            .or_insert_with(|| r.target.clone());
    }
    m
}

/// Absolute source path backing a bind row, if it can be resolved.
pub(crate) fn source_of(row: &MountRow, roots: &HashMap<String, PathBuf>) -> Option<PathBuf> {
    if row.root == "/" {
        return None; // a whole-filesystem mount, not a bind of a subtree
    }
    let base = roots.get(&row.dev)?;
    let rel = row.root.trim_start_matches('/');
    Some(if base == Path::new("/") {
        PathBuf::from("/").join(rel)
    } else {
        base.join(rel)
    })
}

/// Is this a mount we should take over? Module-backed, and landing somewhere we
/// actually serve — never a target under /data (the module's own scratch space).
pub(crate) fn is_absorbable(src: &Path, target: &Path) -> bool {
    src.starts_with(MODULE_ROOT)
        && !target.starts_with("/data")
        && target.components().count() > 1
}

/// A mount we intend to convert.
pub struct Candidate {
    pub target: PathBuf,
    pub source: PathBuf,
}

/// Everything currently absorbable, deepest target first so nested mounts come
/// off in the right order.
/// Absorbable mounts INCLUDING ones the skip list excludes. Used by `doctor` to
/// report what is deliberately being left mounted.
pub fn candidates_all() -> Result<Vec<Candidate>> {
    let body = std::fs::read_to_string(MOUNTINFO).context("read mountinfo")?;
    let rows = parse_mountinfo(&body);
    let roots = fs_roots(&rows);
    Ok(rows
        .iter()
        .filter_map(|r| {
            let src = source_of(r, &roots)?;
            is_absorbable(&src, &r.target).then(|| Candidate {
                target: r.target.clone(),
                source: src,
            })
        })
        .collect())
}

pub fn candidates() -> Result<Vec<Candidate>> {
    let body = std::fs::read_to_string(MOUNTINFO).context("read mountinfo")?;
    let rows = parse_mountinfo(&body);
    let roots = fs_roots(&rows);
    let skips = skip_list();
    let mut out: Vec<Candidate> = rows
        .iter()
        .filter_map(|r| {
            let src = source_of(r, &roots)?;
            if !is_absorbable(&src, &r.target) {
                return None;
            }
            if is_skipped(&src, &r.target, &skips) {
                println!("skipping {} (listed in {SKIP_FILE})", r.target.display());
                return None;
            }
            Some(Candidate { target: r.target.clone(), source: src })
        })
        .collect();
    out.sort_by_key(|c| std::cmp::Reverse(c.target.components().count()));
    Ok(out)
}

fn umount_detach(p: &Path) -> bool {
    let Ok(c) = CString::new(p.to_string_lossy().as_bytes()) else {
        return false;
    };
    unsafe { libc::umount2(c.as_ptr(), libc::MNT_DETACH) == 0 }
}

/// Inject `source` at `target`. A directory bind is expanded to one rule per
/// file rather than a single directory rule: a directory rule REPLACES the stock
/// directory, hiding every entry the module did not ship, which is the same
/// whole-partition masking that bootloops zygote.
fn inject(nm: &Nm, source: &Path, target: &Path, out: &mut u32) -> Result<()> {
    if source.is_dir() {
        for e in std::fs::read_dir(source)?.flatten() {
            let ft = e.file_type()?;
            let child_src = e.path();
            let child_tgt = target.join(e.file_name());
            if ft.is_dir() {
                inject(nm, &child_src, &child_tgt, out)?;
            } else {
                nm.add(&child_tgt, &child_src)?;
                *out += 1;
            }
        }
    } else {
        nm.add(target, source)?;
        *out += 1;
    }
    Ok(())
}

/// `nomount absorb [--dry-run]`.
pub fn run_absorb(dry_run: bool, include_dirs: bool) -> Result<()> {
    let nm = Nm::new();
    nm.version()
        .context("hookless NoMount engine not responding")?;

    let cands = candidates()?;
    if cands.is_empty() {
        println!("nomount absorb: no module-backed mounts to absorb (posture already clean)");
        return Ok(());
    }

    let (mut rules, mut done, mut failed, mut skipped_dirs) = (0u32, 0u32, 0u32, 0u32);
    for c in &cands {
        // Apply the same directory rule the real run uses, so a dry run can never
        // promise an action the real run would decline.
        let is_dir_bind = c.source.is_dir();
        if dry_run {
            if is_dir_bind && !include_dirs {
                println!(
                    "would SKIP directory bind {} <- {} (needs --include-dirs)",
                    c.target.display(), c.source.display()
                );
                skipped_dirs += 1;
            } else {
                println!("would absorb {} <- {}", c.target.display(), c.source.display());
            }
            continue;
        }
        // A DIRECTORY bind becomes one rule per file -- a static snapshot of the
        // listing as it is right now. Anything the owning module adds to that
        // directory later would simply never appear, and unlike a file bind we
        // cannot tell whether it intends to. Opt-in only.
        if is_dir_bind && !include_dirs {
            println!(
                "skipping directory bind {} <- {} (use --include-dirs; injection would \
                 snapshot the listing and miss files added later)",
                c.target.display(), c.source.display()
            );
            skipped_dirs += 1;
            continue;
        }
        // Unmount FIRST, then inject. Inject-first looks safer (the mount shadows
        // the injection, so content is never absent) but is actually fatal: adding
        // a rule d_drops the cached dentry for that name, and a mount hangs off a
        // specific (vfsmount, dentry) pair. Dropping it detaches the mount from
        // path resolution, so umount2() then returns EINVAL -- the path is no
        // longer a mountpoint -- and the entry is stranded in mountinfo until
        // reboot while the content silently reverts to the file underneath.
        // Verified on-device against LSPosed's dex2oat bind.
        //
        // Unmounting first costs a brief window where the stock file shows
        // through. That is strictly better than an unremovable mount, and it also
        // means nm_alloc_rule mirrors metadata from the REAL stock file rather
        // than through the bind -- which is what makes absorption remove the
        // bind's dev/ino/mtime tell instead of preserving it.
        if !umount_detach(&c.target) {
            eprintln!(
                "nomount: cannot unmount {} - leaving it alone (injecting anyway would \
                 strand it in mountinfo)",
                c.target.display()
            );
            failed += 1;
            continue;
        }
        match inject(&nm, &c.source, &c.target, &mut rules) {
            Ok(()) => done += 1,
            Err(e) => {
                eprintln!("nomount: absorb of {} failed: {e:#}", c.target.display());
                failed += 1;
            }
        }
    }

    if dry_run {
        println!(
            "nomount absorb: {} mount(s) would be absorbed, {skipped_dirs} directory bind(s) skipped (dry run)",
            cands.len() as u32 - skipped_dirs
        );
    } else {
        let dirs = if skipped_dirs > 0 {
            format!(", {skipped_dirs} directory bind(s) skipped")
        } else {
            String::new()
        };
        println!("nomount absorb: {done} mount(s) absorbed as {rules} rule(s), {failed} failed{dirs}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The real row this was derived from, captured on-device from a file bind.
    const SAMPLE: &str = "\
205 1 254:78 / /data rw,nosuid,nodev,noatime shared:2 - f2fs /dev/block/dm-78 rw
10222 205 254:78 /local/tmp/bt/src/f /data/local/tmp/bt/dst/f rw,noatime shared:60 - f2fs /dev/block/dm-78 rw
900 205 254:78 /adb/modules/foo/system/bin/x /system/bin/x rw,noatime shared:9 - f2fs /dev/block/dm-78 rw
35 1 0:35 / /product ro,noatime - erofs /dev/block/dm-25 ro";

    #[test]
    fn resolves_a_bind_source_via_its_filesystem_root() {
        let rows = parse_mountinfo(SAMPLE);
        let roots = fs_roots(&rows);
        // field 4 is fs-relative: /adb/... must resolve against /data, not /
        let m = rows.iter().find(|r| r.target == Path::new("/system/bin/x")).unwrap();
        assert_eq!(
            source_of(m, &roots).unwrap(),
            PathBuf::from("/data/adb/modules/foo/system/bin/x")
        );
    }

    #[test]
    fn only_module_backed_rom_targets_are_absorbable() {
        let rows = parse_mountinfo(SAMPLE);
        let roots = fs_roots(&rows);
        for r in &rows {
            let Some(src) = source_of(r, &roots) else { continue };
            let want = r.target == Path::new("/system/bin/x");
            assert_eq!(is_absorbable(&src, &r.target), want, "{:?}", r.target);
        }
    }

    #[test]
    fn whole_filesystem_mounts_are_never_absorbed() {
        let rows = parse_mountinfo(SAMPLE);
        let roots = fs_roots(&rows);
        let prod = rows.iter().find(|r| r.target == Path::new("/product")).unwrap();
        assert!(source_of(prod, &roots).is_none());
    }

    #[test]
    fn skip_list_matches_module_id_or_target_prefix() {
        let src = Path::new("/data/adb/modules/zygisk_lsposed/bin/dex2oat");
        let tgt = Path::new("/apex/com.android.art/bin/dex2oat64");
        assert!(is_skipped(src, tgt, &["zygisk_lsposed".into()]), "module id");
        assert!(is_skipped(src, tgt, &["/apex/".into()]), "target prefix");
        assert!(!is_skipped(src, tgt, &["other_module".into()]));
        assert!(!is_skipped(src, tgt, &["/system/".into()]));
        assert!(!is_skipped(src, tgt, &[]));
    }

    #[test]
    fn unescapes_octal_in_paths() {
        let rows = parse_mountinfo("1 1 0:1 /a\\040b /c\\040d rw - t s rw");
        assert_eq!(rows[0].root, "/a b");
        assert_eq!(rows[0].target, PathBuf::from("/c d"));
    }
}
