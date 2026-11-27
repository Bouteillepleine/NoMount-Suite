
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use anyhow::Result;

use crate::nm::{LiveKind, Nm};

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    pub candidates: usize,
    pub ghostable: usize,
    pub paths: usize,
    pub uids: usize,
    pub cuids: usize,
    pub rejected: usize,
    pub rejected_uids: usize,
    pub rejected_cuids: usize,
    pub rejected_examples: Vec<String>,
    pub dump_failed: bool,
    pub probe_failed: bool,
    pub cloak_unknown: bool,
    /// ghostpaths / uidconceal existed but could not be read, so that table was left
    /// alone rather than replaced with a set we could not build. Stale, still hiding.
    pub extra_unreadable: bool,
    pub conceal_unreadable: bool,
}

impl Summary {
    pub fn effective(&self) -> bool {
        self.paths > 0 && self.uids > 0
    }

    fn warning(&self) -> Option<String> {
        if self.cloak_unknown {
            return Some(
                "\u{26a0} ghost cloak: nm would not answer, so whether this kernel has the \
                 cloak at all is unknown - nothing was synced this pass"
                    .into(),
            );
        }
        if self.dump_failed {
            return Some(
                "\u{26a0} ghost cloak: could not read the engine's live state, so nothing was \
                 measured and nothing was pushed - the kernel keeps the tables it already had, \
                 which still hide but may name paths that have since changed"
                    .into(),
            );
        }
        if self.probe_failed {
            return Some(
                "\u{26a0} ghost cloak: the absence probe would not run, so no path could be \
                 judged ghostable - the kernel keeps the path table it already had rather than \
                 having it replaced with a set nothing measured"
                    .into(),
            );
        }
        if self.extra_unreadable || self.conceal_unreadable {
            let which = match (self.extra_unreadable, self.conceal_unreadable) {
                (true, true) => "ghostpaths and uidconceal",
                (true, false) => "ghostpaths",
                _ => "uidconceal",
            };
            return Some(format!(
                "⚠ ghost cloak: could not read {which} - that table was LEFT AS IT WAS rather \
                 than replaced, so it is whatever the last good sync wrote. Fix the file's \
                 permissions and re-run `nomount ghost sync`"
            ));
        }
        let mut parts: Vec<String> = Vec::new();
        if self.rejected > 0 {
            parts.push(format!("{} of {} path(s)", self.rejected, self.ghostable));
        }
        if self.rejected_uids > 0 {
            parts.push(format!(
                "{} of {} uid(s)",
                self.rejected_uids,
                self.uids + self.rejected_uids
            ));
        }
        if self.rejected_cuids > 0 {
            parts.push(format!(
                "{} of {} conceal uid(s)",
                self.rejected_cuids,
                self.cuids + self.rejected_cuids
            ));
        }
        if !parts.is_empty() {
            let first = if self.rejected_examples.is_empty() {
                String::new()
            } else {
                format!("; first: {}", self.rejected_examples.join(" "))
            };
            return Some(format!(
                "⚠ ghost cloak: {} REFUSED by the kernel - the existence oracles stay open for \
                 those{first}",
                parts.join(" and ")
            ));
        }
        None
    }
}

const CTL_CHUNK: usize = 12 * 1024;

pub(crate) fn candidates(list: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = crate::nm::parse_list(list)
        .into_iter()
        .filter(|r| r.kind != LiveKind::Whiteout && !r.public)
        .map(|r| r.target)
        .filter(|t| t.is_absolute())
        .collect();
    v.sort();
    v.dedup();
    v
}

/// Secondary users present on the device -- work profiles, clones, additional accounts.
fn device_user_ids() -> Vec<u32> {
    let mut v = vec![0u32];
    if let Ok(rd) = std::fs::read_dir("/data/system/users") {
        for e in rd.flatten() {
            if let Some(n) = e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) {
                v.push(n);
            }
        }
    }
    v.sort_unstable();
    v.dedup();
    v
}

/// Expand blocked appids into every raw uid the engine hides them under.
///
/// The engine normalises before deciding (`uid % NM_PER_USER_RANGE`, plus a remap of the
/// sdksandbox range down to the appid), so one hide-list entry covers the app in every user
/// profile and in its sandbox. The cloak compares the RAW uid and does not normalise, so a table
/// of bare appids left those same processes hidden-but-not-absent: stat says ENOENT while
/// truncate still answers EROFS and mkdirat still answers EEXIST. Ordered so that if the cap
/// bites it drops the least likely uid rather than a primary-user one.
fn expand_ghost_uids(appids: &[u32], users: &[u32]) -> Vec<u32> {
    const SDKSANDBOX_OFF: u32 = 10_000;
    let mut v: Vec<u32> = Vec::new();
    let push = |u: u32, v: &mut Vec<u32>| {
        if u != 0 && !v.contains(&u) {
            v.push(u);
        }
    };
    for a in appids {
        push(*a, &mut v);
    }
    for u in users.iter().filter(|u| **u != 0) {
        for a in appids {
            if let Some(x) =
                u.checked_mul(crate::blocklist::PER_USER_RANGE).and_then(|x| x.checked_add(*a))
            {
                push(x, &mut v);
            }
        }
    }
    for u in users {
        for a in appids {
            if let Some(x) = u
                .checked_mul(crate::blocklist::PER_USER_RANGE)
                .and_then(|x| x.checked_add(*a))
                .and_then(|x| x.checked_add(SDKSANDBOX_OFF))
            {
                push(x, &mut v);
            }
        }
    }
    v
}

/// The packages whose tasks must look idle to the callers we already hide from.
///
/// Hand-maintained, one entry per line, same grammar as the hide list: it is the
/// mirror of whatever filters package visibility for those callers, and the Suite
/// has no way to read that from another module. An absent or empty file clears the
/// kernel table, so removing the file turns the concealment off.
/// Extra paths to cloak from the callers we hide from, beyond the ones the
/// sync derives from injected rules.
///
/// The derived set only covers paths the Suite serves, so it cannot reach a
/// socket or a node the system owns -- `/dev/socket/adbd` being the case that
/// motivated this: an app that sees it while `init.svc.adbd` reads stopped has
/// caught the spoof, because init unlinks that socket before publishing that
/// value. Hand-maintained, one absolute path per line, `#` comments. These are
/// pushed as-is: the absence probe judges injected paths, and a path the Suite
/// does not serve has nothing to probe.
pub const EXTRA_PATHS: &str = "/data/adb/nomount/ghostpaths";

/// A cloak list from disk, or `None` when the file is there and could not be read.
///
/// The two must stay apart. An empty set reaches `push` as a table REPLACEMENT, and when
/// there is nothing at all to send `push` issues `-`, which flushes the kernel's table
/// outright -- so folding a read error into "empty" turns one unreadable file into a
/// silent un-cloaking. Never created is the ordinary case and really does mean empty.
fn read_list(path: &str) -> Option<Vec<String>> {
    match std::fs::read_to_string(path) {
        Ok(raw) => Some(parse_conceal(&raw)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(Vec::new()),
        Err(_) => None,
    }
}

fn extra_paths() -> Option<Vec<String>> {
    // '@name' is an abstract socket, not a path; the kernel takes both in this list
    // and only the socket guard ever looks the '@' form up.
    Some(
        read_list(EXTRA_PATHS)?
            .into_iter()
            .filter(|p| p.starts_with('/') || p.starts_with('@'))
            .collect(),
    )
}

pub const CONCEAL_PATH: &str = "/data/adb/nomount/uidconceal";

fn parse_conceal(raw: &str) -> Vec<String> {
    crate::statefile::list_entries(raw).into_iter().map(str::to_owned).collect()
}

fn conceal_entries() -> Option<Vec<String>> {
    read_list(CONCEAL_PATH)
}

/// KernelSU's app-profile store: EVERY app with a profile, root or not (a DenyList
/// "umount modules" profile included). Only records with allow_su are root grants.
pub const KSU_ALLOWLIST: &str = "/data/adb/ksu/.allowlist";

/// Package-shaped ASCII runs in a binary blob.
///
/// Why this is worth doing: the conceal list is hand-maintained by package NAME, and a
/// repackaged manager gets a new random name every time it is rebuilt. The old name stays
/// in the file, the new one is never added, and the getpriority oracle silently reopens --
/// measured on an OP15 on 2026-11-08, where one uid with live tasks and no package the
/// caller could name took Duck Detector's Dangerous Apps card from INFO to Warning, and the
/// file still carried three dead manager names from earlier rebuilds.
///
/// A re-spoofed manager has to be granted root again before it is of any use, so it lands
/// here under its new name on its own. Reading it makes the common case self-healing
/// instead of a thing someone has to remember.
fn package_names_in(blob: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    let flush = |cur: &mut String, out: &mut Vec<String>| {
        // A package name needs a dot, and every run must be label-shaped: this is a blob,
        // so anything looser picks up field names and paths that happen to contain a dot.
        let ok = cur.len() >= 3
            && cur.contains('.')
            && !cur.starts_with('.')
            && !cur.ends_with('.')
            && !cur.contains("..")
            && cur.split('.').all(|l| {
                !l.is_empty()
                    && l.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                    && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            });
        if ok && !out.contains(cur) {
            out.push(cur.clone());
        }
        cur.clear();
    };
    for &b in blob {
        let c = b as char;
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' {
            cur.push(c);
        } else {
            flush(&mut cur, &mut out);
        }
    }
    flush(&mut cur, &mut out);
    out
}

/// Apps KernelSU has granted root, or an empty list when that cannot be told.
///
/// Empty on failure is right here: these are ADDED to the hand-maintained list, so a store
/// we cannot read costs the automatic half and leaves the explicit half exactly as written.
///
/// Every name in the store used to be taken, which concealed each DenyList app (a profile,
/// but no root) from itself: `getpriority(PRIO_USER, getuid())` answered ESRCH, which stock
/// cannot. The kernel is asked per installed app; the records are a fallback.
fn root_granted_packages() -> Vec<String> {
    let records = || match std::fs::read(KSU_ALLOWLIST) {
        Ok(b) => root_records_in(&b),
        Err(_) => Vec::new(),
    };
    let Some(installed) = crate::blocklist::installed_packages() else { return records() };
    match granted_by_kernel(&installed, &device_user_ids(), crate::ksu::uid_granted_root) {
        Asked::All(out) => out,
        // The kernel stopped answering partway: what it said, plus the records for the rest.
        Asked::Some(mut out) => {
            for p in records() {
                if !out.contains(&p) {
                    out.push(p);
                }
            }
            out
        }
        Asked::None => records(),
    }
}

#[derive(Debug, PartialEq)]
enum Asked {
    All(Vec<String>),
    Some(Vec<String>),
    None,
}

/// KernelSU keys a grant by the full uid, and packages.list names user 0's: a clone or a
/// work-profile copy granted root on its own was never asked about.
fn granted_by_kernel(
    installed: &[(String, u32)],
    users: &[u32],
    ask: impl Fn(u32) -> Option<bool>,
) -> Asked {
    let mut out = Vec::new();
    let mut answered = false;
    for (pkg, uid) in installed {
        let appid = crate::blocklist::appid(*uid);
        let mut granted = false;
        for u in users {
            let Some(raw) = u
                .checked_mul(crate::blocklist::PER_USER_RANGE)
                .and_then(|b| b.checked_add(appid))
            else {
                continue;
            };
            match ask(raw) {
                Some(g) => {
                    answered = true;
                    if g {
                        granted = true;
                        break;
                    }
                }
                None if answered => return Asked::Some(out),
                None => return Asked::None,
            }
        }
        if granted {
            out.push(pkg.clone());
        }
    }
    if answered {
        Asked::All(out)
    } else {
        Asked::None
    }
}

const AL_MAGIC: u32 = 0x7f4b_5355;
const AL_HDR: usize = 8;
const AL_REC: usize = 784;
const AL_KEY: usize = 4;
const AL_KEY_LEN: usize = 256;
const AL_ALLOW_SU: usize = 264;

/// Root-granted keys from the store's records (uapi/app_profile.h: version, key[256],
/// curr_uid, allow_su). A layout this build does not recognise yields nothing.
fn root_records_in(blob: &[u8]) -> Vec<String> {
    if blob.len() < AL_HDR
        || !(blob.len() - AL_HDR).is_multiple_of(AL_REC)
        || u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]) != AL_MAGIC
    {
        return Vec::new();
    }
    let mut out: Vec<String> = Vec::new();
    for r in blob[AL_HDR..].as_chunks::<AL_REC>().0 {
        if r[AL_ALLOW_SU] == 0 {
            continue;
        }
        let key = &r[AL_KEY..AL_KEY + AL_KEY_LEN];
        let end = key.iter().position(|&b| b == 0).unwrap_or(key.len());
        if let Ok(name) = std::str::from_utf8(&key[..end]) {
            if package_names_in(name.as_bytes()).first().map(String::as_str) == Some(name)
                && !out.iter().any(|o| o == name)
            {
                out.push(name.to_string());
            }
        }
    }
    out
}

/// Entries that name a package this device does not have installed.
///
/// Reported, never dropped: a stale name is the fingerprint of a manager that was rebuilt
/// under a new random name, which is exactly when the list needs a human to look at it.
pub fn stale_conceal_entries(entries: &[String], installed: &[(String, u32)]) -> Vec<String> {
    entries
        .iter()
        .filter(|e| {
            !e.contains('*') && !installed.iter().any(|(p, _)| p == *e)
        })
        .cloned()
        .collect()
}

/// Resolve the conceal list to every raw uid the kernel will be asked about.
///
/// Expanded through the same path as the hide list: getpriority(PRIO_USER) is
/// asked about a raw uid, so an appid-only table would leave the app visible in
/// every secondary profile and in its sandbox.
/// `None` means the conceal set could not be resolved -- either the list itself was
/// unreadable or the package map was. An empty `Some` is a real "nothing to conceal".
fn conceal_uids() -> Option<Vec<u32>> {
    let entries = conceal_entries()?;
    // The manager is in no list and cannot usefully be in one: a repackaged manager is
    // rebuilt under a NEW random package name every time, so a name-keyed table goes
    // stale in silence -- the old name stops resolving, the new one is never added, and
    // the getpriority UID-visibility oracle reopens on the manager's own running tasks.
    // Observed twice on the same device, 2026-11-08 and 2026-11-18. Ask the kernel which
    // appid holds manager status instead; KSUN, SukiSU and ReSukiSU all answer ('K', 10).
    // Only an app appid: KernelSU answers a "no manager" sentinel otherwise (-1, 65535).
    let manager = crate::ksu::manager_appid().filter(|a| (10_000..20_000).contains(a));
    let granted = root_granted_packages();
    if entries.is_empty() && granted.is_empty() {
        return Some(match manager {
            Some(a) => expand_ghost_uids(&[a], &device_user_ids()),
            None => Vec::new(),
        });
    }
    // There ARE entries and we cannot map them to uids. Reporting that as an empty set
    // would flush the kernel's conceal table and quietly turn getpriority concealment off.
    let installed = crate::blocklist::installed_packages()?;
    let mut entries = entries;
    for p in granted {
        if !entries.contains(&p) {
            entries.push(p);
        }
    }
    let mut appids: Vec<u32> = Vec::new();
    if let Some(a) = manager {
        appids.push(a);
    }
    for e in &entries {
        if let Ok(hits) = crate::blocklist::expand(e, &installed) {
            for (_, uid) in hits {
                let a = crate::blocklist::appid(uid);
                if a != 0 && !appids.contains(&a) {
                    appids.push(a);
                }
            }
        }
    }
    appids.sort_unstable();
    appids.dedup();
    Some(expand_ghost_uids(&appids, &device_user_ids()))
}

fn ghost_uids(live: &[u32]) -> Vec<u32> {
    let mut appids: Vec<u32> = live
        .iter()
        .map(|u| crate::blocklist::appid(*u))
        .filter(|u| *u != 0)
        .collect();
    appids.sort_unstable();
    appids.dedup();
    expand_ghost_uids(&appids, &device_user_ids())
}

fn absent_to(uid: u32, paths: &[PathBuf]) -> Option<Vec<bool>> {
    if paths.is_empty() {
        return Some(Vec::new());
    }
    let cpaths: Vec<std::ffi::CString> = paths
        .iter()
        .map(|p| std::ffi::CString::new(p.as_os_str().as_bytes()).ok())
        .collect::<Option<Vec<_>>>()?;

    let mut fds = [0i32; 2];
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return None;
    }
    let (rd, wr) = (fds[0], fds[1]);

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe {
            libc::close(rd);
            libc::close(wr);
        }
        return None;
    }
    if pid == 0 {
        unsafe {
            libc::close(rd);
            if libc::getuid() != uid
                && (libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(uid, uid, uid) != 0
                    || libc::setresuid(uid, uid, uid) != 0)
            {
                libc::_exit(3);
            }
            for c in &cpaths {
                let mut st: libc::stat = std::mem::zeroed();
                let byte: u8 = if libc::lstat(c.as_ptr(), &mut st) == 0 {
                    0
                } else if std::io::Error::last_os_error().raw_os_error()
                    == Some(libc::ENOENT)
                {
                    1
                } else {
                    0
                };
                if libc::write(wr, (&byte as *const u8).cast(), 1) != 1 {
                    libc::_exit(4);
                }
            }
            libc::_exit(0);
        }
    }

    unsafe { libc::close(wr) };
    let mut f = unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(rd) };
    let mut buf = Vec::with_capacity(paths.len());
    let read_ok = f.read_to_end(&mut buf).is_ok();
    drop(f);

    let mut status: i32 = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    let exited_clean = waited >= 0
        && libc::WIFEXITED(status)
        && libc::WEXITSTATUS(status) == 0;

    if !read_ok || !exited_clean || buf.len() != paths.len() {
        return None;
    }
    Some(buf.into_iter().map(|b| b == 1).collect())
}

/// The kernel's ghost_rule_sane() (lkm/ghost.c), mirrored so a path it would refuse is
/// never sent: one refused token fails the whole replace it rides in.
pub(crate) const GH_RULE_LEN: usize = 192;

pub(crate) fn ghost_rule_ok(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() >= GH_RULE_LEN || s.contains('\0') || s.contains('\n') {
        return false;
    }
    if b.first() == Some(&b'@') {
        return b.len() >= 2;
    }
    if b.len() < 6 || b[0] != b'/' || s.contains("//") {
        return false;
    }
    let slashes = b.iter().filter(|&&c| c == b'/').count();
    if b[b.len() - 1] == b'/' {
        slashes >= 3
    } else {
        slashes >= 2
    }
}

fn bump(out: &mut Summary, kind: char, n: usize) {
    match kind {
        'p' => out.paths += n,
        'c' => out.cuids += n,
        _ => out.uids += n,
    }
}

fn chunks(items: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    let mut cur = String::new();
    for it in items {
        if !cur.is_empty() && cur.len() + it.len() + 1 > CTL_CHUNK {
            v.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push('\n');
        }
        cur.push_str(it);
    }
    if !cur.is_empty() {
        v.push(cur);
    }
    v
}

/// Replace the kernel's `kind` table with `items`, without ever leaving it emptier than
/// either the old or the new set. One chunk goes as `=`, which the kernel validates and
/// stages before it swaps. Anything larger, or a replace the kernel refuses, is added
/// with `+` first and only then are the stale entries removed with `~`: clearing first
/// opened the cloak for every `nm` spawn of the rebuild, on every sync.
fn push(nm: &Nm, kind: char, items: &[String], out: &mut Summary) {
    let mut want: Vec<&str> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for it in items {
        let ok = if kind == 'p' {
            ghost_rule_ok(it)
        } else {
            it.parse::<u32>().map(|u| u != 0).unwrap_or(false)
        };
        if !ok {
            if kind == 'p' {
                out.rejected += 1;
                if out.rejected_examples.len() < 3 {
                    out.rejected_examples.push(it.clone());
                }
            } else if kind == 'c' {
                out.rejected_cuids += 1;
            } else {
                out.rejected_uids += 1;
            }
            continue;
        }
        if seen.insert(it.as_str()) {
            want.push(it.as_str());
        }
    }
    if want.is_empty() {
        let _ = nm.ghost_ctl(&format!("{kind}-"));
        return;
    }
    let parts = chunks(&want);
    if parts.len() == 1 && nm.ghost_ctl(&format!("{kind}={}", parts[0])).is_ok() {
        bump(out, kind, want.len());
        return;
    }
    for part in &parts {
        let n = part.split('\n').count();
        if nm.ghost_ctl(&format!("{kind}+{part}")).is_ok() {
            bump(out, kind, n);
            continue;
        }
        for it in part.split('\n') {
            if nm.ghost_ctl(&format!("{kind}+{it}")).is_ok() {
                bump(out, kind, 1);
            } else if kind == 'p' {
                out.rejected += 1;
                if out.rejected_examples.len() < 3 {
                    out.rejected_examples.push(it.to_string());
                }
            } else if kind == 'c' {
                out.rejected_cuids += 1;
            } else {
                out.rejected_uids += 1;
            }
        }
    }
    // Stale entries go last. An unreadable table leaves them in place: over-hiding until
    // the next sync, never under-hiding.
    let Ok(live) = nm.ghost_list() else { return };
    let prefix = format!("{kind} ");
    let stale: Vec<&str> = live
        .lines()
        .filter_map(|l| l.strip_prefix(prefix.as_str()))
        .map(str::trim)
        .filter(|e| !e.is_empty() && !seen.contains(e))
        .collect();
    for part in chunks(&stale) {
        let _ = nm.ghost_ctl(&format!("{kind}~{part}"));
    }
}

pub fn sync(nm: &Nm) -> Result<Option<Summary>> {
    match nm.ghost_present() {
        Some(true) => {}
        // a kernel built without the cloak: nothing to sync and nothing to say
        Some(false) => return Ok(None),
        None => {
            return Ok(Some(Summary { cloak_unknown: true, ..Summary::default() }));
        }
    }
    let mut out = Summary::default();

    // Both of these used to answer an unreadable dump by sending `p-` and `u-`, which
    // CLEARS the kernel's two tables -- the one thing the push path 50 lines below
    // documents as "what un-cloaks the device", and it fired on a transient nm failure
    // during any mutating verb, because main.rs re-syncs after each one. A dump that would
    // not read says nothing about what should be cloaked, so there is nothing to push:
    // leave the kernel the table it already has, which is stale but still hiding, and let
    // Summary::warning() say the pass did not measure anything. Measured-empty still
    // clears, further down -- that is a different answer.
    let mut uids: Vec<u32> = match nm.uid_list_live() {
        Ok(live) => ghost_uids(&live),
        Err(_) => {
            out.dump_failed = true;
            return Ok(Some(out));
        }
    };
    uids.dedup();

    let list = match nm.list() {
        Ok(l) => l,
        Err(_) => {
            out.dump_failed = true;
            return Ok(Some(out));
        }
    };
    let cands = candidates(&list);
    out.candidates = cands.len();

    let ghostable: Vec<String> = match uids.first() {
        Some(&probe) => match absent_to(probe, &cands) {
            Some(mask) => cands
                .iter()
                .zip(mask)
                .filter(|(_, absent)| *absent)
                .filter_map(|(p, _)| p.to_str().map(str::to_owned))
                .collect(),
            None => {
                out.probe_failed = true;
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    out.ghostable = ghostable.len();

    // An unreadable list is not an empty one. `push` sends the first chunk as `=`, which
    // REPLACES the kernel's table, and sends `-` outright when there is nothing to send --
    // so pushing a set we failed to build is what un-cloaks the device. Skip the push
    // instead: the kernel keeps the table it already has, which is stale but still hiding,
    // and say so rather than reporting an ordinary success.
    //
    // This comment described a guard that was not here: a probe that would not run left
    // `ghostable` empty, and the push below then sent `p-` and cleared the path table for
    // real. An empty set the probe MEASURED still clears -- a path a module no longer
    // serves must stop being hidden - but an empty set it never measured must not. Pushing
    // the extras alone would be worse than skipping, since that replaces the table with
    // only them and drops every probed path.
    if out.probe_failed {
        // nothing measured, so nothing to push
    } else {
        match extra_paths() {
            Some(extra) => {
                let mut paths = ghostable;
                for e in extra {
                    if !paths.contains(&e) {
                        paths.push(e);
                    }
                }
                push(nm, 'p', &paths, &mut out);
            }
            None => out.extra_unreadable = true,
        }
    }

    let uid_strs: Vec<String> = uids.iter().map(u32::to_string).collect();
    push(nm, 'u', &uid_strs, &mut out);

    match conceal_uids() {
        Some(conceal) => {
            let strs: Vec<String> = conceal.iter().map(u32::to_string).collect();
            push(nm, 'c', &strs, &mut out);
        }
        None => out.conceal_unreadable = true,
    }
    Ok(Some(out))
}

pub fn run_sync(verbose: bool) -> Result<()> {
    let nm = Nm::new();
    // Outside a pass: a reload between its delete and re-add would be pushed as the set.
    let _pass = crate::mount::pass_lock();
    match sync(&nm)? {
        None => {
            if verbose {
                println!(
                    "nomount ghost: this kernel has no _ghost support (or the engine is below v26) - nothing to populate"
                );
            }
            Ok(())
        }
        Some(s) => {
            if let Some(w) = s.warning() {
                println!("nomount ghost: {w}");
            } else if s.probe_failed {
                println!(
                    "nomount ghost: the absence probe did not run, so no path could be judged ghostable - the kernel keeps the table it already had. This is not \"nothing to ghost\"."
                );
            } else if !s.effective() {
                println!(
                    "nomount ghost: inert -- {} path(s), {} uid(s) (both tables must be non-empty for any guard to fire)",
                    s.paths, s.uids
                );
            } else if verbose {
                println!(
                    "nomount ghost: {} of {} rule target(s) ghosted, {} uid(s)",
                    s.paths, s.candidates, s.uids
                );
                if s.cuids > 0 {
                    println!(
                        "nomount ghost: {} uid(s) concealed from those callers (tasks read idle)",
                        s.cuids
                    );
                }
                // A name in the list that is not installed is the fingerprint of an app --
                // in practice a repackaged root manager -- rebuilt under a new random name.
                // The entry it left behind conceals nothing and the new name is in no list,
                // so the getpriority oracle reopens with nothing on screen to say so.
                if let (Some(entries), Some(installed)) =
                    (conceal_entries(), crate::blocklist::installed_packages())
                {
                    let stale = stale_conceal_entries(&entries, &installed);
                    if !stale.is_empty() {
                        println!(
                            "nomount ghost: {} conceal entr{} name a package that is not installed: {}",
                            stale.len(),
                            if stale.len() == 1 { "y" } else { "ies" },
                            stale.join(", ")
                        );
                        println!(
                            "nomount ghost: that is what a rebuilt manager leaves behind. The \
                             manager itself is resolved from the kernel and stays concealed either \
                             way, so a dead name conceals nothing and is safe to drop."
                        );
                    }
                }
            }
            Ok(())
        }
    }
}

pub fn sync_quietly(nm: &Nm) {
    let _pass = crate::mount::pass_lock();
    if let Ok(Some(s)) = sync(nm) {
        if let Some(w) = s.warning() {
            eprintln!("nomount: {w}");
        }
    }
}

pub fn sync_after_pass(nm: &Nm) {
    let Ok(Some(s)) = sync(nm) else { return };
    if let Some(w) = s.warning() {
        println!("nomount: {w}");
    } else if s.paths > 0 {
        println!("nomount: ghost cloak re-synced ({} paths, {} uids)", s.paths, s.uids);
    }
}

#[cfg(test)]
mod tests {

    fn al_record(key: &str, uid: i32, allow_su: bool) -> Vec<u8> {
        let mut r = vec![0u8; super::AL_REC];
        r[0..4].copy_from_slice(&4u32.to_le_bytes());
        r[4..4 + key.len()].copy_from_slice(key.as_bytes());
        r[260..264].copy_from_slice(&uid.to_le_bytes());
        r[264] = allow_su as u8;
        r
    }

    /// A DenyList "umount modules" profile is a record with allow_su = 0. Taking it as a root
    /// grant concealed the app from itself: getpriority on its own uid answered ESRCH.
    #[test]
    fn only_root_granted_records_are_root_grants() {
        let mut blob = Vec::new();
        blob.extend_from_slice(&0x7f4b_5355u32.to_le_bytes());
        blob.extend_from_slice(&4u32.to_le_bytes());
        blob.extend(al_record("com.root.app", 10200, true));
        blob.extend(al_record("com.denylisted.app", 10201, false));
        blob.extend(al_record("$", 9999, false));
        assert_eq!(super::root_records_in(&blob), vec!["com.root.app".to_string()]);

        let mut bad_magic = blob.clone();
        bad_magic[0] ^= 0xff;
        assert!(super::root_records_in(&bad_magic).is_empty(), "unknown store: conceal nothing");
        assert!(super::root_records_in(&blob[..blob.len() - 1]).is_empty(), "unknown layout");
    }

    #[test]
    fn a_rebuilt_manager_is_concealed_by_grant_and_its_dead_name_is_reported() {
        // The store is a blob: only label-shaped runs with a dot are package names, or
        // field names and paths come along too.
        let blob = b"\x00\x01allow\x00com.example.app\x00\x10\x10ehcnsovvne.smxv6a5.zrk687nl\
\x00/data/adb/ksu/.allowlist\x00..bad\x00trailing.\x00a.b\x00";
        let found = package_names_in(blob);
        assert!(found.contains(&"com.example.app".to_string()), "{found:?}");
        assert!(found.contains(&"ehcnsovvne.smxv6a5.zrk687nl".to_string()), "{found:?}");
        assert!(found.contains(&"a.b".to_string()), "{found:?}");
        for junk in ["..bad", "trailing.", "/data/adb/ksu/.allowlist", ".allowlist"] {
            assert!(!found.contains(&junk.to_string()), "picked up {junk}: {found:?}");
        }
        // A path's last component is label-shaped on its own; the slash ends the run, so
        // what survives must not be the whole path.
        assert!(!found.iter().any(|p| p.contains('/')), "{found:?}");

        // Stale = named but not installed. That is the fingerprint of a rebuilt manager,
        // and it is reported rather than dropped.
        let installed = vec![
            ("com.example.app".to_string(), 10001u32),
            ("io.github.muntashirakon.AppManager".to_string(), 10002),
        ];
        let entries = vec![
            "com.example.app".to_string(),
            "mfwtvm.dryrdf.wdodpp".to_string(),
            "yktuwp.apjvhz.adavin".to_string(),
            "*.duckdetector".to_string(),
        ];
        let stale = stale_conceal_entries(&entries, &installed);
        assert_eq!(stale, vec!["mfwtvm.dryrdf.wdodpp", "yktuwp.apjvhz.adavin"]);
        // A glob is a pattern, not a name, so it is never called stale.
        assert!(!stale.iter().any(|e| e.contains('*')), "{stale:?}");
        assert!(stale_conceal_entries(&[], &installed).is_empty());
    }
    use super::*;

    #[test]
    fn a_root_grant_is_asked_per_user_and_a_failure_midway_is_not_complete() {
        let installed = vec![
            ("com.a".to_string(), 10100),
            ("com.clone".to_string(), 10200),
            ("com.b".to_string(), 10300),
        ];
        let users = [0, 10];
        // Only the user-10 copy of com.clone is granted.
        let ask = |uid: u32| Some(uid == 10100 || uid == 1_010_200);
        assert_eq!(
            granted_by_kernel(&installed, &users, ask),
            Asked::All(vec!["com.a".to_string(), "com.clone".to_string()])
        );
        let fails_at_b = |uid: u32| if uid == 10300 { None } else { Some(uid == 10100) };
        assert_eq!(
            granted_by_kernel(&installed, &users, fails_at_b),
            Asked::Some(vec!["com.a".to_string()]),
            "a partial answer must not read as the whole list"
        );
        assert_eq!(granted_by_kernel(&installed, &users, |_| None), Asked::None);
    }

    #[test]
    fn an_unreadable_cloak_list_is_not_an_empty_one() {
        // Thread id as well as pid: tests share a process and run in parallel, and
        // absent_to_distinguishes_present_from_missing builds "nm-ghost-<pid>" too -- with
        // the same name this test's remove_dir_all deleted that one's fixture mid-run.
        let d = std::env::temp_dir().join(format!(
            "nm-ghost-readlist-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();

        // Never created: a real "nothing to cloak".
        let missing = d.join("absent");
        assert_eq!(read_list(missing.to_str().unwrap()), Some(Vec::new()));

        // Present and readable, including the comment/blank handling.
        let ok = d.join("list");
        std::fs::write(&ok, "# note\n\n/dev/socket/adbd\n@abstract\n").unwrap();
        assert_eq!(
            read_list(ok.to_str().unwrap()),
            Some(vec!["/dev/socket/adbd".to_string(), "@abstract".to_string()])
        );

        // Present and unreadable. A directory where a file belongs is the portable way
        // to force a non-NotFound error -- the real cases are EACCES and a bad label,
        // which a test running as root could not reproduce anyway.
        let unreadable = d.join("wedged");
        std::fs::create_dir(&unreadable).unwrap();
        assert_eq!(
            read_list(unreadable.to_str().unwrap()),
            None,
            "an unreadable list must not read as empty: push() turns an empty set into a \
             table flush, which un-cloaks the device"
        );

        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn an_unreadable_list_is_reported_rather_than_passing_as_a_clean_sync() {
        let s = Summary { conceal_unreadable: true, ..Summary::default() };
        let w = s.warning().expect("an unreadable conceal list must warn");
        assert!(w.contains("uidconceal"), "{w}");
        assert!(w.contains("LEFT AS IT WAS"), "{w}");

        let s = Summary { extra_unreadable: true, ..Summary::default() };
        assert!(s.warning().unwrap().contains("ghostpaths"));

        // And the ordinary pass still says nothing.
        assert!(Summary { paths: 3, uids: 2, ..Summary::default() }.warning().is_none());
    }

    /// GH_MAX_UIDS in the kernel's ghost.c. Nothing in the production path trims to it: a
    /// cloak that normalises the uid dedupes the expansion as it stores it (measured on
    /// device - 120 sent, 20 stored), and one that truly runs out answers ENOSPC, which
    /// push() reports as a refusal.
    const GHOST_MAX_UIDS: usize = 128;

    #[test]
    fn the_conceal_list_ignores_blanks_and_comments() {
        let got = parse_conceal("\n# a note\n  com.one  \n\n#\ncom.two\n");
        assert_eq!(got, vec!["com.one".to_string(), "com.two".to_string()]);
    }

    #[test]
    fn the_cloak_covers_every_uid_the_engine_hides_the_app_under() {
        // One hide-list entry, primary user plus a work profile.
        let out = expand_ghost_uids(&[10384], &[0, 10]);
        assert!(out.contains(&10384), "the app itself");
        assert!(out.contains(&1010384), "the same app in user 10 (work profile / clone)");
        assert!(out.contains(&20384), "its sdksandbox uid in user 0");
        assert!(out.contains(&1020384), "its sdksandbox uid in user 10");
        assert!(!out.contains(&0), "uid 0 is never ghosted");

        // A single-user device must not grow entries it has no processes for.
        let solo = expand_ghost_uids(&[10384], &[0]);
        assert_eq!(solo, vec![10384, 20384]);

        // Bare appids come first so that a kernel which does run out of room keeps the entries
        // that matter. Nothing is pre-truncated: a normalising kernel dedupes the rest away, and
        // one that cannot answers ENOSPC, which push() reports.
        let many: Vec<u32> = (10000..10200).collect();
        let all = expand_ghost_uids(&many, &[0, 10]);
        assert!(all.len() > GHOST_MAX_UIDS, "the expansion is not pre-trimmed");
        assert_eq!(all[0], 10000, "primary-user appids lead");
        assert!(all.iter().take(many.len()).all(|u| many.contains(u)));
    }

    #[test]
    fn candidates_exclude_whiteouts_and_public_rules() {
        let list = "\
/product/app/A/A.apk -> /data/adb/modules/M/product/app/A/A.apk
/product/overlay/B.apk -> /data/adb/modules/M/product/overlay/B.apk (public)
/system/etc/gone (whiteout)
/system/etc/vdir (virtual dir)
/system/etc/c.conf -> /data/adb/modules/M/system/etc/c.conf [UID: 10123]
";
        let c = candidates(list);
        assert_eq!(
            c,
            vec![
                PathBuf::from("/product/app/A/A.apk"),
                PathBuf::from("/system/etc/c.conf"),
                PathBuf::from("/system/etc/vdir"),
            ],
            "whiteouts and (public) rules must never be ghosted"
        );
    }

    #[test]
    fn candidates_keep_a_target_containing_a_bracket() {
        let list = "/product/app/Foo (2)/x.apk -> /data/adb/modules/M/x.apk\n";
        assert_eq!(candidates(list), vec![PathBuf::from("/product/app/Foo (2)/x.apk")]);
    }

    #[test]
    fn candidates_are_sorted_deduped_and_absolute() {
        let list = "\
/b/b/b -> /x
/a/a/a -> /y
/b/b/b -> /z
not-a-path -> /q
";
        assert_eq!(
            candidates(list),
            vec![PathBuf::from("/a/a/a"), PathBuf::from("/b/b/b")]
        );
    }

    #[test]
    fn summary_is_only_effective_with_both_tables() {
        let mut s = Summary { paths: 3, uids: 0, ..Default::default() };
        assert!(!s.effective(), "no uids -> every guard is dead code");
        s.uids = 2;
        assert!(s.effective());
        s.paths = 0;
        assert!(!s.effective(), "no paths -> every guard is dead code");
    }

    #[test]
    fn absent_to_distinguishes_present_from_missing() {
        let d = std::env::temp_dir().join(format!("nm-ghost-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        let there = d.join("there");
        std::fs::write(&there, b"x").unwrap();
        let gone = d.join("gone");
        let uid = unsafe { libc::getuid() };
        let ans = absent_to(uid, &[there.clone(), gone.clone()]);
        let _ = std::fs::remove_dir_all(&d);
        let ans = ans.expect("probe should run as our own uid");
        assert_eq!(ans, vec![false, true], "present -> not ghostable, missing -> ghostable");
    }

    #[test]
    fn absent_to_on_an_empty_list_is_not_an_error() {
        // Load-bearing for the push policy: a candidate set the probe MEASURED as empty
        // must still clear the kernel's path table, because a path a module no longer
        // serves has to stop being hidden. Only an unmeasured pass skips the push. If this
        // ever answers None, `nomount vfs clear` stops clearing the cloak with it.
        assert_eq!(absent_to(unsafe { libc::getuid() }, &[]), Some(Vec::new()));
    }

    #[test]
    fn an_unmeasured_pass_never_reports_that_it_cleared_anything() {
        // Both of these used to clear the kernel's tables on a failed read, which is
        // fail-open on a detection cloak: a transient nm error during any mutating verb
        // un-cloaked the device until the next successful sync. They now leave the tables
        // alone, so neither message may claim otherwise.
        for s in [
            Summary { dump_failed: true, ..Default::default() },
            Summary { probe_failed: true, ..Default::default() },
        ] {
            let w = s.warning().expect("an unmeasured pass must warn, not pass quietly");
            assert!(
                w.contains("keeps the"),
                "an unmeasured pass must say the kernel kept its table: {w}"
            );
            for lie in ["CLEARED", "is EMPTY", "left empty"] {
                assert!(!w.contains(lie), "nothing is cleared on a failed read: {w}");
            }
            assert!(!s.effective(), "an unmeasured pass has established nothing");
        }
    }

    #[test]
    fn ghost_uids_collapses_the_live_list_to_appids_then_re_expands_it() {
        // The live list is whatever uids the engine reports, clones included; they collapse to
        // one appid and then expand again into the uids the CLOAK has to match raw. Collapsing
        // and stopping there is what left a hidden app's clone hidden-but-not-absent.
        let out = ghost_uids(&[1_010_471, 10_471, 10_123]);
        assert!(out.contains(&10_123) && out.contains(&10_471), "both appids survive");
        assert!(out.contains(&20_123) && out.contains(&20_471), "and their sdksandbox uids");
        assert_eq!(out.len(), out.iter().collect::<std::collections::HashSet<_>>().len());
    }

    /// Pinned against the kernel's ghost_rule_sane(): any path it refuses fails the whole
    /// replace it rides in, so Rust must refuse exactly the same set.
    #[test]
    fn ghost_rule_ok_matches_the_kernel() {
        for ok in ["/dev/socket/adbd", "/system/etc/a", "/data/adb/x/", "@jdwp-control", "@x"] {
            assert!(ghost_rule_ok(ok), "{ok}");
        }
        let long = format!("/system/etc/{}", "x".repeat(180));
        for bad in ["/sbin", "/su", "/dev/", "/debug_ramdisk", "/dev//socket", "@", "rel/a/b", "/a/b/c\0d"] {
            assert!(!ghost_rule_ok(bad), "{bad}");
        }
        assert!(!ghost_rule_ok(&long), "{} bytes", long.len());
        assert!(ghost_rule_ok(&long[..GH_RULE_LEN - 1]));
    }

    #[test]
    fn chunks_never_exceed_the_ctl_size_and_keep_every_item() {
        let items: Vec<String> = (0..500).map(|i| format!("/system/etc/many/{i:04}-{}", "y".repeat(60))).collect();
        let refs: Vec<&str> = items.iter().map(String::as_str).collect();
        let parts = chunks(&refs);
        assert!(parts.len() > 1);
        assert!(parts.iter().all(|p| p.len() <= CTL_CHUNK), "a chunk over the limit");
        let back: Vec<&str> = parts.iter().flat_map(|p| p.split('\n')).collect();
        assert_eq!(back, refs);
        assert!(chunks(&[]).is_empty());
    }

    #[test]
    fn ghost_uids_never_cloaks_from_root() {
        let out = ghost_uids(&[0, 10_123, 100_000]);
        assert!(out.contains(&10_123));
        assert!(!out.contains(&0), "uid 0 and anything normalising to appid 0 stay out");
        assert!(ghost_uids(&[0]).is_empty(), "a set of only root leaves the table empty");
    }

    #[test]
    fn ghost_uids_is_order_independent() {
        assert_eq!(ghost_uids(&[10_009, 10_471, 10_123]), ghost_uids(&[10_123, 10_009, 10_471]));
    }

    #[test]
    fn ghost_uids_on_an_empty_set_is_empty() {
        assert!(ghost_uids(&[]).is_empty());
    }

    #[test]
    fn a_refused_uid_is_never_reported_as_a_refused_path() {
        let s = Summary { uids: 1, rejected_uids: 3, ghostable: 0, ..Default::default() };
        let w = s.warning().expect("a refused table must warn");
        assert!(w.contains("3 of 4 uid(s)"), "the uid table has its own denominator: {w}");
        assert!(!w.contains("path(s)"), "no path was refused: {w}");
        assert!(!w.contains("10471"), "an appid must never reach this string: {w}");

        let s = Summary {
            ghostable: 9,
            rejected: 2,
            rejected_examples: vec!["/product/app/A/A.apk".into()],
            ..Default::default()
        };
        let w = s.warning().unwrap();
        assert!(w.contains("2 of 9 path(s)"), "{w}");
        assert!(w.contains("first: /product/app/A/A.apk"), "{w}");

        let s = Summary { ghostable: 9, rejected: 2, uids: 1, rejected_uids: 1, ..Default::default() };
        let w = s.warning().unwrap();
        assert!(w.contains("2 of 9 path(s) and 1 of 2 uid(s)"), "{w}");

        assert!(Summary::default().warning().is_none(), "a clean sync says nothing");
    }
}
