
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
    pub rejected: usize,
    pub rejected_uids: usize,
    pub rejected_examples: Vec<String>,
    pub dump_failed: bool,
    pub probe_failed: bool,
}

impl Summary {
    pub fn effective(&self) -> bool {
        self.paths > 0 && self.uids > 0
    }

    fn warning(&self) -> Option<String> {
        if self.dump_failed {
            return Some(
                "⚠ ghost cloak: could not read the engine's live state - both tables CLEARED, \
                 so the existence oracles are open until the next successful sync"
                    .into(),
            );
        }
        if self.probe_failed {
            return Some(
                "\u{26a0} ghost cloak: the absence probe would not run, so no path could be \
                 cloaked - the path table is EMPTY and the existence oracles are open"
                    .into(),
            );
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
            push(u * crate::blocklist::PER_USER_RANGE + a, &mut v);
        }
    }
    for u in users {
        for a in appids {
            push(u * crate::blocklist::PER_USER_RANGE + a + SDKSANDBOX_OFF, &mut v);
        }
    }
    v
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

fn push(nm: &Nm, kind: char, items: &[String], out: &mut Summary) {
    let mut first = true;
    let mut chunk: Vec<&str> = Vec::new();
    let mut len = 0usize;

    let flush = |chunk: &mut Vec<&str>, len: &mut usize, first: &mut bool, out: &mut Summary| {
        if chunk.is_empty() {
            return;
        }
        let replacing = *first;
        let cmd = format!("{}{}{}", kind, if replacing { '=' } else { '+' }, chunk.join("\n"));
        if nm.ghost_ctl(&cmd).is_ok() {
            match kind {
                'p' => out.paths += chunk.len(),
                _ => out.uids += chunk.len(),
            }
        } else {
            if replacing {
                let _ = nm.ghost_ctl(&format!("{kind}-"));
                match kind {
                    'p' => out.paths = 0,
                    _ => out.uids = 0,
                }
            }
            for it in chunk.iter() {
                let one = format!("{}+{}", kind, it);
                if nm.ghost_ctl(&one).is_ok() {
                    match kind {
                        'p' => out.paths += 1,
                        _ => out.uids += 1,
                    }
                } else if kind == 'p' {
                    out.rejected += 1;
                    if out.rejected_examples.len() < 3 {
                        out.rejected_examples.push((*it).to_string());
                    }
                } else {
                    out.rejected_uids += 1;
                }
            }
        }
        *first = false;
        chunk.clear();
        *len = 0;
    };

    for it in items {
        if len + it.len() + 1 > CTL_CHUNK && !chunk.is_empty() {
            flush(&mut chunk, &mut len, &mut first, out);
        }
        len += it.len() + 1;
        chunk.push(it.as_str());
    }
    flush(&mut chunk, &mut len, &mut first, out);

    if first {
        let _ = nm.ghost_ctl(&format!("{kind}-"));
    }
}

pub fn sync(nm: &Nm) -> Result<Option<Summary>> {
    if !nm.ghost_present() {
        return Ok(None);
    }
    let mut out = Summary::default();

    let mut uids: Vec<u32> = match nm.uid_list_live() {
        Ok(live) => ghost_uids(&live),
        Err(_) => {
            let _ = nm.ghost_ctl("p-");
            let _ = nm.ghost_ctl("u-");
            out.dump_failed = true;
            return Ok(Some(out));
        }
    };
    uids.dedup();

    let list = match nm.list() {
        Ok(l) => l,
        Err(_) => {
            let _ = nm.ghost_ctl("p-");
            let _ = nm.ghost_ctl("u-");
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

    push(nm, 'p', &ghostable, &mut out);
    let uid_strs: Vec<String> = uids.iter().map(u32::to_string).collect();
    push(nm, 'u', &uid_strs, &mut out);
    Ok(Some(out))
}

pub fn run_sync(verbose: bool) -> Result<()> {
    let nm = Nm::new();
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
                    "nomount ghost: the absence probe did not run, so no path could be judged ghostable - the cloak is left empty. This is not \"nothing to ghost\"."
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
            }
            Ok(())
        }
    }
}

pub fn sync_quietly(nm: &Nm) {
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
    use super::*;

    /// GH_MAX_UIDS in the kernel's ghost.c. Nothing in the production path trims to it: a
    /// cloak that normalises the uid dedupes the expansion as it stores it (measured on
    /// device - 120 sent, 20 stored), and one that truly runs out answers ENOSPC, which
    /// push() reports as a refusal.
    const GHOST_MAX_UIDS: usize = 128;

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
        assert_eq!(absent_to(unsafe { libc::getuid() }, &[]), Some(Vec::new()));
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
