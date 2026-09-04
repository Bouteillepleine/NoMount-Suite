//! Populate the kernel's `_ghost` tables from the live rule set.
//!
//! `_ghost` (kernel_patches/common/_ghost) closes the syscalls that resolve a
//! path and then act without consulting a hijacked filesystem op -- `O_PATH`,
//! all four `*xattr(2)`, `link(2)`, the whole `LOOKUP_DIRECTORY`/`ENOTDIR`
//! family, `truncate`/`utimensat`/`chmod`/`chown`, `mkdirat`/`mknodat`, and
//! `access(W_OK)`/`open(O_WRONLY|O_CREAT)`. Its guards are DEAD CODE until both
//! of its tables are populated: `ghost_hidden_path()` short-circuits to false on
//! an empty table. This module is what makes them live.
//!
//! WHY IT MOVED OUT OF service.sh
//! -----------------------------
//! It used to be forty lines of shell that ran ONCE, about ten seconds after
//! `sys.boot_completed`. Nothing re-ran it. Meanwhile the WebUI offers a Reload
//! button whose own comment reads "Install/remove a module, tap Reload, no
//! reboot", and `nomount reload` / `nomount mount` rebuild the rule set from
//! scratch. After any of those the ghost path table describes the PREVIOUS rule
//! set, and the consequences are the two the shell block itself warns about:
//!
//!   * a newly injected path is not in the table, so all eleven oracle families
//!     stay open for it -- the same state as not running `_ghost` at all;
//!   * a path that went from injected-only to SHADOWING is still ghosted while
//!     the engine now correctly serves the hidden reader the stock file, so one
//!     path answers `stat` = OK and `chmod`/`truncate`/`listxattr` = ENOENT at
//!     the same time. That is "a self-contradiction no real file can produce, so
//!     a scanner does not even need a control path to see it" -- worse than
//!     leaving the oracle open.
//!
//! `doctor.rs` detects the second case after the fact (`ghost cloak
//! over-reaches`); nothing repaired it until the next boot.
//!
//! THREE THINGS THIS DOES BETTER THAN THE SHELL DID
//! ------------------------------------------------
//! 1. **ENOENT, not "not -e".** `[ -e "$p" ]` in shell is false for ENOENT and
//!    for EACCES alike, and the two must not be conflated: ghosting a merely
//!    UNREACHABLE path turns its EACCES into ENOENT while a genuinely absent
//!    name under the same unsearchable parent still answers EACCES -- a new
//!    tell, of exactly the shape `_ghost` exists to remove. The shell worked
//!    around it by testing the parent's searchability first, which covers a
//!    unsearchable directory but not a per-file denial on the leaf. Here the
//!    child reads `errno` and requires exactly `ENOENT`.
//! 2. **Targets come from the one rule parser.** The shell cut `nm l` output at
//!    the first `" ("` with sed, which also truncates any target containing that
//!    substring -- the same hazard the block below it documents at length for a
//!    target containing a space. [`crate::nm::parse_list`] peels the known
//!    suffixes instead.
//! 3. **One process, not N.** One fork for the whole candidate list and one
//!    netlink command per table, instead of one `su` plus one `nm k g p+…` exec
//!    per path.
//!
//! WHAT IT STILL CANNOT DO
//! -----------------------
//! The probe forks and drops to the hidden uid, but it stays in the ROOT
//! SELinux domain -- `su <uid> -c` had the same problem (it runs in `ksu`), and
//! `_ghost/README.md` records `_pathhide` getting a wrong answer exactly that
//! way. A leaf whose type the root domain cannot `getattr` but an app can would
//! be reported absent and get ghosted, which is the "apps break" direction. It
//! is narrow -- the root domain is permissive and the engine's own hiding is
//! what produces the ENOENT we are looking for -- but it is the residual, and
//! `nomount check` re-tests every ghosted path from the hidden uid afterwards
//! (`doctor::ghost_seen_by`) precisely because this cannot be settled here.

use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use anyhow::Result;

use crate::nm::{LiveKind, Nm};

/// What one sync did. Every field is reported, because a PARTIALLY populated
/// table is the state `ghost.c` calls worse than an empty one.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// Rule targets considered.
    pub candidates: usize,
    /// Of those, absent to the probe uid -- i.e. injected-only, so ghostable.
    pub ghostable: usize,
    /// Actually installed in the kernel's path table.
    pub paths: usize,
    /// Hidden uids installed.
    pub uids: usize,
    /// Paths the kernel refused (table full, or over its rule-length cap).
    pub rejected: usize,
    /// The first few refusals, for a log line a human can act on.
    pub rejected_examples: Vec<String>,
    /// `nm list` could not be read, so both tables were cleared rather than
    /// rebuilt from a possibly-truncated view of the rule set.
    pub dump_failed: bool,
}

impl Summary {
    /// The cloak only fires when BOTH tables are non-empty -- so this is the
    /// one line worth printing.
    pub fn effective(&self) -> bool {
        self.paths > 0 && self.uids > 0
    }
}

/// `nm k g` payloads ride in one netlink attribute. The client caps the whole
/// payload at 16292 bytes and the knob word takes 4 of them; stay well inside
/// so a long path near the kernel's 191-byte rule cap cannot push a batch over.
const CTL_CHUNK: usize = 12 * 1024;

/// Which rule targets are candidates for ghosting.
///
/// NOT every injection target. Where a rule SHADOWS a stock file the engine
/// deliberately serves the hidden reader that stock file, and a `(public)` rule
/// stays visible on purpose -- ghosting either produces the self-contradiction
/// described in this module's header. Measured on OP15 at v1.3.57: of 260 rules
/// 259 were of that kind, so a naive "ghost everything" closed the oracle on ONE
/// path and opened a louder one on the other 259.
///
/// Whiteouts are excluded because a whiteout's whole job is to make a name
/// absent, which is what a hidden reader already sees.
///
/// The rest is decided by asking the engine rather than modelling it: become a
/// uid that IS hidden and look. See [`absent_to`].
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

/// Ask, as `uid`, which of `paths` are ABSENT -- not merely unreadable.
///
/// One fork for the whole list. The child drops privilege and, for each path,
/// answers exactly one byte:
///
///   1  `lstat` failed with ENOENT           -> injected-only, ghostable
///   0  anything else (visible, or EACCES)   -> leave it alone
///
/// EACCES is deliberately NOT treated as absent: see this module's header.
/// `lstat`, not `stat`, so a ghosted symlink is judged on the link itself rather
/// than on whatever it points at.
///
/// Returns `None` if the probe could not run at all, which the caller must treat
/// as "ghost nothing" -- an empty table is the honest state, and a half-filled
/// one is a pattern of its own.
fn absent_to(uid: u32, paths: &[PathBuf]) -> Option<Vec<bool>> {
    if paths.is_empty() {
        return Some(Vec::new());
    }
    // Pre-build the C strings in the PARENT: allocating after fork() in a
    // multi-threaded process is not async-signal-safe. This binary is
    // single-threaded, but the rule costs nothing to keep.
    let cpaths: Vec<std::ffi::CString> = paths
        .iter()
        .map(|p| std::ffi::CString::new(p.as_os_str().as_bytes()).ok())
        .collect::<Option<Vec<_>>>()?;

    let mut fds = [0i32; 2];
    // SAFETY: fds is a 2-element array, which is what pipe(2) writes.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return None;
    }
    let (rd, wr) = (fds[0], fds[1]);

    // SAFETY: fork in a single-threaded process; the child only calls
    // async-signal-safe functions and _exit()s.
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
            // Supplementary groups FIRST, then gid, then uid -- each step needs
            // the privilege the next one drops. Without setgroups the child
            // keeps root's group list and a path reachable through one of those
            // groups reads as VISIBLE here and absent for a real app, which is
            // the safe direction (we ghost less) but still wrong.
            //
            // Skipped when we ARE the target uid: there is nothing to drop, and
            // setgroups() needs CAP_SETGID, so attempting it unprivileged would
            // abort a probe that is already running with exactly the identity it
            // wanted. In production this branch never fires -- the caller is
            // root and the target is an app uid.
            if libc::getuid() != uid
                && (libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setresgid(uid, uid, uid) != 0
                    || libc::setresuid(uid, uid, uid) != 0)
            {
                libc::_exit(3);
            }
            for c in &cpaths {
                let mut st: libc::stat = std::mem::zeroed();
                // ENOENT specifically, NOT "lstat failed". EACCES must not be
                // read as absence -- see this module's header. `last_os_error`
                // only wraps the errno value for the Os variant, so it neither
                // allocates nor locks, which is what makes it usable here.
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

    // SAFETY: parent side; rd is ours, wr belongs to the child.
    unsafe { libc::close(wr) };
    let mut f = unsafe { <std::fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(rd) };
    let mut buf = Vec::with_capacity(paths.len());
    let read_ok = f.read_to_end(&mut buf).is_ok();
    drop(f);

    let mut status: i32 = 0;
    // SAFETY: pid came from fork() above and has not been waited on.
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    let exited_clean = waited >= 0
        && libc::WIFEXITED(status)
        && libc::WEXITSTATUS(status) == 0;

    if !read_ok || !exited_clean || buf.len() != paths.len() {
        return None;
    }
    Some(buf.into_iter().map(|b| b == 1).collect())
}

/// Push a whole table in as few netlink commands as possible.
///
/// The FIRST command is `p=` / `u=`, which clears and refills under one
/// acquisition of the kernel's lock, so no reader can observe an intermediate
/// table. Continuations are `p+` / `u+`. A rule set that fits one payload -- a
/// real 260-rule device does -- is therefore a single atomic replace; one that
/// does not narrows the window to the chunk boundary instead of the hundreds of
/// separate commands this used to be.
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
            // CLEAR FIRST if this was the replace chunk. The likeliest reason a
            // `p=` is refused is not a bad rule -- it is a kernel whose ghost.c
            // predates the opcode and rejects the MODE. The builders choose
            // `nomount_ref` and `patches_ref` independently, so a Suite newer
            // than the kernel's _ghost is a supported pairing; falling straight
            // through to `+` there would APPEND to the previous sync's table
            // instead of replacing it, and a stale entry is exactly what this
            // module exists to remove. Every ghost.c ever shipped understands
            // `-`, so the clear is safe on both.
            if replacing {
                let _ = nm.ghost_ctl(&format!("{kind}-"));
                match kind {
                    'p' => out.paths = 0,
                    _ => out.uids = 0,
                }
            }
            // The kernel reports the FIRST error and still applies the rest, so
            // a refused chunk is not a lost chunk -- but we cannot tell which
            // entry it refused from one status. Re-send one at a time: at this
            // point we are already in the unhappy path and correctness of the
            // report matters more than the extra commands.
            for it in chunk.iter() {
                let one = format!("{}+{}", kind, it);
                if nm.ghost_ctl(&one).is_ok() {
                    match kind {
                        'p' => out.paths += 1,
                        _ => out.uids += 1,
                    }
                } else {
                    out.rejected += 1;
                    if out.rejected_examples.len() < 3 {
                        out.rejected_examples.push((*it).to_string());
                    }
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

    // An empty desired set still has to CLEAR the table: leaving the previous
    // one behind is precisely the staleness this module exists to end.
    if first {
        let _ = nm.ghost_ctl(&format!("{kind}-"));
    }
}

/// Re-derive both `_ghost` tables from the live rule set and the hide list.
///
/// Returns `Ok(None)` when `_ghost` is not present in this kernel (or the engine
/// is older than v26), which is not an error: the whole feature is inert there
/// and the caller should say nothing.
pub fn sync(nm: &Nm) -> Result<Option<Summary>> {
    if !nm.ghost_present() {
        return Ok(None);
    }
    let mut out = Summary::default();

    // The uid table is exactly the set per-UID hiding already uses, read from
    // the cache the hide pass writes. Deriving it a second way is how the two
    // would drift, and a uid in one table but not the other is a path that is
    // hidden by the engine and not cloaked by _ghost.
    let mut uids: Vec<u32> = crate::blocklist::cache_read()
        .values()
        .map(|u| crate::blocklist::appid(*u))
        .filter(|u| *u != 0) // root is never hidden from
        .collect();
    uids.sort_unstable();
    uids.dedup();

    // A FAILED dump is not an empty rule set, and the difference decides whether
    // the tables are cleared. `nm list` exits 4 on a truncated dump precisely so
    // a caller can tell a prefix from the whole set (the contract is stated in
    // userspace/src/nm.c), and acting on a prefix would ghost some paths and not
    // others -- the half-populated state ghost.c calls worse than an empty one.
    //
    // So: clear both tables and say so. That is the fail-OPEN direction the whole
    // design is asymmetric towards -- the oracles reopen, which is exactly the
    // unpatched kernel's behaviour, where a stale table can make one path answer
    // stat=OK and chmod=ENOENT at once.
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

    // Fail-safe by construction: with no hidden uid there is nothing to probe
    // WITH, and with nothing to probe with the honest table is the empty one.
    let ghostable: Vec<String> = match uids.first() {
        Some(&probe) => match absent_to(probe, &cands) {
            Some(mask) => cands
                .iter()
                .zip(mask)
                .filter(|(_, absent)| *absent)
                .filter_map(|(p, _)| p.to_str().map(str::to_owned))
                .collect(),
            None => Vec::new(),
        },
        None => Vec::new(),
    };
    out.ghostable = ghostable.len();

    push(nm, 'p', &ghostable, &mut out);
    let uid_strs: Vec<String> = uids.iter().map(u32::to_string).collect();
    push(nm, 'u', &uid_strs, &mut out);
    Ok(Some(out))
}

/// `sync`, plus the one line a boot script or the WebUI should see. Kept apart
/// from [`sync`] so the pass that runs after `mount`/`reload` can stay quiet on
/// the happy path while `nomount ghost sync` always says something.
pub fn run_sync(verbose: bool) -> Result<()> {
    let nm = Nm::new();
    match sync(&nm)? {
        None => {
            if verbose {
                println!(
                    "nomount ghost: this kernel has no _ghost support (or the engine is below v26) -- nothing to populate"
                );
            }
            Ok(())
        }
        Some(s) => {
            if s.dump_failed {
                println!(
                    "nomount ghost: ⚠ could not read the live rule set -- both tables CLEARED, so the existence oracles are open until the next successful sync"
                );
            } else if s.rejected > 0 {
                println!(
                    "nomount ghost: ⚠ {} of {} path(s) REFUSED by the kernel -- the existence oracles stay open for those{}{}",
                    s.rejected,
                    s.ghostable,
                    if s.rejected_examples.is_empty() { "" } else { "; first: " },
                    s.rejected_examples.join(" ")
                );
            } else if !s.effective() {
                println!(
                    "nomount ghost: inert -- {} path(s), {} uid(s) (BOTH tables must be non-empty for any guard to fire)",
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

/// Called at the end of `mount` and `reload`. Never fails the pass: a rule set
/// that is live but not yet cloaked is the state this whole module exists to
/// improve on, and it is strictly better than a boot that aborted.
pub fn sync_after_pass(nm: &Nm) {
    match sync(nm) {
        Ok(Some(s)) if s.dump_failed => println!(
            "nomount: ⚠ ghost cloak: could not read the live rule set -- tables cleared, oracles open"
        ),
        Ok(Some(s)) if s.rejected > 0 => println!(
            "nomount: ⚠ ghost cloak: {} of {} path(s) refused -- existence oracles stay open for those",
            s.rejected, s.ghostable
        ),
        Ok(Some(s)) if s.paths > 0 => {
            println!("nomount: ghost cloak re-synced ({} paths, {} uids)", s.paths, s.uids)
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three exclusions, in the one place they are decided. Getting any of
    /// them wrong ghosts a path the engine intends a hidden reader to SEE, which
    /// is the "apps break" direction the design is asymmetric against.
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

    /// A target containing " (" survives. The shell this replaced cut the line
    /// at the first one with sed, so `/product/app/Foo (2)/x.apk` was submitted
    /// as `/product/app/Foo` -- a different path, and one that could be a real
    /// directory.
    #[test]
    fn candidates_keep_a_target_containing_a_bracket() {
        let list = "/product/app/Foo (2)/x.apk -> /data/adb/modules/M/x.apk\n";
        assert_eq!(candidates(list), vec![PathBuf::from("/product/app/Foo (2)/x.apk")]);
    }

    /// Duplicates collapse and relative junk is dropped, so a malformed dump
    /// cannot inflate the count the report prints.
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

    /// The probe must answer "absent" for a path that is not there and "present"
    /// for one that is -- as the CURRENT uid, which is the only uid a test can
    /// become without privilege.
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
}
