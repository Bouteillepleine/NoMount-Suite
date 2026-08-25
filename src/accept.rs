//! Findings the user has looked at and decided to live with.
//!
//! Some findings are permanent by design on a given setup. An LSPosed user will
//! always carry a `dex2oat` bind, because absorb deliberately never takes it
//! over -- breaking a hook framework surfaces hours later during dexopt, not at
//! boot. Someone running ReVanced through its own installer has chosen the tmpfs
//! it mounts over `/product/app`. Both are real, both are visible to any app, and
//! neither has a fix the Suite can apply.
//!
//! Before this file those rendered as a red chip forever, and a permanently red
//! chip is one the reader learns to ignore -- which is strictly worse than no
//! chip, because it also hides the NEXT finding.
//!
//! The rule this must not break is the one the rest of the project spent dozens
//! of commits enforcing: never a false green. So an acceptance:
//!
//!   * never changes a verdict. The JSON still says `"verdict":"fail"`, and the
//!     human output still prints FAIL. Only an `accepted` flag is added.
//!   * renders GREY, never green. "1 accepted" is a different word from "clean"
//!     and the summary keeps counting it separately.
//!   * is bound to the EVIDENCE it was granted for, by fingerprint. Accepting
//!     "1 module mount: dex2oat64" does not accept "2 module mounts" later --
//!     the fingerprint moves and the finding comes back at full severity.
//!   * requires a reason, which is stored and shown. An acceptance nobody can
//!     explain six months later is indistinguishable from a bug being ignored.

use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Result};

fn store() -> PathBuf {
    PathBuf::from("/data/adb/nomount/accepted.txt")
}

pub struct Acceptance {
    pub check: String,
    /// Fingerprint of the evidence at the time it was accepted.
    pub fingerprint: String,
    /// Unix seconds. 0 when the clock was unreadable -- recorded as 0 rather
    /// than as "now" so a bogus timestamp is visibly bogus.
    pub when: u64,
    pub reason: String,
}

/// Tab-separated, because a reason is free text and every other separator this
/// project uses appears inside real reasons. A tab does not: the CLI rejects one
/// in [`add`].
fn parse(txt: &str) -> Vec<Acceptance> {
    let mut out = Vec::new();
    for line in txt.lines() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(4, '\t');
        let (Some(check), Some(fp), Some(when), Some(reason)) =
            (it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        out.push(Acceptance {
            check: check.to_string(),
            fingerprint: fp.to_string(),
            when: when.parse().unwrap_or(0),
            reason: reason.to_string(),
        });
    }
    out
}

pub fn load() -> Vec<Acceptance> {
    parse(&fs::read_to_string(store()).unwrap_or_default())
}

/// The acceptance covering this exact finding, if any.
///
/// Matching on BOTH id and fingerprint is the whole safety property: an
/// acceptance is a statement about one measured state, not a permanent mute on a
/// check.
pub fn covering<'a>(
    list: &'a [Acceptance],
    check: &str,
    fingerprint: &str,
) -> Option<&'a Acceptance> {
    list.iter().find(|a| a.check == check && a.fingerprint == fingerprint)
}

/// An acceptance for this check whose fingerprint no longer matches -- i.e. the
/// user accepted something here once and the evidence has since moved.
///
/// Surfaced rather than silently ignored: "you accepted this when it said X, it
/// now says Y" is the single most useful line the report can print about a
/// finding that came back.
pub fn stale<'a>(
    list: &'a [Acceptance],
    check: &str,
    fingerprint: &str,
) -> Option<&'a Acceptance> {
    list.iter().find(|a| a.check == check && a.fingerprint != fingerprint)
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_all(list: &[Acceptance]) -> Result<()> {
    let mut s = String::from(
        "# NoMount Suite — accepted findings (managed by `nomount accept`)\n\
         # <check-id>\\t<evidence-fingerprint>\\t<unix-seconds>\\t<reason>\n\
         # An acceptance never turns a finding green. It records that you looked\n\
         # at it and decided to live with it, and it lapses if the evidence moves.\n",
    );
    for a in list {
        let _ = writeln!(s, "{}\t{}\t{}\t{}", a.check, a.fingerprint, a.when, a.reason);
    }
    let p = store();
    fs::write(&p, s)?;
    // 0600, matching every other file in the state directory. `fs::write` creates
    // at 0666 & ~umask, and this can run from the WebUI's exec where the umask is
    // whatever ksud left -- the 0700 parent is not a property to depend on.
    //
    // The SELinux label needs no help here: a file created by a root process
    // inherits its parent's type, so this lands `adb_data_file` like the rest of
    // the directory. It is `set_perm` in customize.sh that has to name the
    // context explicitly, because that call OVERRIDES the inherited label with
    // `system_file` when the argument is omitted.
    let _ = fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    Ok(())
}

pub fn add(check: &str, fingerprint: &str, reason: &str) -> Result<()> {
    let reason = reason.trim();
    if reason.is_empty() {
        bail!("a reason is required: an acceptance nobody can explain later is indistinguishable from a bug being ignored");
    }
    if check.contains('\t') || reason.contains('\t') || reason.contains('\n') {
        bail!("check id and reason must not contain a tab or newline (the store is tab-separated)");
    }
    let mut list = load();
    // One acceptance per check. Re-accepting after the evidence moved REPLACES
    // the old row rather than stacking, so the store cannot grow a history of
    // fingerprints that no longer mean anything.
    list.retain(|a| a.check != check);
    list.push(Acceptance {
        check: check.to_string(),
        fingerprint: fingerprint.to_string(),
        when: now(),
        reason: reason.to_string(),
    });
    list.sort_by(|a, b| a.check.cmp(&b.check));
    write_all(&list)
}

pub fn remove(check: &str) -> Result<bool> {
    let mut list = load();
    let before = list.len();
    list.retain(|a| a.check != check);
    if list.len() == before {
        return Ok(false);
    }
    write_all(&list)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reason_with_spaces_and_colons_round_trips() {
        let v = parse("zero-mount\tdeadbeefdeadbeef\t1756000000\tLSPosed: I want the hook, it is by design\n");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].check, "zero-mount");
        assert_eq!(v[0].when, 1_756_000_000);
        assert_eq!(v[0].reason, "LSPosed: I want the hook, it is by design");
    }

    /// Comments, blank lines and CRLF (the store is edited by hand often enough).
    #[test]
    fn junk_lines_are_skipped_not_fatal() {
        let v = parse("# header\r\n\r\nbad-line-no-tabs\r\na\tb\t1\tc\r\n");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].check, "a");
    }

    /// The safety property: an acceptance covers ONE measured state.
    #[test]
    fn an_acceptance_lapses_when_the_evidence_moves() {
        let list = parse("zero-mount\taaaaaaaaaaaaaaaa\t1\tby design\n");
        assert!(covering(&list, "zero-mount", "aaaaaaaaaaaaaaaa").is_some());
        assert!(covering(&list, "zero-mount", "bbbbbbbbbbbbbbbb").is_none());
        // ...and the lapsed one is still findable, so the report can say so.
        assert!(stale(&list, "zero-mount", "bbbbbbbbbbbbbbbb").is_some());
        assert!(stale(&list, "zero-mount", "aaaaaaaaaaaaaaaa").is_none());
    }

    /// A different check is never covered by another's acceptance.
    #[test]
    fn acceptances_do_not_bleed_between_checks() {
        let list = parse("zero-mount\taaaaaaaaaaaaaaaa\t1\tby design\n");
        assert!(covering(&list, "rom-tmpfs", "aaaaaaaaaaaaaaaa").is_none());
        assert!(stale(&list, "rom-tmpfs", "zzzzzzzzzzzzzzzz").is_none());
    }
}
