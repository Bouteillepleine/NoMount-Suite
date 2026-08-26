//! What the audit remembers between runs.
//!
//! Every run used to be the first run. The report said "2 detectable" whether
//! that had appeared ten seconds ago after a module install or had been true
//! since the day the Suite went on, and those are different problems with
//! different urgency — so both read as equally alarming, which is the same
//! flattening the verdict split fixed one level down.
//!
//! Three things are remembered, and each answers a question a reader actually
//! asks:
//!
//!   * **Has anything changed?** A signature over the open findings. When it
//!     matches the last run, the report can say "unchanged since <date>" instead
//!     of re-litigating the same list. This is the calming one.
//!   * **Is this new?** First-seen time per finding, keyed on the finding AND its
//!     evidence. A finding that comes back after being fixed is genuinely new
//!     again, and is treated that way.
//!   * **How long has it been fine?** Consecutive clean boots. One counter, and
//!     it says more about whether a setup is stable than any single run can.
//!
//! Deliberately NOT a trend graph or a score. Those invent precision the
//! measurements do not have; a "73/100 stealth score" would be a fabricated
//! number, and once it exists people optimise it instead of reading the findings.
//!
//! Best-effort throughout: a history that cannot be read or written must never
//! fail an audit. Absent history simply means the report says less.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

const STORE: &str = "/data/adb/nomount/audit-history.json";

pub struct Seen {
    pub fingerprint: String,
    pub first_seen: i64,
}

#[derive(Default)]
pub struct History {
    /// Boot this history was last updated in. Counters move once per boot, not
    /// once per run -- a user pressing the button five times has not survived
    /// five boots.
    pub boot_id: String,
    /// Consecutive boots whose audit found nothing open.
    pub clean_boots: u32,
    /// Boots the audit has run in at all, so "9 of 9" can be stated rather than
    /// "9" with no denominator.
    pub total_boots: u32,
    /// Did THIS boot already count as clean? Lets a later run in the same boot
    /// break the streak without double-counting the boot.
    pub this_boot_clean: bool,
    /// Signature over the open findings, and when it last changed.
    pub signature: String,
    pub changed_at: i64,
    /// check id -> what was seen and when it first appeared.
    pub seen: BTreeMap<String, Seen>,
}

fn store() -> PathBuf {
    PathBuf::from(STORE)
}

/// Minimal reader for the shape [`save`] writes. Deliberately not a general JSON
/// parser: this file is written by us, on this device, and a hand-edited or
/// corrupt one should degrade to "no history" rather than pull in a parser and a
/// class of failures with it.
fn field<'a>(s: &'a str, key: &str) -> Option<&'a str> {
    let pat = format!("\"{key}\":");
    let i = s.find(&pat)? + pat.len();
    let rest = s[i..].trim_start();
    if let Some(r) = rest.strip_prefix('"') {
        let end = r.find('"')?;
        Some(&r[..end])
    } else {
        let end = rest.find([',', '}']).unwrap_or(rest.len());
        Some(rest[..end].trim())
    }
}

pub fn load() -> History {
    let Ok(txt) = fs::read_to_string(store()) else { return History::default() };
    let mut h = History {
        boot_id: field(&txt, "boot_id").unwrap_or_default().to_string(),
        clean_boots: field(&txt, "clean_boots").and_then(|v| v.parse().ok()).unwrap_or(0),
        total_boots: field(&txt, "total_boots").and_then(|v| v.parse().ok()).unwrap_or(0),
        this_boot_clean: field(&txt, "this_boot_clean").map(|v| v == "true").unwrap_or(false),
        signature: field(&txt, "signature").unwrap_or_default().to_string(),
        changed_at: field(&txt, "changed_at").and_then(|v| v.parse().ok()).unwrap_or(0),
        seen: BTreeMap::new(),
    };
    // "findings":[{"check":"..","fingerprint":"..","first_seen":N}, ...]
    if let Some(i) = txt.find("\"findings\":") {
        for chunk in txt[i..].split("{\"check\":").skip(1) {
            let obj = format!("{{\"check\":{chunk}");
            let (Some(c), Some(fp)) = (field(&obj, "check"), field(&obj, "fingerprint")) else {
                continue;
            };
            let first = field(&obj, "first_seen").and_then(|v| v.parse().ok()).unwrap_or(0);
            h.seen.insert(c.to_string(), Seen { fingerprint: fp.to_string(), first_seen: first });
        }
    }
    h
}

pub fn save(h: &History) {
    use crate::json::J;
    let doc = J::Obj(vec![
        ("version", J::Num(1)),
        ("boot_id", J::s(&h.boot_id)),
        ("clean_boots", J::Num(h.clean_boots as i64)),
        ("total_boots", J::Num(h.total_boots as i64)),
        ("this_boot_clean", J::Bool(h.this_boot_clean)),
        ("signature", J::s(&h.signature)),
        ("changed_at", J::Num(h.changed_at)),
        (
            "findings",
            J::Arr(
                h.seen
                    .iter()
                    .map(|(k, v)| {
                        J::Obj(vec![
                            ("check", J::s(k)),
                            ("fingerprint", J::s(&v.fingerprint)),
                            ("first_seen", J::Num(v.first_seen)),
                        ])
                    })
                    .collect(),
            ),
        ),
    ]);
    let p = store();
    if fs::write(&p, doc.render()).is_ok() {
        let _ = fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    }
}

pub fn boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Signature over the OPEN findings only.
///
/// Accepted ones are excluded on purpose: accepting something is the user
/// saying "stop telling me", and letting it keep the signature churning would
/// undo that. Passes and n/a are excluded because a check that starts applying
/// (you hid your first app) is not a change the reader needs alarming about.
pub fn signature(open: &[(String, String)]) -> String {
    let mut v: Vec<String> = open.iter().map(|(id, fp)| format!("{id}:{fp}")).collect();
    v.sort();
    crate::json::fingerprint(&v.join("|"))
}

/// Fold this run into the history and return the updated record.
///
/// `open` is (check id, evidence fingerprint) for every finding that is failing
/// and not accepted.
/// `boot` is passed in rather than read here, so this stays a pure function of
/// its inputs and the boot-boundary behaviour is testable at all. Reading
/// /proc/sys/kernel/random/boot_id inside made every test see the HOST's real
/// boot id, so "same boot" could never be exercised.
/// `assessable` is false when the run could not actually measure — any check
/// came back `Unmeasured`. Such a boot must NOT touch the streak in either
/// direction.
///
/// This was the streak's one false green, and it was the worst kind: the streak
/// is the single number in the whole report with no evidence printed beside it,
/// so nothing on screen contradicts it. `open` is built from Fail|Reboot only,
/// so a boot where /proc/self/mountinfo would not open — every mount check
/// Unmeasured, every target check n/a because the rule list came back empty —
/// produced `open.is_empty()`, incremented the counter, and printed
/// "clean on the last 9 of 9 boots" over a boot in which nothing was read.
///
/// Not counting it at all is the honest third state: the streak means "boots
/// that were checked and were clean", so a boot that could not be checked is
/// not a member of either set.
pub fn update(
    mut h: History,
    open: &[(String, String)],
    now: i64,
    boot: &str,
    assessable: bool,
) -> History {
    let new_boot = !boot.is_empty() && boot != h.boot_id;
    let clean = open.is_empty();

    if new_boot && assessable {
        h.boot_id = boot.to_string();
        h.total_boots = h.total_boots.saturating_add(1);
        h.clean_boots = if clean { h.clean_boots.saturating_add(1) } else { 0 };
        h.this_boot_clean = clean;
    } else if new_boot {
        // Remember the boot so a later, assessable run in the same boot is not
        // mistaken for a new one -- but leave both counters untouched.
        h.boot_id = boot.to_string();
        h.this_boot_clean = false;
    } else if !clean && h.this_boot_clean {
        // A later run in the same boot found something the boot pass did not.
        // The boot was not clean after all: take it back rather than let the
        // streak claim a boot that had a finding in it.
        h.clean_boots = 0;
        h.this_boot_clean = false;
    }

    let sig = signature(open);
    if sig != h.signature {
        h.signature = sig;
        h.changed_at = now;
    }

    // First-seen, keyed on the EVIDENCE as well as the check: a finding that was
    // fixed and came back is new again, and one whose evidence grew ("1 mount"
    // -> "3 mounts") is a different situation than the one first recorded.
    let mut next: BTreeMap<String, Seen> = BTreeMap::new();
    for (id, fp) in open {
        let first = match h.seen.get(id) {
            Some(prev) if &prev.fingerprint == fp => prev.first_seen,
            _ => now,
        };
        next.insert(id.clone(), Seen { fingerprint: fp.clone(), first_seen: first });
    }
    h.seen = next;
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h0() -> History {
        History { boot_id: "boot-a".into(), ..Default::default() }
    }
    fn f(id: &str, fp: &str) -> (String, String) {
        (id.to_string(), fp.to_string())
    }

    /// The streak counts BOOTS, not runs. Pressing the button five times in one
    /// boot has not survived five boots.
    #[test]
    fn the_streak_moves_once_per_boot() {
        let mut h = h0();
        h.boot_id = "boot-a".into();
        // Same boot as stored -> no counter movement.
        h = update(h, &[], 100, "boot-a", true);
        assert_eq!(h.total_boots, 0);
        assert_eq!(h.clean_boots, 0);
    }

    /// A NEW boot advances both counters; a clean one extends the streak and a
    /// dirty one resets it.
    #[test]
    fn a_new_boot_advances_the_streak() {
        let mut h = h0();
        h.clean_boots = 4;
        h.total_boots = 4;
        h = update(h, &[], 100, "boot-b", true);
        assert_eq!((h.total_boots, h.clean_boots), (5, 5));
        h = update(h, &[f("rom-tmpfs", "x")], 200, "boot-c", true);
        assert_eq!((h.total_boots, h.clean_boots), (6, 0), "a finding resets the streak");
    }

    /// A boot that could not be measured is not a clean boot.
    #[test]
    fn an_unassessable_boot_does_not_extend_the_streak() {
        let mut h = h0();
        h.clean_boots = 9;
        h.total_boots = 9;
        // New boot, nothing open -- but nothing measurable either.
        h = update(h, &[], 100, "boot-z", false);
        assert_eq!((h.total_boots, h.clean_boots), (9, 9), "neither counter moves");
        assert!(!h.this_boot_clean, "and the boot is not banked as clean");
        // A later run in the same boot that CAN measure still counts it.
        h = update(h, &[], 200, "boot-z", true);
        assert_eq!((h.total_boots, h.clean_boots), (9, 9), "same boot, already seen");
    }

    /// A finding whose evidence is unchanged keeps its original first-seen, so
    /// "here since Tuesday" stays true across reboots.
    #[test]
    fn an_unchanged_finding_keeps_its_first_seen() {
        let mut h = h0();
        h = update(h, &[f("rom-tmpfs", "aaaa")], 100, "boot-a", true);
        assert_eq!(h.seen["rom-tmpfs"].first_seen, 100);
        h = update(h, &[f("rom-tmpfs", "aaaa")], 500, "boot-a", true);
        assert_eq!(h.seen["rom-tmpfs"].first_seen, 100, "still the original sighting");
    }

    /// ...but evidence that MOVED is a new situation, and dates from now.
    #[test]
    fn changed_evidence_restarts_the_clock() {
        let mut h = h0();
        h = update(h, &[f("rom-tmpfs", "aaaa")], 100, "boot-a", true);
        h = update(h, &[f("rom-tmpfs", "bbbb")], 500, "boot-a", true);
        assert_eq!(h.seen["rom-tmpfs"].first_seen, 500);
    }

    /// A finding that is fixed leaves the record, so if it returns it is new.
    #[test]
    fn a_fixed_finding_is_forgotten_and_returns_as_new() {
        let mut h = h0();
        h = update(h, &[f("rom-tmpfs", "aaaa")], 100, "boot-a", true);
        h = update(h, &[], 200, "boot-a", true);
        assert!(h.seen.is_empty());
        h = update(h, &[f("rom-tmpfs", "aaaa")], 300, "boot-a", true);
        assert_eq!(h.seen["rom-tmpfs"].first_seen, 300);
    }

    /// The signature only moves when the OPEN set moves -- that is what lets the
    /// report say "unchanged since" instead of re-listing every run.
    #[test]
    fn the_signature_is_stable_while_the_findings_are() {
        let mut h = h0();
        h = update(h, &[f("a", "1"), f("b", "2")], 100, "boot-a", true);
        let at = h.changed_at;
        // Same findings, different order: same signature.
        h = update(h, &[f("b", "2"), f("a", "1")], 900, "boot-a", true);
        assert_eq!(h.changed_at, at, "reordering is not a change");
        h = update(h, &[f("a", "1")], 950, "boot-a", true);
        assert_eq!(h.changed_at, 950, "losing one IS a change");
    }

    /// A later run in the same boot that finds something must take back the
    /// clean boot, not leave the streak claiming a boot that had a finding.
    #[test]
    fn a_finding_later_in_the_same_boot_breaks_the_streak() {
        let mut h = h0();
        h.this_boot_clean = true;
        h.clean_boots = 9;
        h = update(h, &[f("rom-tmpfs", "aaaa")], 100, "boot-a", true);
        assert_eq!(h.clean_boots, 0);
        assert!(!h.this_boot_clean);
    }

    /// The reader must survive a truncated or hand-edited file.
    #[test]
    fn a_corrupt_store_reads_as_no_history() {
        assert_eq!(field("{\"clean_boots\":", "clean_boots"), Some(""));
        assert_eq!(field("not json at all", "clean_boots"), None);
        assert_eq!(field("{\"boot_id\":\"xyz\"}", "boot_id"), Some("xyz"));
        assert_eq!(field("{\"clean_boots\":9,\"x\":1}", "clean_boots"), Some("9"));
    }
}
