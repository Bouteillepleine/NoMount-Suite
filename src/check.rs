//! `nomount check` — the one diagnostic verb, and the one shape it answers in.
//!
//! There used to be seven: `doctor`, `audit`, `posture`, `selfcheck`, `snapshot`,
//! `verify` and `plan`. They carried two competing verdict enums (`doctor::Level`
//! with Error/Warn/Info, `audit::Verdict` with Pass/Fail/Reboot/N-A/Unmeasured),
//! three JSON shapes and a fourth key=value one, and `health`'s answers were
//! stringly typed on top of that ("ok" | "mismatch:<path>(...)" | "unchecked").
//! The tell was in the WebUI: `mergeFindings` existed only to normalise three
//! report shapes into one list in JavaScript, because one list is what a reader
//! wants. `posture` was pure duplication — a strict subset of `audit`'s checks —
//! and is gone for good. `plan` was cut on the same reasoning and it was WRONG:
//! it had no caller in this repo, which is not the same as no caller. The module
//! test harness parses its output to lint a staged module before it is ever
//! applied, and nothing else can do that, so `plan` is back.
//!
//! What is NOT collapsed is the distinction that earns its keep:
//!
//!   PLAN    — will the module set produce a bad rule? Resolved off the module
//!             tree and the live rule list. Cheap (128 ms against 1217 ms for
//!             `--device`, measured on an OP15) and safe to run at post-fs-data
//!             before anything else exists — because it runs no `su` probe and
//!             does not walk the ROM, NOT because it touches nothing live. A
//!             handful of its rows do ask the engine and the kernel; see
//!             [`Section::Plan`].
//!   DEVICE  — is what we serve actually detectable, and is it being served? Every
//!             answer here is MEASURED on this device, and several need running
//!             processes, so the result depends on WHEN it is asked.
//!
//! That is a `--plan` / `--device` selector within one command and one output
//! shape, not two commands with two shapes. Neither flag runs both.
//!
//! Both written artifacts are produced from [`Report`] and nothing else, so there
//! is no second serialisation to drift from the first: `audit.json` is this
//! report's JSON, and `health.txt` is its facts rendered as key=value.


use anyhow::Result;

use crate::json::J;

/// Where a check comes from, and therefore what its answer depends on.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Section {
    /// Resolved from the module tree and the rule list, so the answer is stable
    /// as far as the module set goes.
    ///
    /// It is NOT "no running process is involved", which is what this said and
    /// what `Report::text`'s header repeated. `doctor::plan_checks` asks the live
    /// engine for its version, its rule list and its ghost list, execs `ksud` to
    /// read the kernel-umount setting, reads `/proc/self/mountinfo`, walks other
    /// processes' mount namespaces, and forks up to sixteen times dropping to a
    /// hidden appid to `stat` the device. One of those rows prints "Measured
    /// here, not assumed from the build" one line under the header, which is how
    /// the contradiction was found. What makes `--plan` cheap (128 ms against
    /// 1217 ms for `--device`, measured on an OP15) is that it runs no `su`
    /// probe and does not walk the ROM -- not that it touches nothing live.
    Plan,
    /// Measured on this device, now. Some of these need a process to have opened
    /// an injected file, which is why they can honestly report `Unmeasured`.
    Device,
}

impl Section {
    pub fn slug(self) -> &'static str {
        match self {
            Section::Plan => "plan",
            Section::Device => "device",
        }
    }
}

/// The single verdict. One enum, seven states, and every one of them was already
/// being expressed somewhere -- the old pair just could not express all seven at
/// once, so each half approximated the other's states with its own.
///
/// Declaration order is REPORT order: worst first. `#[derive(Ord)]` gives that
/// for free, and sorting on the enum itself means the order can never drift from
/// the meaning the way a separate rank table did.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    /// Measured, and it is wrong. Was `audit::Verdict::Fail` and `doctor`'s
    /// `Level::Error` -- which were the same severity all along.
    Fail,
    /// Real, but already cured: a reboot applies the fix that is pending.
    Reboot,
    /// The check COULD have applied and did not run. Mountinfo unreadable, a
    /// fork that failed, no process yet holding an injected file. Amber, never
    /// green: reporting an unrun check as clean is how a hole survives.
    Unmeasured,
    /// Something worth knowing that is not a failure, and that the reader should
    /// do something about. In practice that is a hazard in the plan: nothing has
    /// gone wrong yet, something will, and the module set is the reader's to
    /// change.
    ///
    /// The line is: WARN = a shipping detector can see this today AND there is
    /// something the reader should change. Both halves. Stated as the first half
    /// alone, the rule pulls `audit::check_zero_mount`'s two by-design bind arms
    /// back up here -- a hook framework's binds and the Suite's own `my_*` binds,
    /// which ARE visible in every app's mountinfo and are staying, on purpose, on
    /// the default configuration. Both are Notes, deliberately; see `audit::soft`
    /// for the measurement.
    Warn,
    /// Measured, and it holds.
    Pass,
    /// Does not apply to THIS device or THIS configuration, and no arrangement of
    /// the two would make it apply as things stand. Grey, never amber, and never
    /// counted as a pass.
    NotApplicable,
    /// Worth printing, not worth acting on. A standing observation about a
    /// working configuration, and where `audit::soft` lands: a real, measured
    /// inconsistency that NOTHING SHIPPING PROBES. It keeps its oracle string and
    /// stays in `audit.json` and in `nomount check`'s text output as an engine
    /// regression canary; it is not put in front of a user as something to fix.
    ///
    /// The line is: NOTE = either nothing looks at it, or nothing about it should
    /// be changed. The second clause is what `audit::check_zero_mount`'s two
    /// by-design bind arms land on -- real mounts a detector can see, that the
    /// Suite declines to remove on purpose. The WebUI renders notes in a
    /// collapsed "Good to know" disclosure, so this is quiet, not silent.
    Note,
}

impl Verdict {
    pub fn slug(self) -> &'static str {
        match self {
            Verdict::Fail => "fail",
            Verdict::Reboot => "reboot",
            Verdict::Unmeasured => "unmeasured",
            Verdict::Warn => "warn",
            Verdict::Pass => "pass",
            Verdict::NotApplicable => "n/a",
            Verdict::Note => "note",
        }
    }
    pub fn tag(self) -> &'static str {
        match self {
            Verdict::Fail => "FAIL",
            Verdict::Reboot => "REBOOT",
            Verdict::Unmeasured => "UNMEASURED",
            Verdict::Warn => "WARN",
            Verdict::Pass => "PASS",
            Verdict::NotApplicable => "N/A",
            Verdict::Note => "NOTE",
        }
    }
    /// The coarse axis the ONE findings list sorts and colours on.
    ///
    /// Deliberately coarser than the verdict: a plan warning and a measured
    /// failure both mean "look at this", and the row already says which by name.
    /// This used to be computed in JavaScript for doctor rows and not at all for
    /// audit rows, which is why the two could not share a list without a merge
    /// step.
    pub fn severity(self) -> &'static str {
        match self {
            Verdict::Fail | Verdict::Reboot | Verdict::Warn => "attention",
            Verdict::Unmeasured => "unmeasured",
            Verdict::Pass => "ok",
            Verdict::NotApplicable | Verdict::Note => "info",
        }
    }
}

/// One answer, whichever section produced it.
pub struct Check {
    /// Stable slug. This is what an acceptance would be keyed on and what the
    /// WebUI uses for element ids, so it must not change when the display name
    /// does.
    pub id: String,
    pub name: String,
    pub section: Section,
    pub verdict: Verdict,
    /// What was actually read. Always populated, including on a pass -- a bare
    /// "OK" is not evidence.
    pub evidence: String,
    /// One line in the reader's terms, on every verdict. The evidence is written
    /// for whoever is debugging the engine and is good at that job; this field is
    /// for the person who installed a module and wants to know if they are fine.
    pub meaning: String,
    /// What an attacker would do with a failure. Only where there is one.
    pub oracle: Option<String>,
    /// Who caused this: a module id, the kernel, the root manager, the user's own
    /// configuration. A finding without an owner is a finding nobody can close.
    pub owner: Option<String>,
}

impl Check {
    pub fn new(
        section: Section,
        id: impl Into<String>,
        name: impl Into<String>,
        verdict: Verdict,
        evidence: impl Into<String>,
    ) -> Check {
        Check {
            id: id.into(),
            name: name.into(),
            section,
            verdict,
            evidence: evidence.into(),
            meaning: String::new(),
            oracle: None,
            owner: None,
        }
    }
    pub fn meaning(mut self, m: impl Into<String>) -> Check {
        self.meaning = m.into();
        self
    }
    pub fn oracle(mut self, o: impl Into<String>) -> Check {
        self.oracle = Some(o.into());
        self
    }
    pub fn owner(mut self, o: impl Into<String>) -> Check {
        self.owner = Some(o.into());
        self
    }
    fn json(&self) -> J {
        J::Obj(vec![
            ("id", J::s(&self.id)),
            ("name", J::s(&self.name)),
            ("section", J::s(self.section.slug())),
            ("verdict", J::s(self.verdict.slug())),
            ("severity", J::s(self.verdict.severity())),
            ("evidence", J::s(&self.evidence)),
            ("meaning", J::s(&self.meaning)),
            ("oracle", J::os(self.oracle.clone())),
            ("owner", J::os(self.owner.clone())),
        ])
    }
}

/// Turn a display name into a stable id: lowercase, non-alphanumerics collapsed
/// to single hyphens.
///
/// The audit kept a hand-maintained name -> id table and doctor kept none at all,
/// so half the rows in the merged list had no id to key anything on. Deriving it
/// means a new check cannot forget to have one; the cost is that RENAMING a check
/// changes its id, which is the trade the old table was making in the other
/// direction and losing.
pub fn slug(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut hyphen = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.extend(c.to_lowercase());
            hyphen = false;
        } else if !hyphen && !out.is_empty() {
            out.push('-');
            hyphen = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "unnamed-check".to_string()
    } else {
        out
    }
}

/// Counts, one per verdict. No derived states stored -- they are all functions of
/// these seven numbers.
pub struct Tally {
    pub fail: usize,
    pub reboot: usize,
    pub unmeasured: usize,
    pub warn: usize,
    pub pass: usize,
    pub na: usize,
    pub note: usize,
}

impl Tally {
    pub fn of(checks: &[Check]) -> Tally {
        let mut t = Tally { fail: 0, reboot: 0, unmeasured: 0, warn: 0, pass: 0, na: 0, note: 0 };
        for c in checks {
            match c.verdict {
                Verdict::Fail => t.fail += 1,
                Verdict::Reboot => t.reboot += 1,
                Verdict::Unmeasured => t.unmeasured += 1,
                Verdict::Warn => t.warn += 1,
                Verdict::Pass => t.pass += 1,
                Verdict::NotApplicable => t.na += 1,
                Verdict::Note => t.note += 1,
            }
        }
        t
    }
    /// Findings the reader still has to act on. Drives the exit status.
    pub fn open_failures(&self) -> usize {
        self.fail + self.reboot
    }
    /// Did every check that COULD apply actually get measured?
    ///
    /// `open_failures` answers "is there something to act on" and says nothing
    /// about whether the run had anything to look at. That gap is not academic:
    /// the boot pass runs before any app has opened a module file, so its
    /// process-dependent checks are unmeasured by construction -- and the
    /// audit.json it caches is what the module card and the WebUI show as the
    /// device's verdict for the rest of the uptime. A summary rendering
    /// "12 passed, 0 failed" for a run with an unmeasured check is telling its
    /// reader something was verified that was not.
    pub fn complete(&self) -> bool {
        self.unmeasured == 0
    }
    fn json(&self) -> J {
        J::Obj(vec![
            ("fail", J::Num(self.fail as i64)),
            ("reboot", J::Num(self.reboot as i64)),
            ("unmeasured", J::Num(self.unmeasured as i64)),
            ("warn", J::Num(self.warn as i64)),
            ("pass", J::Num(self.pass as i64)),
            ("not_applicable", J::Num(self.na as i64)),
            ("note", J::Num(self.note as i64)),
            ("open_failures", J::Num(self.open_failures() as i64)),
            // The field every cached-verdict reader needs and none of them had: a
            // summary can be free of failures and still not be a clean answer.
            ("complete", J::Bool(self.complete())),
        ])
    }
}

/// One `key=value` row of the fingerprint, or of the plan counts.
pub type Fact = (String, String);

/// A count that may not have been taken. `J::Null`, never `0`.
fn num_or_null(n: Option<usize>) -> J {
    match n {
        Some(v) => J::Num(v as i64),
        None => J::Null,
    }
}

/// Everything one run of `nomount check` produced.
///
/// `facts` is the flat key=value fingerprint of the live system that `health.txt`,
/// `snapshot` and `verify` are all built on. It is data, not verdicts: `uname`,
/// the rule count, whether the engine answered. The verdicts derived from it are
/// in `checks` alongside every other one, which is what stopped `health` needing
/// its own three-way "ok" | "mismatch:..." | "unchecked" string encoding.
pub struct Report {
    pub ts: i64,
    pub engine: Option<u32>,
    /// Live rules, and the directories holding them. `None` means the engine
    /// would not list its rules, which is NOT the same statement as zero -- see
    /// [`Report::text`]'s header for the argument, which the `--plan` arm already
    /// made and this one did not.
    pub rules: Option<usize>,
    pub directories: Option<usize>,
    pub facts: Vec<Fact>,
    pub checks: Vec<Check>,
}

pub const CACHE: &str = "/data/adb/nomount/audit.json";
pub const HEALTH: &str = "/data/adb/nomount/health.txt";

impl Report {
    pub fn tally(&self) -> Tally {
        Tally::of(&self.checks)
    }

    /// Worst first, then by section, then by name -- a stable order, so two runs
    /// of the same device produce a diffable report.
    ///
    /// The one exception is a dead engine, which outranks everything: with it down
    /// every other row is describing a device that is not hiding anything.
    pub fn sort(&mut self) {
        self.checks.sort_by(|a, b| {
            let key = |c: &Check| {
                (
                    !(c.id == "engine-responding" && c.verdict == Verdict::Fail),
                    c.verdict,
                    c.section.slug(),
                    c.name.clone(),
                )
            };
            key(a).cmp(&key(b))
        });
    }

    /// The one-line verdict, in the reader's terms.
    ///
    /// Ordered by what a reader has to do about it. "not fully measured" sits
    /// ABOVE "clean" on purpose: it is not a failure, and it is not a pass either.
    pub fn verdict(&self) -> String {
        let t = self.tally();
        if t.fail > 0 {
            format!("{} check(s) FAILED", t.fail)
        } else if t.reboot > 0 {
            format!("{} check(s) need a reboot to finish", t.reboot)
        // UNMEASURED OUTRANKS WARN, because both enums say it does.
        //
        // `Verdict`'s declaration order is Fail, Reboot, Unmeasured, Warn, and
        // `doctor::Level` mirrors it with a comment insisting the two must agree
        // "or the report and the plan disagree about which line matters more".
        // `Report::sort` honours it — Unmeasured rows print above Warn rows — and
        // this function did not, so a run with four unmeasured checks and one
        // warning rendered `1 plan warning(s)` and the incompleteness vanished
        // from the ONE string `health.txt` carries and `service.sh` logs onto the
        // card. The full `summary:` line said INCOMPLETE; the card reader never
        // sees that line.
        } else if !t.complete() {
            format!(
                "not fully measured ({} check(s) had nothing to look at{})",
                t.unmeasured,
                if t.warn > 0 { format!(", plus {} warning(s)", t.warn) } else { String::new() }
            )
        // NOT "plan warning(s)". `t.warn` counts EVERY Warn in the report, and
        // nothing in the type says a Warn came from the plan; a device row that
        // reached amber made the verdict read "1 plan warning(s)" and pointed the
        // user at a module set that was not the cause. Today `audit.rs` emits no
        // Warn at all -- the four `soft()` engine canaries and both of
        // `check_zero_mount`'s by-design bind arms are Notes -- but the wording
        // must not depend on that staying true.
        } else if t.warn > 0 {
            format!("{} warning(s)", t.warn)
        } else {
            "clean".to_string()
        }
    }

    /// `health.txt` / `snapshot.txt`: the facts as key=value, one per line.
    ///
    /// The ONLY renderer of that format. `health.rs` used to own a `to_text` that
    /// listed every field by hand, and `run_selfcheck`'s `--json` arm then parsed
    /// its own output back apart to build the JSON -- two descriptions of one
    /// shape, and a field added to either could go missing from the other.
    pub fn fingerprint_text(&self) -> String {
        let mut s = String::new();
        for (k, v) in &self.facts {
            s.push_str(k);
            s.push('=');
            s.push_str(v);
            s.push('\n');
        }
        s
    }

    pub fn json(&self) -> String {
        J::Obj(vec![
            // Was "doctor" / "audit" / "posture" / "selfcheck", depending which of
            // the four you had run.
            ("kind", J::s("check")),
            ("ts", J::Num(self.ts)),
            ("suite", J::s(env!("CARGO_PKG_VERSION"))),
            (
                "engine",
                match self.engine {
                    Some(v) => J::Num(v as i64),
                    None => J::Null,
                },
            ),
            // null, not 0, when the rule list could not be read. A consumer that
            // prints `rules || 0` is back where it started, but at least the
            // document no longer asserts a count nobody measured.
            ("rules", num_or_null(self.rules)),
            ("directories", num_or_null(self.directories)),
            // Which sections ran. Without this a cached report is ambiguous: a
            // reader cannot tell "the plan is clean" from "the plan was not
            // looked at", and those are the two answers this file exists to keep
            // apart everywhere else.
            (
                "sections",
                J::Arr(
                    [Section::Plan, Section::Device]
                        .into_iter()
                        .filter(|x| self.ran(*x))
                        .map(|x| J::s(x.slug()))
                        .collect(),
                ),
            ),
            ("verdict", J::s(self.verdict())),
            ("summary", self.tally().json()),
            (
                "facts",
                J::Arr(
                    self.facts
                        .iter()
                        .map(|(k, v)| J::Obj(vec![("key", J::s(k)), ("value", J::s(v))]))
                        .collect(),
                ),
            ),
            ("checks", J::Arr(self.checks.iter().map(Check::json).collect())),
        ])
        .render()
    }

    /// Did this run include the given section?
    ///
    /// Read off the checks rather than carried as a flag, so it cannot disagree
    /// with what is actually in the report.
    pub fn ran(&self, section: Section) -> bool {
        self.checks.iter().any(|c| c.section == section)
    }

    /// The human report. One list, in the order [`Report::sort`] put it.
    pub fn text(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        // The header describes what was MEASURED, so a `--plan` run must not open
        // with "0 live rule(s) ... engine not responding": nobody asked the engine
        // anything, and a zero nobody measured reads exactly like a zero somebody
        // did. That confusion is the whole reason for this pass.
        if self.ran(Section::Device) {
            let engine = match self.engine {
                Some(v) => format!("v{v}"),
                None => "not responding".to_string(),
            };
            // ...and the SAME argument applies inside a device run whose rule dump
            // failed. It printed "0 live rule(s) across 0 directory(ies)", which is
            // a zero nobody measured wearing the clothes of one somebody did. The
            // `engine-rule-dump` FAIL row below says why, but the header is the
            // line that gets grepped and pasted.
            let _ = match (self.rules, self.directories) {
                (Some(r), Some(d)) => writeln!(
                    s,
                    "nomount check: {r} live rule(s) across {d} directory(ies) | engine {engine}\n"
                ),
                _ => writeln!(s, "nomount check: rule list unreadable | engine {engine}\n"),
            };
        } else {
            // "nothing on the device was measured" was false, and visibly so: the
            // very next line on a healthy OP15 is a ghost row ending "Measured
            // here, not assumed from the build". The plan section does ask the
            // live engine and the kernel a handful of questions -- see
            // `Section::Plan`. What it did NOT do is run the device section, and
            // that is the thing a reader needs to know from the header.
            let _ = writeln!(
                s,
                "nomount check: plan section only — the device's own checks were not run\n"
            );
        }
        for c in &self.checks {
            let _ = writeln!(s, "[{}] {} ({})", c.verdict.tag(), c.name, c.section.slug());
            if !c.meaning.is_empty() {
                let _ = writeln!(s, "       {}", c.meaning);
            }
            // Plan findings carry one sentence that is both the explanation and the
            // measurement, so printing both lines repeats it verbatim. Say it once.
            if c.evidence != c.meaning {
                let _ = writeln!(s, "       measured: {}", c.evidence);
            }
            if let Some(o) = c.owner.as_deref() {
                let _ = writeln!(s, "       from: {o}");
            }
            if let Some(o) = c.oracle.as_deref() {
                let _ = writeln!(s, "       oracle: {o}");
            }
        }
        let t = self.tally();
        // The incompleteness goes ON the summary line, not only in a note under
        // it. This line is what gets grepped, pasted and read at a glance, and a
        // run whose process-dependent checks had nothing to look at must not read
        // as "N passed" with the caveat somewhere else.
        let _ = writeln!(
            s,
            "\nsummary: {} failed, {} pending reboot, {} unmeasured, {} warnings, {} passed, \
             {} not applicable, {} notes{}",
            t.fail,
            t.reboot,
            t.unmeasured,
            t.warn,
            t.pass,
            t.na,
            t.note,
            if t.complete() {
                String::new()
            } else {
                format!(
                    " — INCOMPLETE: {} check(s) were not measured, so this is not a clean result",
                    t.unmeasured
                )
            }
        );
        let _ = writeln!(s, "verdict: {}", self.verdict());
        if t.reboot > 0 {
            let _ = writeln!(s, "note: a pending-reboot check is still detectable until you reboot.");
        }
        if t.unmeasured > 0 {
            let _ = writeln!(s, "note: an unmeasured check was NOT verified — it is not a pass.");
        }
        s
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Build a report over the requested sections.
///
/// `plan` and `device` are independent: the boot path wants the cheap static half
/// before zygote and the measured half only once apps are running, and a caller
/// asking for one must not pay for the other. Asking for neither is a caller bug,
/// so it is treated as asking for both.
pub fn build(plan: bool, device: bool) -> Result<Report> {
    let (plan, device) = if !plan && !device { (true, true) } else { (plan, device) };
    let mut checks: Vec<Check> = Vec::new();
    let mut facts: Vec<(String, String)> = Vec::new();
    // None on a --plan-only run too: nobody asked the engine anything there
    // either, which is the case the header's own comment was written for.
    let (mut rules, mut directories) = (None, None);
    let mut engine = None;

    if device {
        let (device_checks, n_rules, n_dirs) = crate::audit::device_checks();
        rules = n_rules;
        directories = n_dirs;
        engine = crate::nm::Nm::new().version().ok();
        checks.extend(device_checks);
        // The runtime fingerprint, and the verdicts that come out of it. Both from
        // one gather() -- the canary and the drift probe are the expensive part and
        // running them twice to produce two report shapes is what the old
        // selfcheck/audit split was doing.
        let fp = crate::health::gather();
        checks.extend(fp.checks());
        facts = fp.facts();
    }
    if plan {
        let (plan_checks, counts) = crate::doctor::plan_checks()?;
        checks.extend(plan_checks);
        // Plan counts are facts about the module set, not verdicts, so they go
        // where the rest of the facts do -- and they are the numbers a bug report
        // needs first.
        for (k, v) in counts {
            facts.push((k, v));
        }
    }

    let mut r = Report { ts: now_secs(), engine, rules, directories, facts, checks };
    r.sort();
    Ok(r)
}

/// `nomount check [--plan] [--device] [--json] [--write]`.
pub fn run_check(plan: bool, device: bool, json: bool, write: bool) -> Result<()> {
    let want_device = device || !plan;
    let r = build(plan, device)?;

    if json {
        println!("{}", r.json());
    } else {
        print!("{}", r.text());
    }

    if write {
        // Best-effort, and deliberately so: a diagnostic that cannot cache its
        // result has still produced it on stdout, and failing the command would
        // turn a full disk into a boot-script error.
        // Atomic, and 0600 by construction -- see crate::statefile. service.sh
        // reads health.txt field by field and treats a missing key as a verdict,
        // so a half-written record is worse than no record at all.
        let _ = crate::statefile::write_atomic(CACHE, r.json());
        // health.txt carries the fingerprint, so only a run that MEASURED it may
        // write one. A --plan-only run has no facts about the running system, and
        // stamping a fresh `ts=` on an empty record is how `service.sh`'s
        // freshness test would come to certify a health record that was never
        // taken.
        if want_device {
            let mut body = r.fingerprint_text();
            body.push_str(&format!("verdict={}\n", r.verdict()));
            body.push_str(&format!("ts={}\n", r.ts));
            let _ = crate::statefile::write_atomic(HEALTH, body);
        }
    }

    if r.tally().open_failures() > 0 {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(id: &str, v: Verdict) -> Check {
        Check::new(Section::Device, id, id, v, "evidence")
    }

    /// The one-line verdict is the ONLY string `health.txt` carries and
    /// `service.sh` puts on the manager card, so what it ranks and what it calls
    /// things both matter.
    ///
    /// Two defects, one line apart. It tested `warn` before `complete()`, so four
    /// unmeasured checks beside one warning rendered as a warning and the
    /// incompleteness vanished — while `Verdict`'s own declaration order, the
    /// `doctor::Level` that mirrors it, and `Report::sort` all rank Unmeasured
    /// ABOVE Warn. And it called every Warn a "plan warning", though `audit::soft`
    /// emits four measured DEVICE tells through that verdict.
    #[test]
    fn the_verdict_line_ranks_and_names_what_it_counts() {
        let r = |v: Vec<Check>| Report {
            ts: 0,
            engine: None,
            rules: None,
            directories: None,
            facts: Vec::new(),
            checks: v,
        };

        // Unmeasured outranks warn, and says so without hiding the warning.
        let v = r(vec![c("a", Verdict::Warn), c("b", Verdict::Unmeasured)]).verdict();
        assert!(v.starts_with("not fully measured"), "unmeasured must outrank warn: {v}");
        assert!(v.contains("1 warning(s)"), "and must not hide the warning: {v}");

        // A warning alone is a warning -- not a PLAN warning. `soft()` rows are
        // measured device tells and they land in this same count.
        let v = r(vec![c("a", Verdict::Warn), c("b", Verdict::Pass)]).verdict();
        assert_eq!(v, "1 warning(s)");
        assert!(!v.contains("plan"), "a device tell is not a plan warning");

        // Fail still outranks everything, and clean still means clean.
        assert!(r(vec![c("a", Verdict::Fail), c("b", Verdict::Unmeasured)])
            .verdict()
            .contains("FAILED"));
        assert_eq!(r(vec![c("a", Verdict::Pass)]).verdict(), "clean");
    }

    /// The distinction the whole `Unmeasured` state exists for, now on the ONE
    /// enum: an unmeasured check is not a failure and is not a pass either, and a
    /// summary must be able to say so without a second report shape.
    #[test]
    fn unmeasured_is_neither_a_failure_nor_a_clean_result() {
        let t = Tally::of(&[c("a", Verdict::Pass), c("b", Verdict::Unmeasured)]);
        assert_eq!(t.open_failures(), 0);
        assert!(!t.complete());
        // n/a IS a measured answer -- "there is nothing here to test" is the
        // result. Only Unmeasured means the question went unanswered.
        assert!(Tally::of(&[c("a", Verdict::NotApplicable)]).complete());
        // ...and a plan warning is not a failure to act on at boot either.
        let w = Tally::of(&[c("a", Verdict::Warn)]);
        assert_eq!(w.open_failures(), 0);
        assert!(w.complete());
    }

    /// Worst first, and a dead engine ahead of everything: with it down, every
    /// other row describes a device that is not hiding anything.
    #[test]
    fn a_dead_engine_sorts_above_every_other_failure() {
        let mut r = Report {
            ts: 0,
            engine: None,
            rules: None,
            directories: None,
            facts: Vec::new(),
            checks: vec![
                c("zero-mount-posture", Verdict::Pass),
                c("some-other-check", Verdict::Fail),
                c("engine-responding", Verdict::Fail),
                c("a-note", Verdict::Note),
            ],
        };
        r.sort();
        let order: Vec<&str> = r.checks.iter().map(|x| x.id.as_str()).collect();
        assert_eq!(order[0], "engine-responding");
        assert_eq!(order[1], "some-other-check");
        assert_eq!(order[3], "a-note");
        assert_eq!(r.verdict(), "2 check(s) FAILED");
    }

    #[test]
    fn a_run_with_nothing_open_but_something_unmeasured_is_not_clean() {
        let r = Report {
            ts: 0,
            engine: Some(18),
            rules: Some(3),
            directories: Some(1),
            facts: Vec::new(),
            checks: vec![c("a", Verdict::Pass), c("b", Verdict::Unmeasured)],
        };
        assert_eq!(r.verdict(), "not fully measured (1 check(s) had nothing to look at)");
        assert!(r.json().contains("\"complete\":false"));
    }

    /// A note is not something to act on; a warning is. That is the whole ladder.
    ///
    /// `audit::soft` used to emit `Warn` for four tells nothing shipping probes,
    /// so they were labelled "attention"/"will bite later" beside real failures
    /// and put "N warning(s)" on the manager card. Those are Notes now. `Note` is
    /// no longer dropped by the WebUI either -- it renders in a collapsed
    /// "Good to know" disclosure -- so the ladder is about what the reader should
    /// ACT on, not about which verdict is visible.
    #[test]
    fn a_note_is_information_and_a_warning_is_attention() {
        assert_eq!(Verdict::Note.severity(), "info");
        assert_eq!(Verdict::Warn.severity(), "attention");
        let r = |v: Vec<Check>| Report {
            ts: 0,
            engine: None,
            rules: None,
            directories: None,
            facts: Vec::new(),
            checks: v,
        };
        // An engine canary nothing probes does not stop the run reading clean...
        assert_eq!(r(vec![c("a", Verdict::Note), c("b", Verdict::Pass)]).verdict(), "clean");
        // ...but a plan hazard the reader can fix does.
        assert_eq!(r(vec![c("a", Verdict::Warn), c("b", Verdict::Pass)]).verdict(), "1 warning(s)");
        // A note is still measured and still complete -- it is not an excuse.
        assert!(Tally::of(&[c("a", Verdict::Note)]).complete());
        assert_eq!(Tally::of(&[c("a", Verdict::Note)]).open_failures(), 0);
    }

    /// A count nobody measured must not print as a zero somebody did.
    ///
    /// `device_checks` returned `(checks, 0, 0)` when the rule dump failed, so the
    /// header opened "nomount check: 0 live rule(s) across 0 directory(ies) |
    /// engine v30" -- the exact confusion the `--plan` arm of this same function
    /// was fixed for three lines above. The same 0 reached the WebUI's
    /// bug-report clipboard.
    #[test]
    fn an_unread_rule_list_prints_as_unread_not_as_zero() {
        let r = Report {
            ts: 0,
            engine: Some(30),
            rules: None,
            directories: None,
            facts: Vec::new(),
            checks: vec![c("engine-rule-dump", Verdict::Fail)],
        };
        let t = r.text();
        assert!(t.contains("rule list unreadable | engine v30"), "{t}");
        assert!(!t.contains("0 live rule(s)"), "{t}");
        assert!(r.json().contains("\"rules\":null"), "{}", r.json());
        assert!(r.json().contains("\"directories\":null"), "{}", r.json());

        // A run that DID read them still says so, with the numbers.
        let ok = Report {
            ts: 0,
            engine: Some(30),
            rules: Some(3),
            directories: Some(1),
            facts: Vec::new(),
            checks: vec![c("a", Verdict::Pass)],
        };
        assert!(ok.text().contains("3 live rule(s) across 1 directory(ies)"), "{}", ok.text());
        assert!(ok.json().contains("\"rules\":3"), "{}", ok.json());
    }

    /// ids are derived, so a check cannot ship without one -- the gap that left
    /// every doctor row in the merged list with nothing to key on.
    #[test]
    fn slugs_are_stable_and_never_empty() {
        assert_eq!(slug("PM-published files open for a hidden app"), "pm-published-files-open-for-a-hidden-app");
        assert_eq!(slug("readdir ino vs stat ino"), "readdir-ino-vs-stat-ino");
        assert_eq!(slug("  spaces  everywhere  "), "spaces-everywhere");
        assert_eq!(slug("///"), "unnamed-check");
    }

    /// health.txt has exactly one renderer now. It used to have two descriptions
    /// of the same shape -- a hand-written `to_text` and a `--json` arm that
    /// parsed that text back apart.
    #[test]
    fn the_fingerprint_renders_as_key_equals_value() {
        let r = Report {
            ts: 7,
            engine: Some(18),
            rules: None,
            directories: None,
            facts: vec![("engine".into(), "v18".into()), ("consistency".into(), "ok".into())],
            checks: Vec::new(),
        };
        assert_eq!(r.fingerprint_text(), "engine=v18\nconsistency=ok\n");
        assert!(r.json().contains("\"key\":\"consistency\",\"value\":\"ok\""));
    }
}
