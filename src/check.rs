//! `nomount check` - the one diagnostic verb, and the one shape it answers in

use anyhow::Result;

use crate::json::J;

/// Where a check comes from, and therefore what its answer depends on
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Plan,
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

/// The single verdict
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Fail,
    Reboot,
    Unmeasured,
    Warn,
    Pass,
    NotApplicable,
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
    /// The coarse axis the one findings list sorts and colours on
    pub fn severity(self) -> &'static str {
        match self {
            Verdict::Fail | Verdict::Reboot | Verdict::Warn => "attention",
            Verdict::Unmeasured => "unmeasured",
            Verdict::Pass => "ok",
            Verdict::NotApplicable | Verdict::Note => "info",
        }
    }
}

/// One answer, whichever section produced it
pub struct Check {
    /// Stable slug
    pub id: String,
    pub name: String,
    pub section: Section,
    pub verdict: Verdict,
    /// What was actually read
    pub evidence: String,
    /// One line in the reader's terms, on every verdict
    pub meaning: String,
    /// What an attacker would do with a failure
    pub oracle: Option<String>,
    /// Who caused this: a module id, the kernel, the root manager, the user's own configuration
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

/// Turn a display name into a stable id: lowercase, non-alphanumerics collapsed to single
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

/// Counts, one per verdict
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
    /// Findings the reader still has to act on
    pub fn open_failures(&self) -> usize {
        self.fail + self.reboot
    }
    /// Did every check that could apply actually get measured?
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
            ("complete", J::Bool(self.complete())),
        ])
    }
}

/// One `key=value` row of the fingerprint, or of the plan counts
pub type Fact = (String, String);

fn num_or_null(n: Option<usize>) -> J {
    match n {
        Some(v) => J::Num(v as i64),
        None => J::Null,
    }
}

/// Everything one run of `nomount check` produced
pub struct Report {
    pub ts: i64,
    /// Which sections were actually RUN, recorded rather than inferred from the findings.
    /// `plan_checks` emits a finding only when it has one, so a device with a perfectly
    /// clean module set produced zero plan checks - and `ran(Plan)`, which asked "is there
    /// a plan check", then said the plan half had been skipped.
    pub sections: Vec<Section>,
    pub engine: Option<u32>,
    /// Live rules, and the directories holding them
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

    /// Worst first, then by section, then by name - a stable order, so two runs of the same
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

    /// The one-line verdict, in the reader's terms
    pub fn verdict(&self) -> String {
        let t = self.tally();
        if t.fail > 0 {
            format!("{} check(s) FAILED", t.fail)
        } else if t.reboot > 0 {
            format!("{} check(s) need a reboot to finish", t.reboot)
        } else if !t.complete() {
            format!(
                "not fully measured ({} check(s) had nothing to look at{})",
                t.unmeasured,
                if t.warn > 0 { format!(", plus {} warning(s)", t.warn) } else { String::new() }
            )
        } else if t.warn > 0 {
            format!("{} warning(s)", t.warn)
        } else {
            "clean".to_string()
        }
    }

    /// `health.txt` / `snapshot.txt`: the facts as key=value, one per line
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
            ("rules", num_or_null(self.rules)),
            ("directories", num_or_null(self.directories)),
            (
                "sections",
                J::Arr(self.sections.iter().map(|x| J::s(x.slug())).collect()),
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
    pub fn ran(&self, section: Section) -> bool {
        self.sections.contains(&section)
    }

    /// The human report
    pub fn text(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::new();
        if self.ran(Section::Device) {
            let engine = match self.engine {
                Some(v) => format!("v{v}"),
                None => "not responding".to_string(),
            };
            let _ = match (self.rules, self.directories) {
                (Some(r), Some(d)) => writeln!(
                    s,
                    "nomount check: {r} live rule(s) across {d} directory(ies) | engine {engine}\n"
                ),
                _ => writeln!(s, "nomount check: rule list unreadable | engine {engine}\n"),
            };
        } else {
            let _ = writeln!(
                s,
                "nomount check: plan section only - the device's own checks were not run\n"
            );
        }
        for c in &self.checks {
            let _ = writeln!(s, "[{}] {} ({})", c.verdict.tag(), c.name, c.section.slug());
            if !c.meaning.is_empty() {
                let _ = writeln!(s, "       {}", c.meaning);
            }
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
                    " - incomplete: {} check(s) were not measured, so this is not a clean result",
                    t.unmeasured
                )
            }
        );
        let _ = writeln!(s, "verdict: {}", self.verdict());
        if t.reboot > 0 {
            let _ = writeln!(s, "note: a pending-reboot check is still detectable until you reboot.");
        }
        if t.unmeasured > 0 {
            let _ = writeln!(s, "note: an unmeasured check was not verified - it is not a pass.");
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

/// Build a report over the requested sections
pub fn build(plan: bool, device: bool) -> Result<Report> {
    let (plan, device) = if !plan && !device { (true, true) } else { (plan, device) };
    let mut checks: Vec<Check> = Vec::new();
    let mut facts: Vec<(String, String)> = Vec::new();
    let (mut rules, mut directories) = (None, None);
    let mut engine = None;

    if device {
        let (device_checks, n_rules, n_dirs) = crate::audit::device_checks();
        rules = n_rules;
        directories = n_dirs;
        engine = crate::nm::Nm::new().version().ok();
        checks.extend(device_checks);
        let fp = crate::health::gather();
        checks.extend(fp.checks());
        facts = fp.facts();
    }
    if plan {
        let (plan_checks, counts) = crate::doctor::plan_checks()?;
        checks.extend(plan_checks);
        for (k, v) in counts {
            facts.push((k, v));
        }
    }

    let mut sections = Vec::new();
    if plan {
        sections.push(Section::Plan);
    }
    if device {
        sections.push(Section::Device);
    }
    let mut r = Report { ts: now_secs(), sections, engine, rules, directories, facts, checks };
    r.sort();
    Ok(r)
}

/// `nomount check [--plan] [--device] [--json] [--write]`
pub fn run_check(plan: bool, device: bool, json: bool, write: bool) -> Result<()> {
    let want_device = device || !plan;
    let r = build(plan, device)?;

    if json {
        println!("{}", r.json());
    } else {
        print!("{}", r.text());
    }

    if write {
        let _ = crate::statefile::write_atomic(CACHE, r.json());
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

    #[test]
    fn the_verdict_line_ranks_and_names_what_it_counts() {
        let r = |v: Vec<Check>| Report {
            ts: 0,
            sections: vec![Section::Device],
            engine: None,
            rules: None,
            directories: None,
            facts: Vec::new(),
            checks: v,
        };

        let v = r(vec![c("a", Verdict::Warn), c("b", Verdict::Unmeasured)]).verdict();
        assert!(v.starts_with("not fully measured"), "unmeasured must outrank warn: {v}");
        assert!(v.contains("1 warning(s)"), "and must not hide the warning: {v}");

        let v = r(vec![c("a", Verdict::Warn), c("b", Verdict::Pass)]).verdict();
        assert_eq!(v, "1 warning(s)");
        assert!(!v.contains("plan"), "a device tell is not a plan warning");

        assert!(r(vec![c("a", Verdict::Fail), c("b", Verdict::Unmeasured)])
            .verdict()
            .contains("FAILED"));
        assert_eq!(r(vec![c("a", Verdict::Pass)]).verdict(), "clean");
    }

    #[test]
    fn unmeasured_is_neither_a_failure_nor_a_clean_result() {
        let t = Tally::of(&[c("a", Verdict::Pass), c("b", Verdict::Unmeasured)]);
        assert_eq!(t.open_failures(), 0);
        assert!(!t.complete());
        assert!(Tally::of(&[c("a", Verdict::NotApplicable)]).complete());
        let w = Tally::of(&[c("a", Verdict::Warn)]);
        assert_eq!(w.open_failures(), 0);
        assert!(w.complete());
    }

    #[test]
    fn a_dead_engine_sorts_above_every_other_failure() {
        let mut r = Report {
            ts: 0,
            sections: vec![Section::Device],
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
            sections: vec![Section::Device],
            engine: Some(18),
            rules: Some(3),
            directories: Some(1),
            facts: Vec::new(),
            checks: vec![c("a", Verdict::Pass), c("b", Verdict::Unmeasured)],
        };
        assert_eq!(r.verdict(), "not fully measured (1 check(s) had nothing to look at)");
        assert!(r.json().contains("\"complete\":false"));
    }

    #[test]
    fn a_note_is_information_and_a_warning_is_attention() {
        assert_eq!(Verdict::Note.severity(), "info");
        assert_eq!(Verdict::Warn.severity(), "attention");
        let r = |v: Vec<Check>| Report {
            ts: 0,
            sections: vec![Section::Device],
            engine: None,
            rules: None,
            directories: None,
            facts: Vec::new(),
            checks: v,
        };
        assert_eq!(r(vec![c("a", Verdict::Note), c("b", Verdict::Pass)]).verdict(), "clean");
        assert_eq!(r(vec![c("a", Verdict::Warn), c("b", Verdict::Pass)]).verdict(), "1 warning(s)");
        assert!(Tally::of(&[c("a", Verdict::Note)]).complete());
        assert_eq!(Tally::of(&[c("a", Verdict::Note)]).open_failures(), 0);
    }

    #[test]
    fn an_unread_rule_list_prints_as_unread_not_as_zero() {
        let r = Report {
            ts: 0,
            sections: vec![Section::Device],
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

        let ok = Report {
            ts: 0,
            sections: vec![Section::Device],
            engine: Some(30),
            rules: Some(3),
            directories: Some(1),
            facts: Vec::new(),
            checks: vec![c("a", Verdict::Pass)],
        };
        assert!(ok.text().contains("3 live rule(s) across 1 directory(ies)"), "{}", ok.text());
        assert!(ok.json().contains("\"rules\":3"), "{}", ok.json());
    }

    #[test]
    fn slugs_are_stable_and_never_empty() {
        assert_eq!(slug("PM-published files open for a hidden app"), "pm-published-files-open-for-a-hidden-app");
        assert_eq!(slug("readdir ino vs stat ino"), "readdir-ino-vs-stat-ino");
        assert_eq!(slug("  spaces  everywhere  "), "spaces-everywhere");
        assert_eq!(slug("///"), "unnamed-check");
    }

    #[test]
    fn a_section_that_found_nothing_still_reports_as_having_run() {
        let clean_plan = Report {
            ts: 0,
            sections: vec![Section::Plan, Section::Device],
            engine: Some(32),
            rules: Some(3),
            directories: Some(1),
            facts: Vec::new(),
            checks: vec![c("a", Verdict::Pass)],
        };
        assert!(clean_plan.ran(Section::Plan), "it ran; it just had nothing to say");
        assert!(clean_plan.ran(Section::Device));
        assert!(clean_plan.json().contains(r#""sections":["plan","device"]"#), "{}", clean_plan.json());

        let device_only = Report {
            ts: 0,
            sections: vec![Section::Device],
            engine: Some(32),
            rules: Some(3),
            directories: Some(1),
            facts: Vec::new(),
            checks: vec![c("a", Verdict::Pass)],
        };
        assert!(!device_only.ran(Section::Plan), "this one really was skipped");
        assert!(device_only.json().contains(r#""sections":["device"]"#), "{}", device_only.json());
    }

    #[test]
    fn the_fingerprint_renders_as_key_equals_value() {
        let r = Report {
            ts: 7,
            sections: vec![Section::Device],
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
