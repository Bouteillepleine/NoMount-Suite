
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

const DEFAULT_NM_BIN: &str = "/data/adb/modules/meta-nomount/bin/arm64-v8a/nm";

pub struct Nm {
    bin: String,
}

/// Why one `nm` invocation failed. The exit code alone said "a rule in this chunk was
/// refused"; the per-rule retry exists to find out WHICH and why, and it was throwing the
/// engine's answer away.
pub(crate) struct NmErr {
    pub code: Option<i32>,
    pub why: String,
}

impl Nm {
    pub fn new() -> Self {
        let bin = std::env::var("NM_BIN").ok().unwrap_or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("nm")))
                .filter(|p| p.exists())
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| DEFAULT_NM_BIN.to_string())
        });
        Self { bin }
    }

    const EXIT_TIMEOUT: i32 = 5;
    const EXIT_NO_ENGINE: i32 = 2;

    const DEADLINE: Duration = Duration::from_secs(30);
    const KILL_GRACE: Duration = Duration::from_millis(500);

    fn engine_is_unreachable(code: Option<i32>) -> bool {
        matches!(code, None | Some(Nm::EXIT_TIMEOUT) | Some(Nm::EXIT_NO_ENGINE))
    }

    /// `Command::output()` waits forever. nm bounds its own netlink round trip, so a call
    /// that outlives DEADLINE is nm itself wedged rather than the engine being slow - and
    /// these all run from post-fs-data, where waiting forever is a boot hang with nothing
    /// on the console to say why.
    fn output(&self, args: &[&str]) -> std::io::Result<std::process::Output> {
        self.output_within(args, Nm::DEADLINE)
    }

    fn output_within(
        &self,
        args: &[&str],
        deadline: Duration,
    ) -> std::io::Result<std::process::Output> {
        let spawn = || {
            Command::new(&self.bin)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
        };
        let mut tries = 0;
        let mut child = loop {
            match spawn() {
                Err(e) if e.raw_os_error() == Some(26) && tries < 20 => {
                    tries += 1;
                    std::thread::sleep(Duration::from_millis(5));
                }
                r => break r?,
            }
        };

        let by = Instant::now() + deadline;
        let mut so = child.stdout.take();
        let mut se = child.stderr.take();
        let (eof_tx, eof_rx) = std::sync::mpsc::channel();
        let t_out = std::thread::spawn(move || {
            let mut b = Vec::new();
            if let Some(h) = so.as_mut() {
                let _ = h.read_to_end(&mut b);
            }
            let _ = eof_tx.send(());
            b
        });
        let t_err = std::thread::spawn(move || {
            let mut b = Vec::new();
            if let Some(h) = se.as_mut() {
                let _ = h.read_to_end(&mut b);
            }
            b
        });

        let _ = eof_rx.recv_timeout(by.saturating_duration_since(Instant::now()));
        let Some(status) = reap_by(&mut child, by)? else {
            let _ = child.kill();
            if !matches!(reap_by(&mut child, Instant::now() + Nm::KILL_GRACE), Ok(Some(_))) {
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("nm {} did not answer in {deadline:?}", args.join(" ")),
            ));
        };

        Ok(std::process::Output {
            status,
            stdout: t_out.join().unwrap_or_default(),
            stderr: t_err.join().unwrap_or_default(),
        })
    }

    fn run_coded(&self, args: &[&str]) -> std::result::Result<String, NmErr> {
        let out = self
            .output(args)
            .map_err(|e| NmErr { code: None, why: e.to_string() })?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        Err(NmErr {
            code: out.status.code(),
            why: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        })
    }

    fn run(&self, args: &[&str]) -> Result<String> {
        let out = self
            .output(args)
            .with_context(|| format!("exec {} {:?}", self.bin, args))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let mut msg = err.trim().to_string();
            if msg.is_empty() {
                let out_s = String::from_utf8_lossy(&out.stdout);
                msg = out_s.lines().next().unwrap_or_default().trim().to_string();
            }
            bail!(
                "nm {} failed (exit {}): {}",
                args.join(" "),
                out.status.code().map(|c| c.to_string()).unwrap_or_else(|| "signal".into()),
                msg
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    pub fn version(&self) -> Result<u32> {
        Ok(self.version_full()?.0)
    }

    /// The second half is the engine's build string, which a kernel older than this
    /// attribute does not send. It exists because NOMOUNT_VERSION is the wire protocol:
    /// it only moves when the protocol does, so two kernels that behave differently can
    /// both answer 34, and from userspace nothing else tells them apart.
    pub fn version_full(&self) -> Result<(u32, Option<String>)> {
        let out = self.run(&["v"])?;
        let mut parts = out.split_ascii_whitespace();
        let proto = parts
            .next()
            .unwrap_or_default()
            .parse::<u32>()
            .context("nm v: non-numeric version (engine not responding?)")?;
        let build = parts.next().filter(|s| !s.is_empty()).map(str::to_string);
        Ok((proto, build))
    }

    pub fn add(&self, virtual_path: &Path, real: &Path) -> Result<()> {
        let public = crate::pmcache::is_pm_published(virtual_path);
        self.run(&add_argv(public, path_str(virtual_path)?, path_str(real)?))
            .map(drop)
    }

    pub fn del(&self, virtual_path: &Path) -> Result<()> {
        self.run(&["del", path_str(virtual_path)?]).map(drop)
    }

    pub fn whiteout(&self, path: &Path) -> Result<()> {
        self.run(&["w", path_str(path)?]).map(drop)
    }

    pub fn uid_block(&self, uid: u32) -> Result<()> {
        self.run(&["block", &crate::blocklist::appid(uid).to_string()])
            .map(drop)
    }

    pub fn uid_unblock(&self, uid: u32) -> Result<()> {
        self.run(&["unblock", &crate::blocklist::appid(uid).to_string()])
            .map(drop)
    }

    pub fn set_hide_isolated(&self, mode: u32) -> Result<()> {
        self.run(&["k", "i", &mode.to_string()]).map(drop)
    }

    pub fn uid_list_live(&self) -> Result<Vec<u32>> {
        let out = self.run(&["l", "u"])?;
        let mut uids = Vec::new();
        for tok in out.split(|c: char| !c.is_ascii_digit()) {
            if let Ok(u) = tok.parse::<u32>() {
                uids.push(u);
            }
        }
        Ok(uids)
    }

    pub fn set_dir_shape(&self, packed: bool) -> Result<()> {
        self.run(&["k", "d", if packed { "1" } else { "0" }]).map(|_| ())
    }

    pub fn clear(&self) -> Result<()> {
        self.run(&["clear"]).map(drop)
    }

    pub fn list(&self) -> Result<String> {
        self.run(&["list"])
    }

    pub fn ghost_list(&self) -> Result<String> {
        self.run(&["l", "g"])
    }

    /// `None` means nm could not be asked at all - it would not spawn, it was killed, or
    /// the engine is unreachable. That is not the same answer as a kernel built without
    /// the cloak, and reporting it as one let the caller skip the sync in silence.
    pub fn ghost_present(&self) -> Option<bool> {
        match self.run_coded(&["k", "g"]) {
            Ok(_) => Some(true),
            Err(e) if Nm::engine_is_unreachable(e.code) => None,
            Err(_) => Some(false),
        }
    }

    pub fn ghost_ctl(&self, cmd: &str) -> Result<()> {
        self.run(&["k", "g", cmd]).map(drop)
    }

    pub fn pathhide_list(&self) -> Result<String> {
        self.run(&["l", "p"])
    }

    /// Same three-way answer as [`Nm::ghost_present`]: `None` is "could not ask",
    /// which is not the same as a kernel built without the cloak.
    pub fn pathhide_present(&self) -> Option<bool> {
        match self.run_coded(&["k", "p"]) {
            Ok(_) => Some(true),
            Err(e) if Nm::engine_is_unreachable(e.code) => None,
            Err(_) => Some(false),
        }
    }

    /// One rule per call: the engine length-checks each write against
    /// PH_RULE_LEN, unlike ghost_ctl()'s multi-token buffer.
    pub fn pathhide_ctl(&self, cmd: &str) -> Result<()> {
        self.run(&["k", "p", cmd]).map(drop)
    }

    fn add_batch_coded(
        &self,
        public: bool,
        pairs: &[(&Path, &Path)],
    ) -> std::result::Result<(), NmErr> {
        let mut args: Vec<&str> = Vec::with_capacity(1 + usize::from(public) + pairs.len() * 2);
        args.push("add");
        if public {
            args.push("--public");
        }
        for (v, r) in pairs {
            args.push(path_str(v).map_err(|e| NmErr { code: None, why: e.to_string() })?);
            args.push(path_str(r).map_err(|e| NmErr { code: None, why: e.to_string() })?);
        }
        self.run_coded(&args).map(drop)
    }

}

const ADD_BATCH_PAIRS: usize = 31;

impl Nm {
    pub fn add_many<'a>(&self, pairs: &[(&'a Path, &'a Path)]) -> Vec<(&'a Path, &'a Path)> {
        let (pairs, mut failed): (Vec<_>, Vec<_>) = pairs
            .iter()
            .copied()
            .partition(|(v, r)| v.to_str().is_some() && r.to_str().is_some());
        for (v, _) in &failed {
            eprintln!("nomount: rule refused for {}: non-UTF8 path", v.display());
        }
        let mut gave_up = false;
        for (public, group) in batch_groups(&pairs, crate::pmcache::is_pm_published) {
            for chunk in group.chunks(ADD_BATCH_PAIRS) {
                if gave_up {
                    failed.extend(chunk.iter().copied());
                    continue;
                }
                let batch = self.add_batch_coded(public, chunk);
                if batch.is_ok() {
                    continue;
                }
                if Nm::engine_is_unreachable(batch.unwrap_err().code) {
                    eprintln!(
                        "nomount: the engine stopped answering mid-pass - abandoning the \
                         remaining injections rather than retrying each one against it. \
                         {} rule(s) in this chunk and everything after it are unserved.",
                        chunk.len()
                    );
                    gave_up = true;
                    failed.extend(chunk.iter().copied());
                    continue;
                }
                for (i, (v, r)) in chunk.iter().enumerate() {
                    match self.add_batch_coded(public, std::slice::from_ref(&(*v, *r))) {
                        Ok(_) => {}
                        Err(e) => {
                            failed.push((*v, *r));
                            eprintln!(
                                "nomount: rule refused for {}: {}",
                                v.display(),
                                if e.why.is_empty() {
                                    e.code.map_or_else(
                                        || "nm did not run".to_string(),
                                        |c| format!("nm exit {c}"),
                                    )
                                } else {
                                    e.why.clone()
                                }
                            );
                            if Nm::engine_is_unreachable(e.code) {
                                gave_up = true;
                                failed.extend(chunk[i + 1..].iter().copied());
                                eprintln!(
                                    "nomount: the engine stopped answering mid-chunk - {} \
                                     further rule(s) in it were never sent and are unserved.",
                                    chunk.len() - i - 1
                                );
                                break;
                            }
                        }
                    }
                }
            }
        }
        failed
    }
}

fn batch_groups<'a>(
    pairs: &[(&'a Path, &'a Path)],
    is_public: fn(&Path) -> bool,
) -> Vec<(bool, Vec<(&'a Path, &'a Path)>)> {
    let mut out = Vec::new();
    for public in [false, true] {
        let g: Vec<(&Path, &Path)> =
            pairs.iter().copied().filter(|(v, _)| is_public(v) == public).collect();
        if !g.is_empty() {
            out.push((public, g));
        }
    }
    out
}

fn add_argv<'a>(public: bool, virtual_path: &'a str, real: &'a str) -> Vec<&'a str> {
    let mut args = Vec::with_capacity(4);
    args.push("add");
    if public {
        args.push("--public");
    }
    args.push(virtual_path);
    args.push(real);
    args
}

fn path_str(p: &Path) -> Result<&str> {
    p.to_str()
        .with_context(|| format!("non-UTF8 path: {}", p.display()))
}

fn reap_by(child: &mut Child, by: Instant) -> std::io::Result<Option<ExitStatus>> {
    let mut nap = Duration::from_micros(100);
    loop {
        if let Some(st) = child.try_wait()? {
            return Ok(Some(st));
        }
        let now = Instant::now();
        if now >= by {
            return Ok(None);
        }
        std::thread::sleep(nap.min(by - now));
        nap = (nap * 2).min(Duration::from_millis(20));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveKind {
    Inject,
    Whiteout,
    VirtualDir,
}

pub(crate) struct LiveRule {
    pub target: PathBuf,
    pub source: Option<PathBuf>,
    pub uid: u32,
    pub kind: LiveKind,
    pub public: bool,
}

pub(crate) fn parse_list(list: &str) -> Vec<LiveRule> {
    parse_list_counted(list).0
}

/// The second half is the number of non-blank lines the parser could not read.
/// Dropping those silently meant a listing whose shape the engine had changed came
/// back short, and every caller downstream read the missing rules as rules gone.
pub(crate) fn parse_list_counted(list: &str) -> (Vec<LiveRule>, usize) {
    let mut dropped = 0usize;
    let rules = list
        .lines()
        .filter_map(|line| {
            let parsed = parse_line(line);
            if parsed.is_none() && !line.trim().is_empty() {
                dropped += 1;
            }
            parsed
        })
        .collect();
    (rules, dropped)
}

fn parse_line(line: &str) -> Option<LiveRule> {
    let uid: u32 = line
        .split_once(" [UID:")
        .and_then(|(_, r)| r.trim_start().trim_end_matches(']').trim().parse().ok())
        .unwrap_or(0);
    let mut l = line.split(" [UID:").next().unwrap_or(line).trim();
    if l.is_empty() {
        return None;
    }
    let mut public = false;
    let mut kind: Option<LiveKind> = None;
    loop {
        if let Some(rest) = l.strip_suffix(" (public)") {
            public = true;
            l = rest.trim_end();
        } else if let Some(rest) = l.strip_suffix(" (whiteout)") {
            kind = Some(LiveKind::Whiteout);
            l = rest.trim_end();
        } else if let Some(rest) = l.strip_suffix(" (virtual dir)") {
            kind = Some(LiveKind::VirtualDir);
            l = rest.trim_end();
        } else {
            break;
        }
    }
    if let Some(kind) = kind {
        let target = l.trim();
        if target.is_empty() {
            return None;
        }
        return Some(LiveRule {
            target: PathBuf::from(target),
            source: None,
            uid,
            kind,
            public,
        });
    }
    let (t, s) = l.rsplit_once(" -> ")?;
    let (t, s) = (t.trim(), s.trim());
    if t.is_empty() || s.is_empty() {
        return None;
    }
    Some(LiveRule {
        target: PathBuf::from(t),
        source: Some(PathBuf::from(s)),
        uid,
        kind: LiveKind::Inject,
        public,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_adds_the_flag_before_the_paths() {
        assert_eq!(
            add_argv(true, "/product/overlay/Foo.apk", "/data/adb/modules/m/product/overlay/Foo.apk"),
            vec!["add", "--public", "/product/overlay/Foo.apk", "/data/adb/modules/m/product/overlay/Foo.apk"]
        );
        assert_eq!(
            add_argv(false, "/system/lib64/libfoo.so", "/data/adb/modules/m/system/lib64/libfoo.so"),
            vec!["add", "/system/lib64/libfoo.so", "/data/adb/modules/m/system/lib64/libfoo.so"]
        );
    }

    #[test]
    fn only_pm_published_files_opt_out_of_hiding() {
        for p in [
            "/product/overlay/OxygenCustomizerComponentNB8.apk",
            "/system/priv-app/Foo/Foo.apk",
            "/system/priv-app/Foo/lib/arm64/libfoo.so",
        ] {
            assert!(crate::pmcache::is_pm_published(Path::new(p)), "{p} should be public");
        }
        for p in ["/system/lib64/libfoo.so", "/product/etc/permissions/x.xml", "/data/app/x/base.apk"] {
            assert!(!crate::pmcache::is_pm_published(Path::new(p)), "{p} must stay hidden");
        }
    }

    #[test]
    fn parse_list_classifies_every_kind() {
        let s = "/product/x.apk -> /data/adb/modules/M/product/x.apk\n\
                 /system/y (whiteout)\n\
                 /system/vdir (virtual dir)\n\
                 not a rule line\n\
                 /product/z -> /data/adb/modules/M/product/z\n";
        let v = parse_list(s);
        assert_eq!(v.len(), 4);
        assert_eq!(v[0].target, PathBuf::from("/product/x.apk"));
        assert_eq!(v[0].source.as_deref(), Some(Path::new("/data/adb/modules/M/product/x.apk")));
        assert_eq!(v[0].kind, LiveKind::Inject);
        assert_eq!(v[1].kind, LiveKind::Whiteout);
        assert_eq!(v[1].source, None);
        assert_eq!(v[2].kind, LiveKind::VirtualDir);
        assert_eq!(v[3].target, PathBuf::from("/product/z"));
    }

    #[test]
    fn parse_list_strips_uid_and_public_suffixes() {
        let v = parse_list("/product/x.apk -> /data/adb/modules/M/x.apk (public) [UID: 10123]\n");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].source.as_deref(), Some(Path::new("/data/adb/modules/M/x.apk")));
        assert!(v[0].public);
        assert_eq!(v[0].uid, 10123);
        for line in ["/system/y (public) (whiteout)\n", "/system/y (whiteout) (public)\n"] {
            let w = parse_list(line);
            assert_eq!(w.len(), 1, "{line:?}");
            assert_eq!(w[0].kind, LiveKind::Whiteout, "{line:?}");
            assert_eq!(w[0].target, PathBuf::from("/system/y"), "{line:?}");
            assert!(w[0].public, "{line:?}");
        }
        let p = parse_list("/product/z -> /data/adb/modules/M/z\n");
        assert!(!p[0].public);
        assert_eq!(p[0].uid, 0);
    }

    #[cfg(unix)]
    #[test]
    fn the_version_reply_carries_the_build_string_when_the_kernel_sends_one() {
        // `nm v` printed one field before the build string existed, and a kernel that
        // predates the attribute still prints one. Both have to keep parsing.
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let stub = |name: &str, line: &str| {
            let f = d.path().join(name);
            std::fs::write(&f, format!("#!/bin/sh\necho '{line}'\n")).unwrap();
            std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
            Nm { bin: f.to_string_lossy().into_owned() }
        };

        let nm = stub("old", "34");
        assert_eq!(nm.version_full().unwrap(), (34, None), "an older kernel, one field");

        let nm = stub("new", "34 1.34.1");
        assert_eq!(
            nm.version_full().unwrap(),
            (34, Some("1.34.1".into())),
            "a kernel that sends the build string"
        );
        assert_eq!(nm.version().unwrap(), 34, "the protocol number is unaffected");
    }

    #[cfg(unix)]
    #[test]
    fn nm_verify_reads_the_protocol_number_in_both_version_formats() {
        use std::os::unix::fs::PermissionsExt;
        const VERIFY: &str = include_str!("../hookless/nm-verify.sh");
        let mut head = String::new();
        for l in VERIFY.lines() {
            head.push_str(l);
            head.push('\n');
            if l.trim() == "esac" {
                break;
            }
        }
        assert!(head.ends_with("esac\n"), "nm-verify.sh no longer gates on the version reply");
        let nm_line = head
            .lines()
            .find(|l| l.starts_with("NM="))
            .expect("nm-verify.sh no longer sets NM")
            .to_string();
        let d = tempfile::tempdir().unwrap();
        let run = |reply: &str| {
            let stub = d.path().join("nm");
            std::fs::write(&stub, format!("#!/bin/sh\nprintf '%s' '{reply}'\n")).unwrap();
            std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
            let script = head.replacen(&nm_line, &format!("NM='{}'", stub.display()), 1)
                + "echo \"VER=$VER\"\n";
            let out = Command::new("sh").arg("-c").arg(&script).output().unwrap();
            (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned())
        };

        let (rc, out) = run("34\n");
        assert_eq!(rc, Some(0), "an engine without the build string: {out}");
        assert!(out.contains("VER=34\n"), "{out}");

        let (rc, out) = run("34 1.34.2\n");
        assert_eq!(rc, Some(0), "an engine that sends the build string: {out}");
        assert!(out.contains("VER=34\n"), "{out}");
        assert!(out.contains("1.34.2"), "the build string is not shown: {out}");

        let (rc, out) = run("");
        assert_eq!(rc, Some(1), "no answer must still be fatal: {out}");
    }

    #[cfg(unix)]
    #[test]
    fn a_wedged_nm_is_killed_rather_than_waited_on_forever() {
        let nm = Nm { bin: "/bin/sleep".into() };
        let start = Instant::now();
        let e = nm
            .output_within(&["30"], Duration::from_millis(200))
            .expect_err("a sleeping child must not be waited out");
        assert_eq!(e.kind(), std::io::ErrorKind::TimedOut);
        assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());
    }

    #[cfg(unix)]
    fn logging_stub(d: &Path, tail: &str) -> (Nm, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let log = d.join("calls");
        let f = d.join("nm");
        std::fs::write(&f, format!("#!/bin/sh\necho \"$*\" >> '{}'\n{tail}\n", log.display())).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o755)).unwrap();
        (Nm { bin: f.to_string_lossy().into_owned() }, log)
    }

    #[cfg(unix)]
    #[test]
    fn an_nm_that_never_exits_with_a_code_is_unreachable_to_add_many_as_to_ghost_present() {
        let d = tempfile::tempdir().unwrap();
        let (nm, log) = logging_stub(d.path(), "kill -KILL $$");
        assert_eq!(nm.ghost_present(), None);
        std::fs::remove_file(&log).unwrap();

        let src = Path::new("/data/adb/modules/M/x");
        let a = Path::new("/system/lib64/a.so");
        let b = Path::new("/system/lib64/b.so");
        let c = Path::new("/system/etc/c.conf");
        let failed = nm.add_many(&[(a, src), (b, src), (c, src)]);
        assert_eq!(failed, vec![(a, src), (b, src), (c, src)]);
        let calls = std::fs::read_to_string(&log).unwrap();
        assert_eq!(calls.lines().count(), 1, "a killed batch was retried rule by rule: {calls:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_non_utf8_path_is_refused_alone_and_the_rest_are_still_sent() {
        use std::os::unix::ffi::OsStrExt;
        let d = tempfile::tempdir().unwrap();
        let (nm, log) = logging_stub(d.path(), "exit 0");
        let src = Path::new("/data/adb/modules/M/x");
        let a = Path::new("/system/lib64/a.so");
        let bad = Path::new(std::ffi::OsStr::from_bytes(b"/system/lib64/\xff.so"));
        let c = Path::new("/system/etc/c.conf");
        let failed = nm.add_many(&[(a, src), (bad, src), (c, src)]);
        assert_eq!(failed, vec![(bad, src)]);
        let calls = std::fs::read_to_string(&log).unwrap();
        assert_eq!(calls.lines().count(), 1, "{calls:?}");
        assert!(calls.contains("/system/lib64/a.so") && calls.contains("/system/etc/c.conf"), "{calls:?}");
    }

    #[cfg(unix)]
    #[test]
    fn a_quick_nm_is_not_held_back_by_the_deadline_poll() {
        let nm = Nm { bin: "/bin/sleep".into() };
        let fastest = (0..20)
            .map(|_| {
                let t = Instant::now();
                nm.output_within(&["0.003"], Duration::from_secs(10)).expect("ran");
                t.elapsed()
            })
            .min()
            .unwrap();
        assert!(fastest < Duration::from_millis(15), "{fastest:?}");
    }

    #[cfg(unix)]
    #[test]
    fn an_nm_that_closes_stdout_before_exiting_is_still_waited_for() {
        let nm = Nm { bin: "/bin/sh".into() };
        let t = Instant::now();
        let out = nm
            .output_within(&["-c", "exec >&-; sleep 0.3; exit 7"], Duration::from_secs(10))
            .expect("ran");
        assert_eq!(out.status.code(), Some(7));
        assert!(t.elapsed() >= Duration::from_millis(300), "{:?}", t.elapsed());
    }

    #[cfg(unix)]
    #[test]
    fn a_prompt_answer_is_still_returned_whole() {
        let nm = Nm { bin: "/bin/echo".into() };
        let out = nm.output_within(&["hello"], Duration::from_secs(10)).expect("ran");
        assert!(out.status.success());
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
    }

    #[test]
    fn nms_exit_codes_and_what_rust_reads_into_them_agree_both_ways() {
        const NM_H: &str = include_str!("../userspace/src/nm.h");
        const NM_C: &str = include_str!("../userspace/src/nm.c");
        let define = |name: &str| -> i32 {
            NM_H.lines()
                .find_map(|l| {
                    let mut w = l.split_whitespace();
                    if w.next() != Some("#define") || w.next() != Some(name) {
                        return None;
                    }
                    w.next()?.parse().ok()
                })
                .unwrap_or_else(|| panic!("userspace/src/nm.h no longer defines {name} as a number"))
        };
        let named = [
            ("NM_EXIT_TIMEOUT", Nm::EXIT_TIMEOUT),
            ("NM_EXIT_NO_ENGINE", Nm::EXIT_NO_ENGINE),
        ];
        for (name, rust) in named {
            assert_eq!(define(name), rust, "userspace/src/nm.h's {name} and src/nm.rs disagree");
        }

        assert_eq!(
            NM_C.matches("SYS_EXIT").count(),
            1,
            "nm.c exits somewhere other than its one exit_code path, which this pin cannot see"
        );
        assert!(NM_C.contains("sys1(SYS_EXIT, exit_code)"));
        assert!(
            NM_H.lines().filter(|l| l.contains("SYS_EXIT")).all(|l| l.trim_start().starts_with("#define")),
            "nm.h exits on its own, which this pin cannot see"
        );

        let mut literal = std::collections::BTreeSet::new();
        let mut used = std::collections::BTreeSet::new();
        for (i, _) in NM_C.match_indices("exit_code") {
            let raw = &NM_C[i + "exit_code".len()..];
            if raw.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_') {
                continue;
            }
            let after = raw.trim_start();
            let (or, rhs) = if let Some(r) = after.strip_prefix("|=") {
                (true, r)
            } else if after.starts_with("==") {
                continue;
            } else if let Some(r) = after.strip_prefix('=') {
                (false, r)
            } else {
                continue;
            };
            let rhs = rhs.split(';').next().unwrap_or_default().trim();
            if let Ok(n) = rhs.parse::<i32>() {
                assert!(!or, "nm.c ORs {n} into its exit code");
                literal.insert(n);
            } else if let Some(&(name, _)) = named.iter().find(|(n, _)| *n == rhs) {
                assert!(!or, "nm.c ORs {name} into its exit code");
                used.insert(name);
            } else if rhs == "(rc < 0)" {
                literal.insert(1);
                if !or {
                    literal.insert(0);
                }
            } else {
                panic!("nm.c sets its exit code from `{rhs}`, which this pin cannot resolve");
            }
        }

        for (name, rust) in named {
            assert!(
                used.contains(name),
                "nm.c never exits with {name}, but src/nm.rs still reads {rust} as the engine \
                 being unreachable"
            );
        }
        for c in &literal {
            assert!(
                !Nm::engine_is_unreachable(Some(*c)),
                "nm.c exits {c} for something other than an unreachable engine, and src/nm.rs \
                 reads {c} as the engine being unreachable"
            );
        }
        for c in 0..=255 {
            assert_eq!(
                Nm::engine_is_unreachable(Some(c)),
                named.iter().any(|&(_, v)| v == c),
                "src/nm.rs reads exit {c} differently from what nm.h says it means"
            );
        }
    }

    #[test]
    fn a_line_the_parser_cannot_read_is_counted_not_just_dropped() {
        let (v, unread) = parse_list_counted(
            "/product/x -> /data/adb/modules/M/x\n\
             \n\
             /system/y {something the engine grew later}\n\
             not a rule line\n",
        );
        assert_eq!(v.len(), 1);
        assert_eq!(unread, 2, "the blank line must not count, the other two must");
    }

    #[test]
    fn blank_lines_alone_are_never_counted_as_unreadable() {
        assert_eq!(parse_list_counted("\n\n   \n\t\n").1, 0);
    }

    #[test]
    fn parse_list_drops_empty_sides() {
        assert!(parse_list(" -> /data/x").is_empty());
        assert!(parse_list("/product/x -> ").is_empty());
        assert!(parse_list(" (whiteout)").is_empty());
    }

    #[test]
    fn batches_never_mix_public_and_private() {
        fn fake_public(p: &Path) -> bool {
            p.to_string_lossy().contains("/overlay/")
        }
        let a = Path::new("/system/lib64/a.so");
        let b = Path::new("/product/overlay/B.apk");
        let c = Path::new("/system/etc/c.conf");
        let d = Path::new("/product/overlay/D.apk");
        let src = Path::new("/data/adb/modules/M/x");
        let pairs = [(a, src), (b, src), (c, src), (d, src)];
        let groups = batch_groups(&pairs, fake_public);
        assert_eq!(groups.len(), 2);
        assert!(!groups[0].0, "the private group comes first");
        assert_eq!(groups[0].1, vec![(a, src), (c, src)]);
        assert!(groups[1].0, "the --public group comes second");
        assert_eq!(groups[1].1, vec![(b, src), (d, src)]);
    }

    #[test]
    fn an_empty_group_is_dropped() {
        fn none_public(_: &Path) -> bool { false }
        let a = Path::new("/system/lib64/a.so");
        let src = Path::new("/data/adb/modules/M/x");
        let groups = batch_groups(&[(a, src)], none_public);
        assert_eq!(groups.len(), 1, "only the private group survives");
        assert!(!groups[0].0);
        assert!(batch_groups(&[], none_public).is_empty());
    }

    #[test]
    fn a_batch_fits_nms_argv_cap() {
        let paths = ADD_BATCH_PAIRS * 2;
        assert!(paths <= 64, "{paths} paths would be refused by nm");
    }

    #[test]
    fn parse_list_splits_on_the_last_arrow() {
        let v = parse_list("/system/etc/a -> b -> /data/adb/modules/M/x\n");
        assert_eq!(v[0].target, PathBuf::from("/system/etc/a -> b"));
        assert_eq!(v[0].source.as_deref(), Some(Path::new("/data/adb/modules/M/x")));
    }
}
