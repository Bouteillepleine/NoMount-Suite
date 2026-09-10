//! Client for the hookless NoMount kernel engine

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

const DEFAULT_NM_BIN: &str = "/data/adb/modules/meta-nomount/bin/arm64-v8a/nm";

pub struct Nm {
    bin: String,
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

    fn engine_is_unreachable(code: Option<i32>) -> bool {
        matches!(code, Some(Nm::EXIT_TIMEOUT) | Some(Nm::EXIT_NO_ENGINE))
    }

    fn run_coded(&self, args: &[&str]) -> std::result::Result<String, Option<i32>> {
        let out = Command::new(&self.bin).args(args).output().map_err(|_| None)?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        Err(out.status.code())
    }

    fn run(&self, args: &[&str]) -> Result<String> {
        let out = Command::new(&self.bin)
            .args(args)
            .output()
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

    /// `nm v` - driver version; doubles as a liveness/engine check
    pub fn version(&self) -> Result<u32> {
        self.run(&["v"])?
            .trim()
            .parse::<u32>()
            .context("nm v: non-numeric version (engine not responding?)")
    }

    /// `nm add <virtual> <real>` - inject a VFS redirect
    pub fn add(&self, virtual_path: &Path, real: &Path) -> Result<()> {
        let public = crate::pmcache::is_pm_published(virtual_path);
        self.run(&add_argv(public, path_str(virtual_path)?, path_str(real)?))
            .map(drop)
    }

    /// `nm del <virtual>` - remove a redirect by its virtual path
    pub fn del(&self, virtual_path: &Path) -> Result<()> {
        self.run(&["del", path_str(virtual_path)?]).map(drop)
    }

    /// `nm w <path>` - whiteout (make a path appear absent)
    pub fn whiteout(&self, path: &Path) -> Result<()> {
        self.run(&["w", path_str(path)?]).map(drop)
    }

    /// `nm block <uid>` - hide injections from this UID (sus_path substitute)
    pub fn uid_block(&self, uid: u32) -> Result<()> {
        self.run(&["block", &crate::blocklist::appid(uid).to_string()])
            .map(drop)
    }

    /// `nm unblock <uid>`
    pub fn uid_unblock(&self, uid: u32) -> Result<()> {
        self.run(&["unblock", &crate::blocklist::appid(uid).to_string()])
            .map(drop)
    }

    /// `nm k i <0..3>` - which isolated-process pools per-UID hiding covers
    pub fn set_hide_isolated(&self, mode: u32) -> Result<()> {
        self.run(&["k", "i", &mode.to_string()]).map(drop)
    }

    /// `nm l u` - the kernel's live blocked-UID set (authoritative, straight from the driver's
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

    /// Tell the engine whether this device's ROM directories are dirent-packed, so a
    pub fn set_dir_shape(&self, packed: bool) -> Result<()> {
        self.run(&["k", "d", if packed { "1" } else { "0" }]).map(|_| ())
    }

    /// `nm clear` - drop all rules
    pub fn clear(&self) -> Result<()> {
        self.run(&["clear"]).map(drop)
    }

    /// `nm list` - current rules (raw text)
    pub fn list(&self) -> Result<String> {
        self.run(&["list"])
    }

    /// `nm l g` - the _ghost tables as `p /abs/path` and `u <uid>` lines
    pub fn ghost_list(&self) -> Result<String> {
        self.run(&["l", "g"])
    }

    /// `nm k g` with no value - the presence probe
    pub fn ghost_present(&self) -> bool {
        self.run(&["k", "g"]).is_ok()
    }

    /// `nm k g <cmd>` - one _ghost control command
    pub fn ghost_ctl(&self, cmd: &str) -> Result<()> {
        self.run(&["k", "g", cmd]).map(drop)
    }

    fn add_batch_coded(
        &self,
        public: bool,
        pairs: &[(&Path, &Path)],
    ) -> std::result::Result<(), Option<i32>> {
        let mut args: Vec<&str> = Vec::with_capacity(1 + usize::from(public) + pairs.len() * 2);
        args.push("add");
        if public {
            args.push("--public");
        }
        for (v, r) in pairs {
            args.push(path_str(v).map_err(|_| None)?);
            args.push(path_str(r).map_err(|_| None)?);
        }
        self.run_coded(&args).map(drop)
    }

}

const ADD_BATCH_PAIRS: usize = 31;

impl Nm {
    /// Apply many injections with as few processes as possible
    pub fn add_many<'a>(&self, pairs: &[(&'a Path, &'a Path)]) -> Vec<(&'a Path, &'a Path)> {
        let mut failed = Vec::new();
        let mut gave_up = false;
        for (public, group) in batch_groups(pairs, crate::pmcache::is_pm_published) {
            for chunk in group.chunks(ADD_BATCH_PAIRS) {
                if gave_up {
                    failed.extend(chunk.iter().copied());
                    continue;
                }
                let batch = self.add_batch_coded(public, chunk);
                if batch.is_ok() {
                    continue;
                }
                if Nm::engine_is_unreachable(batch.unwrap_err()) {
                    eprintln!(
                        "nomount: the engine stopped answering mid-pass - abandoning the                          remaining injections rather than retrying each one against it.                          {} rule(s) in this chunk and everything after it are unserved.",
                        chunk.len()
                    );
                    gave_up = true;
                    failed.extend(chunk.iter().copied());
                    continue;
                }
                for (v, r) in chunk {
                    match self.add_batch_coded(public, std::slice::from_ref(&(*v, *r))) {
                        Ok(_) => {}
                        Err(code) => {
                            failed.push((*v, *r));
                            if Nm::engine_is_unreachable(code) {
                                gave_up = true;
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

/// What a `nm list` line describes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveKind {
    Inject,
    Whiteout,
    VirtualDir,
}

/// One parsed `nm list` line
pub(crate) struct LiveRule {
    pub target: PathBuf,
    /// Present only for an [`LiveKind::Inject`]
    pub source: Option<PathBuf>,
    /// The ` [UID: N]` suffix, or 0 for a global rule
    pub uid: u32,
    pub kind: LiveKind,
    /// The engine printed the per-rule `(public)` flag (engine >= 17 reports flags)
    pub public: bool,
}

/// Parse `nm list` output into typed rules - the one parser of this text
pub(crate) fn parse_list(list: &str) -> Vec<LiveRule> {
    list.lines()
        .filter_map(|line| {
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
        })
        .collect()
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
