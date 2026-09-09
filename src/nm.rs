//! Client for the hookless NoMount kernel engine

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Last-resort location of the bundled `nm` binary
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

    fn run(&self, args: &[&str]) -> Result<String> {
        let out = Command::new(&self.bin)
            .args(args)
            .output()
            .with_context(|| format!("exec {} {:?}", self.bin, args))?;
        if !out.status.success() {
            bail!(
                "nm {:?} failed (code {:?}): {}",
                args,
                out.status.code(),
                String::from_utf8_lossy(&out.stderr).trim()
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
}

/// The argv `add` hands to `nm`
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

    /// The flag is what keeps a PackageManager-registered APK readable by an app on the hide
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

    /// The policy `add` applies, stated where it is easy to check: everything pm scans and
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
        let w = parse_list("/system/y (public) (whiteout)\n");
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].kind, LiveKind::Whiteout);
        assert!(w[0].public);
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

    /// A source path containing ` -> ` must not move the split: the source is whatever follows
    #[test]
    fn parse_list_splits_on_the_last_arrow() {
        let v = parse_list("/system/etc/a -> b -> /data/adb/modules/M/x\n");
        assert_eq!(v[0].target, PathBuf::from("/system/etc/a -> b"));
        assert_eq!(v[0].source.as_deref(), Some(Path::new("/data/adb/modules/M/x")));
    }
}
