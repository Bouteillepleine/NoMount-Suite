//! Client for the **hookless** NoMount kernel engine.
//!
//! The hookless driver has no `/dev/nomount` char device — it speaks a PRIVATE
//! RAW netlink protocol (`NOMOUNT_NL_PROTO`), driven by the freestanding `nm`
//! binary. The generic-netlink family it used to register was resolvable by any
//! caller through `CTRL_CMD_GETFAMILY`, which is an enumeration oracle, so the
//! control plane moved off genl entirely. Rather than reimplement the wire
//! protocol here, the Suite shells out to `nm` (which already owns it).
//!
//! Kernel and client must therefore be flashed as a SET: a genl-era `nm` gets no
//! answer from a raw-netlink kernel, and nothing about the version number warns
//! you — it reads as "engine not responding".
//!
//! CLI verbs (first-char dispatch in `nm`): `add <virtual> <real>`, `w <path>`
//! (whiteout), `block`/`unblock <uid>`, `clear`, `list`, `v` (version).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

/// Last-resort location of the bundled `nm` binary. Only used if `NM_BIN` is
/// unset AND we cannot resolve our own path; both normal callers (metamount.sh
/// and the WebUI) export `NM_BIN`.
const DEFAULT_NM_BIN: &str = "/data/adb/modules/meta-nomount/bin/arm64-v8a/nm";

pub struct Nm {
    bin: String,
}

impl Nm {
    pub fn new() -> Self {
        // Resolution order:
        //   1. $NM_BIN                     — explicit override (what callers set)
        //   2. `nm` beside this executable — the module ships bin/<abi>/{nomount,nm}
        //      as siblings, so this stays correct for any module id and any ABI.
        //   3. DEFAULT_NM_BIN              — fixed path, arm64 layout
        // The old default was "/data/adb/modules/nomount/bin/nm", which was wrong
        // twice over: the module id is meta-nomount, and the binaries live under a
        // per-ABI subdirectory. It never fired in practice (callers set NM_BIN) but
        // made a bare `nomount uid ...` from a root shell fail with ENOENT.
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

    /// `nm v` — driver version; doubles as a liveness/engine check.
    pub fn version(&self) -> Result<u32> {
        self.run(&["v"])?
            .trim()
            .parse::<u32>()
            .context("nm v: non-numeric version (engine not responding?)")
    }

    /// `nm add <virtual> <real>` — inject a VFS redirect.
    /// `virtual_path` is the on-device target (e.g. `/system/app/Foo/Foo.apk`);
    /// `real` is the backing module file. Mountless.
    ///
    /// A PM-published file is added with `--public`, i.e. it stays visible to an
    /// app on the hide list. This is the one class of injection the system
    /// advertises to that app by other means: the PackageManager scans the ROM
    /// package directories as system_server (never hidden), registers what it
    /// finds, and then hands the whole codePath to any app that asks about the
    /// package -- the APK AND its nativeLibraryDir `.so` files. Hiding any of them
    /// leaves such an app holding a path the PM says exists and `open()` answers
    /// ENOENT for -- a far louder inconsistency than the injection, and one that is
    /// not merely theoretical: IBM Trusteer (La Banque Postale) walks the package
    /// list at startup, calls getResourcesForApplication() on every entry, and
    /// SIGSEGVs on the IOException from 139 unopenable /product/overlay APKs.
    ///
    /// Deciding it HERE rather than per call site is deliberate: every caller
    /// wants the same answer, and a new one that forgets would reintroduce the
    /// crash for whichever module it serves. The flag is safe to set broadly --
    /// the kernel strips it from any rule that turns out to shadow a stock file,
    /// so only an ADDED APK is ever exempted, and an engine older than 15 drops
    /// it with every other unknown bit (`nomount check --plan` reports that case).
    pub fn add(&self, virtual_path: &Path, real: &Path) -> Result<()> {
        let public = crate::pmcache::is_pm_published(virtual_path);
        self.run(&add_argv(public, path_str(virtual_path)?, path_str(real)?))
            .map(drop)
    }

    /// `nm del <virtual>` — remove a redirect by its virtual path.
    pub fn del(&self, virtual_path: &Path) -> Result<()> {
        self.run(&["del", path_str(virtual_path)?]).map(drop)
    }

    /// `nm w <path>` — whiteout (make a path appear absent).
    pub fn whiteout(&self, path: &Path) -> Result<()> {
        self.run(&["w", path_str(path)?]).map(drop)
    }

    /// `nm block <uid>` — hide injections from this UID (sus_path substitute).
    /// Normalised to the appid, which is what the kernel stores and matches, so
    /// one entry covers the app in every user, work profile and clone.
    pub fn uid_block(&self, uid: u32) -> Result<()> {
        self.run(&["block", &crate::blocklist::appid(uid).to_string()])
            .map(drop)
    }

    /// `nm unblock <uid>`. Same normalisation as `uid_block`.
    pub fn uid_unblock(&self, uid: u32) -> Result<()> {
        self.run(&["unblock", &crate::blocklist::appid(uid).to_string()])
            .map(drop)
    }

    /// `nm k i <0..3>` — which isolated-process pools per-UID hiding covers.
    /// Runtime state like the blocked set itself (a reboot or `nm clear` resets
    /// it), so every apply pass re-asserts it from the persisted setting.
    pub fn set_hide_isolated(&self, mode: u32) -> Result<()> {
        self.run(&["k", "i", &mode.to_string()]).map(drop)
    }

    /// `nm l u` — the kernel's **live** blocked-UID set (authoritative, straight
    /// from the driver's idr via `NM_CMD_GET_UIDS`), independent of the on-disk
    /// block list. The client prints a JSON array; we just harvest the integers.
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

    /// Tell the engine whether this device's ROM directories are dirent-packed,
    /// so a synthesized directory reports the erofs-shaped size instead of the
    /// 4096 placeholder. The engine cannot determine this itself on an
    /// overlay-backed path -- see `crate::dirshape`.
    pub fn set_dir_shape(&self, packed: bool) -> Result<()> {
        self.run(&["k", "d", if packed { "1" } else { "0" }]).map(|_| ())
    }

    /// `nm clear` — drop all rules. (No enable/refresh: hookless activates a
    /// rule the moment it's added, via per-inode ops hijack.)
    pub fn clear(&self) -> Result<()> {
        self.run(&["clear"]).map(drop)
    }

    /// `nm list` — current rules (raw text).
    pub fn list(&self) -> Result<String> {
        self.run(&["list"])
    }

    /// `nm l g` — the _ghost tables as `p /abs/path` and `u <uid>` lines.
    /// Errors on an engine below v26, where the knob does not exist.
    pub fn ghost_list(&self) -> Result<String> {
        self.run(&["l", "g"])
    }

    /// `nm k g` with no value — the presence probe. Exits 0 only when the
    /// _ghost patch set is compiled in AND the engine is >= v26 (below that the
    /// knob does not exist and the kernel answers -EINVAL), so this is what
    /// keeps the whole sync inert on every other kernel.
    pub fn ghost_present(&self) -> bool {
        self.run(&["k", "g"]).is_ok()
    }

    /// `nm k g <cmd>` — one _ghost control command. See ghost.h for the
    /// vocabulary; `p=`/`u=` replace a whole table under one lock and are what
    /// [`crate::ghost`] uses, so a reader never sees a half-built table.
    pub fn ghost_ctl(&self, cmd: &str) -> Result<()> {
        self.run(&["k", "g", cmd]).map(drop)
    }

    /// `nm add` for MANY rules in one process.
    ///
    /// `nm` has always accepted up to 32 add-pairs per invocation -- it batches
    /// them into one netlink payload and refuses (rather than truncating) past
    /// 64 argv words. `add()` passed exactly one, so a 260-rule device paid 260
    /// fork+exec pairs during post-fs-data. That is not just slow: it is the
    /// root-exec burst OOS's kevent heuristic flags, which `service.sh`'s own
    /// ghost block explicitly avoids ("ONE `su` for the whole list: 260 separate
    /// ones is slow at boot and is exactly the root-exec burst OOS flags") while
    /// the mount pass did it anyway.
    ///
    /// `--public` is per-INVOCATION, not per-pair, so callers must group by it;
    /// [`add_many`] does that and returns the pairs it could not confirm.
    ///
    /// Returns `Err` only if the whole batch failed. Because `nm` reports one
    /// status for the batch, a partial failure is indistinguishable from a total
    /// one -- so the caller must fall back to per-rule adds to find out which,
    /// which is what [`add_many`] does.
    fn add_batch(&self, public: bool, pairs: &[(&Path, &Path)]) -> Result<()> {
        let mut args: Vec<&str> = Vec::with_capacity(1 + usize::from(public) + pairs.len() * 2);
        args.push("add");
        if public {
            args.push("--public");
        }
        for (v, r) in pairs {
            args.push(path_str(v)?);
            args.push(path_str(r)?);
        }
        self.run(&args).map(drop)
    }
}

/// `nm`'s argv cap is 64 non-option words; `add` consumes two per rule. Leave a
/// word of headroom for `--public` so the option never pushes a batch over.
const ADD_BATCH_PAIRS: usize = 31;

impl Nm {
    /// Apply many injections with as few processes as possible.
    ///
    /// Returns the subset of `pairs` that could NOT be applied. The happy path
    /// costs one exec per 31 rules; only a batch that fails is re-tried one rule
    /// at a time, so per-rule failure attribution -- which `mount.rs` reports and
    /// `check` reads -- is preserved exactly.
    pub fn add_many<'a>(&self, pairs: &[(&'a Path, &'a Path)]) -> Vec<(&'a Path, &'a Path)> {
        let mut failed = Vec::new();
        for (public, group) in batch_groups(pairs, crate::pmcache::is_pm_published) {
            for chunk in group.chunks(ADD_BATCH_PAIRS) {
                if self.add_batch(public, chunk).is_ok() {
                    continue;
                }
                // The batch said no. Which rule? `nm` ORs its per-rule status
                // into one exit code, so ask again, one at a time.
                for (v, r) in chunk {
                    if self.add_batch(public, std::slice::from_ref(&(*v, *r))).is_err() {
                        failed.push((*v, *r));
                    }
                }
            }
        }
        failed
    }
}

/// Split `pairs` into the two `--public` groups, preserving order within each.
///
/// Pure, and split out so the grouping is testable: `--public` is an
/// invocation-wide flag on `nm`, so a batch that mixes the two would either mark
/// a private rule public (leaking module bytes to a hidden app -- the kernel
/// refuses that on a shadowing rule, but not on an added one) or drop the flag
/// from a PM-published APK, which is the IBM Trusteer SIGSEGV `Nm::add` documents.
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

/// The argv `add` hands to `nm`. Split out so the option spelling is pinned by a
/// test: the client takes any non-option word as a path, so a misspelt flag would
/// silently become the virtual path of the rule it was meant to mark. (The client
/// now refuses an unknown `--` word for the same reason; this catches it here.)
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

/// What a `nm list` line describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LiveKind {
    /// `<target> -> <source>`; source carried in [`LiveRule::source`].
    Inject,
    /// `<target> (whiteout)`.
    Whiteout,
    /// `<target> (virtual dir)`, materialised by the engine, not by a rule.
    VirtualDir,
}

/// One parsed `nm list` line.
pub(crate) struct LiveRule {
    pub target: PathBuf,
    /// Present only for an [`LiveKind::Inject`].
    pub source: Option<PathBuf>,
    /// The ` [UID: N]` suffix, or 0 for a global rule. Part of a rule's identity:
    /// a per-UID rule and a global one can name the SAME target, and `nm del`
    /// only ever addresses uid 0.
    pub uid: u32,
    pub kind: LiveKind,
    /// The engine printed the per-rule `(public)` flag (engine >= 17 reports
    /// flags). A PM-published rule live WITHOUT it is the hazard M-S1 names.
    pub public: bool,
}

/// Parse `nm list` output into typed rules -- the ONE parser of this text.
///
/// There were three: `doctor::parse_live`, `mount::parse_live_rules` and
/// `absorb::live_injections`, each reading the same lines with its own rules.
/// They had already drifted (one split on the FIRST ` -> `, the others on the
/// last; only one peeled ` (public)`, so the other two silently folded the flag
/// into the source path and every metadata comparison against it failed), and
/// nothing made them drift back. Each caller now derives its own shape from these
/// rows instead, so a change to the client's output format is one edit.
///
/// `nm list` appends flag suffixes: ` (public)` on a hiding opt-out, plus the
/// kind markers ` (whiteout)` / ` (virtual dir)`, plus the ` [UID: N]` identity.
/// Peel them all first, in any order, then split on the LAST ` -> ` so a target
/// path containing one is not mis-split.
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

    /// The flag is what keeps a PackageManager-registered APK readable by an app
    /// on the hide list, so its spelling and position are load-bearing: `nm` reads
    /// argv positionally and a word it does not recognise as an option used to
    /// become a path.
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

    /// The policy `add` applies, stated where it is easy to check: everything PM
    /// scans and publishes -- the APK and the nativeLibraryDir .so under a package
    /// dir -- opts out of hiding, everything else a module ships does not.
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
        // The whiteout and virtual-dir lines are kept -- doctor's partition-root
        // check must see them.
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
        // The ` (public)` flag must be peeled or it lands in the source path and
        // every fs::metadata(source) check silently no-ops.
        let v = parse_list("/product/x.apk -> /data/adb/modules/M/x.apk (public) [UID: 10123]\n");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].source.as_deref(), Some(Path::new("/data/adb/modules/M/x.apk")));
        assert!(v[0].public);
        // ...and the UID it was scoped to is kept, not dropped: it is part of the
        // rule's identity, and `nm del` only ever addresses uid 0.
        assert_eq!(v[0].uid, 10123);
        // A whiteout that also carried a flag is still classified as a whiteout,
        // in EITHER order -- the client emits the kind marker first and the flag
        // after it (`nm.c`: is_whiteout, then is_public), and whiteout.rs's
        // "is this applied?" set is built off `kind`, so a rule this dropped
        // would report a live whiteout as "not applied".
        for line in ["/system/y (public) (whiteout)\n", "/system/y (whiteout) (public)\n"] {
            let w = parse_list(line);
            assert_eq!(w.len(), 1, "{line:?}");
            assert_eq!(w[0].kind, LiveKind::Whiteout, "{line:?}");
            assert_eq!(w[0].target, PathBuf::from("/system/y"), "{line:?}");
            assert!(w[0].public, "{line:?}");
        }
        // A plain inject has no flag and is global.
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

    /// `--public` is per-INVOCATION, so a batch may never mix the two kinds.
    /// Getting this wrong is not cosmetic: dropping the flag from a
    /// PM-published APK reintroduces the crash `Nm::add`'s doc comment
    /// describes, and adding it to a private rule marks module bytes readable
    /// by an app the engine is hiding from.
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

    /// An empty side must not produce an empty invocation: `nm add` with no
    /// operand is an error, and used to be reported as success.
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

    /// The chunk size has to leave room for the `add` verb and `--public`
    /// inside nm's 64-word argv cap, which it refuses to exceed rather than
    /// silently truncating.
    #[test]
    fn a_batch_fits_nms_argv_cap() {
        let words = 1 + 1 + ADD_BATCH_PAIRS * 2; // add + --public + two per pair
        assert!(words <= 64, "{words} argv words would be refused by nm");
    }

    /// A source path containing ` -> ` must not move the split: the source is
    /// whatever follows the LAST arrow.
    #[test]
    fn parse_list_splits_on_the_last_arrow() {
        let v = parse_list("/system/etc/a -> b -> /data/adb/modules/M/x\n");
        assert_eq!(v[0].target, PathBuf::from("/system/etc/a -> b"));
        assert_eq!(v[0].source.as_deref(), Some(Path::new("/data/adb/modules/M/x")));
    }
}
