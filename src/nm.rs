//! Client for the **hookless** NoMount kernel engine.
//!
//! The hookless driver has no `/dev/nomount` char device — it's a Generic
//! Netlink family (`nomount`) driven by the freestanding `nm` binary. Rather
//! than reimplement the genl wire protocol here, the Suite shells out to `nm`
//! (which already owns it). This replaces the old ioctl `/dev/nomount` path.
//!
//! CLI verbs (first-char dispatch in `nm`): `add <virtual> <real>`, `w <path>`
//! (whiteout), `block`/`unblock <uid>`, `clear`, `list`, `v` (version).

use std::path::Path;
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
    pub fn add(&self, virtual_path: &Path, real: &Path) -> Result<()> {
        self.run(&["add", path_str(virtual_path)?, path_str(real)?])
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
    pub fn uid_block(&self, uid: u32) -> Result<()> {
        self.run(&["block", &uid.to_string()]).map(drop)
    }

    /// `nm unblock <uid>`.
    pub fn uid_unblock(&self, uid: u32) -> Result<()> {
        self.run(&["unblock", &uid.to_string()]).map(drop)
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

    /// `nm clear` — drop all rules. (No enable/refresh: hookless activates a
    /// rule the moment it's added, via per-inode ops hijack.)
    pub fn clear(&self) -> Result<()> {
        self.run(&["clear"]).map(drop)
    }

    /// `nm list` — current rules (raw text).
    pub fn list(&self) -> Result<String> {
        self.run(&["list"])
    }
}

impl Default for Nm {
    fn default() -> Self {
        Self::new()
    }
}

fn path_str(p: &Path) -> Result<&str> {
    p.to_str()
        .with_context(|| format!("non-UTF8 path: {}", p.display()))
}
