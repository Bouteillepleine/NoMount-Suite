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

/// Default location of the bundled `nm` binary (installed by the module under
/// its own `bin/`). Overridable via `NM_BIN` for testing / relocation.
const DEFAULT_NM_BIN: &str = "/data/adb/modules/nomount/bin/nm";

pub struct Nm {
    bin: String,
}

impl Nm {
    pub fn new() -> Self {
        let bin = std::env::var("NM_BIN").unwrap_or_else(|_| DEFAULT_NM_BIN.to_string());
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
