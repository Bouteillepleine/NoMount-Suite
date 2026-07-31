pub mod handlers;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "nomount",
    version = env!("CARGO_PKG_VERSION"),
    about = "NoMount Suite metamodule + CLI for the hookless VFS engine (nm netlink)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Metamodule mount pass: classify enabled modules and route them
    /// (hookless inject / RRO overlay). su is external (sucompat).
    Mount,
    /// Direct VFS-engine operations via the hookless `nm` client
    Vfs {
        #[command(subcommand)]
        action: VfsAction,
    },
    /// Per-UID hiding (sus_path substitute)
    Uid {
        #[command(subcommand)]
        action: UidAction,
    },
    /// Lint the mount plan (and live rules) for known bootloop/no-op hazards
    Doctor,
    /// Runtime health check: engine liveness, injection consistency, per-UID
    /// self-consistency canary, guard state. `--write` persists to health.txt.
    Selfcheck {
        /// Persist the result to /data/adb/nomount/health.txt (used at boot)
        #[arg(long)]
        write: bool,
    },
    /// Freeze the current healthy fingerprint as the baseline for `verify`
    Snapshot,
    /// Diff the live fingerprint against the saved snapshot; name what drifted
    Verify,
    /// Dump diagnostics to a timestamped folder (default /sdcard/Download)
    Export {
        /// Destination directory (a nm-diag-<ts> subfolder is created inside)
        dir: Option<String>,
    },
    /// Print version
    Version,
}

#[derive(Subcommand)]
pub enum VfsAction {
    /// Add a redirect (virtual_path -> real_path)
    Add { virtual_path: String, real_path: String },
    /// Delete a redirect by virtual path
    Del { virtual_path: String },
    /// Whiteout a path (make it appear absent)
    Whiteout { path: String },
    /// Clear all rules
    Clear,
    /// List active rules
    List,
}

#[derive(Subcommand)]
pub enum UidAction {
    /// Hide injections from an app — accepts a package name (durable) or a bare
    /// UID. Persists across reboots.
    Block { target: String },
    /// Re-show injections to an app — package name or bare UID. Also removes it
    /// from the persistent list.
    Unblock { target: String },
    /// Show the persistent block list with each entry's resolved UID and state
    List,
    /// Re-apply the persistent block list to the kernel (run at boot)
    Apply,
}
