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
    /// Hide injections from a UID
    Block { uid: u32 },
    /// Re-show injections to a UID
    Unblock { uid: u32 },
}
