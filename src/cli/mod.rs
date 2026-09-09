pub mod handlers;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "nomount",
    version = env!("CARGO_PKG_VERSION"),
    about = "NoMount Suite metamodule + CLI for the Prism VFS engine (nm netlink)"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Mount,
    Vfs {
        #[command(subcommand)]
        action: VfsAction,
    },
    Uid {
        #[command(subcommand)]
        action: UidAction,
    },
    Absorb {
        /// Report what would be absorbed without changing anything
        #[arg(long)]
        dry_run: bool,
        /// Also absorb directory binds
        #[arg(long)]
        include_dirs: bool,
        /// Pre-zygote pass
        #[arg(long)]
        early: bool,
    },
    Whiteout {
        #[command(subcommand)]
        action: WhiteoutAction,
    },
    Check {
        /// Only the static half: does the module set resolve into a bad rule?
        #[arg(long)]
        plan: bool,
        /// Only the measured half: is what we serve detectable on this device, and is it being
        #[arg(long)]
        device: bool,
        /// Emit one JSON object instead of prose
        #[arg(long)]
        json: bool,
        /// Also cache to /data/adb/nomount/audit.json, and (unless --plan) write the fingerprint
        #[arg(long)]
        write: bool,
    },
    Plan,
    Reload,
    Snapshot,
    Verify,
    Export {
        dir: Option<String>,
    },
    Version,
}

#[derive(Subcommand)]
pub enum VfsAction {
    Add { virtual_path: String, real_path: String },
    Del { virtual_path: String },
    Whiteout { path: String },
    Clear,
    List,
}

#[derive(Subcommand)]
pub enum UidAction {
    Block {
        target: String,
        /// Allow a platform appid (< 10000: root, system_server, shell ...)
        #[arg(long)]
        force: bool,
    },
    Unblock { target: String },
    List,
    Apply {
        /// Early-boot pass: resolve from the cached appid mirror first, so it works at
        #[arg(long)]
        early: bool,
    },
    Preset {
        name: Option<String>,
        /// Print what would be added without touching the list
        #[arg(long)]
        dry_run: bool,
        /// Only the glob rules, not the exact package names
        #[arg(long)]
        globs: bool,
    },
    Isolated {
        mode: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum WhiteoutAction {
    Add {
        path: String,
        /// Hide it anyway on a filesystem where the hole is measurable (see the refusal message)
        #[arg(long)]
        force: bool,
    },
    Remove { path: String },
    List,
    Apply,
    Suggest,
}
