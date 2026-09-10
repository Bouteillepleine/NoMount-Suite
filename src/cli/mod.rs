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
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        include_dirs: bool,
        #[arg(long)]
        early: bool,
    },
    Whiteout {
        #[command(subcommand)]
        action: WhiteoutAction,
    },
    Check {
        #[arg(long)]
        plan: bool,
        #[arg(long)]
        device: bool,
        #[arg(long)]
        json: bool,
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
        #[arg(long)]
        force: bool,
    },
    Unblock { target: String },
    List,
    Apply {
        #[arg(long)]
        early: bool,
    },
    Preset {
        name: Option<String>,
        #[arg(long)]
        dry_run: bool,
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
        #[arg(long)]
        force: bool,
    },
    Remove { path: String },
    List,
    Apply,
    Suggest,
}
