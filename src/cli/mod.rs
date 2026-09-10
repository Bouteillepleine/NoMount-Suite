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
    Ghost {
        #[command(subcommand)]
        action: GhostAction,
    },
    /// Umount every bind recorded in binds.list and put each source's own SELinux label back.
    ///
    /// Exists for uninstall.sh. `teardown_all` was reachable only from the boot mount pass,
    /// so an uninstall deleted binds.list - the only record of what we bound - while those
    /// binds were still mounted. Nothing could ever clean them up afterwards, and live bind
    /// mounts are the exact thing this module exists to avoid leaving behind.
    Unbind,
    Version,
}

#[derive(Subcommand)]
pub enum GhostAction {
    Sync,
    List,
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
        /// Silence the note when hiding it leaves a measurable hole. Nothing is ever refused
        /// on that ground -- declining would make the module asking for it a no-op -- so this
        /// only quiets a warning you have already read. `nomount check --plan` lists them all.
        #[arg(long)]
        force: bool,
    },
    Remove { path: String },
    List,
    Apply,
    Suggest,
}

/// Would this verb put injection state into the engine?
pub fn serves_injections(cmd: &Commands) -> bool {
    match cmd {
        Commands::Mount | Commands::Reload => true,
        Commands::Absorb { dry_run, .. } => !dry_run,
        Commands::Vfs { action } => {
            matches!(action, VfsAction::Add { .. } | VfsAction::Whiteout { .. })
        }
        Commands::Whiteout { action } => {
            matches!(action, WhiteoutAction::Add { .. } | WhiteoutAction::Apply)
        }
        _ => false,
    }
}

/// Does this verb change the state the kernel's `_ghost` tables are derived from?
pub fn changes_ghost_inputs(cmd: &Commands) -> bool {
    match cmd {
        Commands::Uid { action } => matches!(
            action,
            UidAction::Block { .. }
                | UidAction::Unblock { .. }
                | UidAction::Apply { .. }
                | UidAction::Preset { name: Some(_), dry_run: false, .. }
        ),
        Commands::Vfs { action } => matches!(
            action,
            VfsAction::Add { .. }
                | VfsAction::Del { .. }
                | VfsAction::Whiteout { .. }
                | VfsAction::Clear
        ),
        Commands::Whiteout { action } => matches!(
            action,
            WhiteoutAction::Add { .. } | WhiteoutAction::Remove { .. } | WhiteoutAction::Apply
        ),
        Commands::Absorb { dry_run, .. } => !dry_run,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The verbs the bootloop guard has to hold off: each ends with more being served than
    #[test]
    fn every_serving_verb_is_refused_while_the_guard_is_tripped() {
        for c in [
            Commands::Mount,
            Commands::Reload,
            Commands::Absorb { dry_run: false, include_dirs: false, early: false },
            Commands::Vfs {
                action: VfsAction::Add { virtual_path: "/a".into(), real_path: "/b".into() },
            },
            Commands::Vfs { action: VfsAction::Whiteout { path: "/a".into() } },
            Commands::Whiteout { action: WhiteoutAction::Add { path: "/a".into(), force: false } },
            Commands::Whiteout { action: WhiteoutAction::Apply },
        ] {
            assert!(serves_injections(&c), "a serving verb must be refused on a parked device");
        }
    }

    /// ...and the guard must not block its own recovery
    #[test]
    fn the_guard_never_blocks_diagnosis_or_removal() {
        for c in [
            Commands::Check { plan: false, device: false, json: false, write: false },
            Commands::Plan,
            Commands::Absorb { dry_run: true, include_dirs: false, early: false },
            Commands::Export { dir: None },
            Commands::Snapshot,
            Commands::Verify,
            Commands::Vfs { action: VfsAction::Del { virtual_path: "/a".into() } },
            Commands::Vfs { action: VfsAction::Clear },
            Commands::Vfs { action: VfsAction::List },
            Commands::Whiteout { action: WhiteoutAction::Remove { path: "/a".into() } },
            Commands::Whiteout { action: WhiteoutAction::List },
            Commands::Whiteout { action: WhiteoutAction::Suggest },
            Commands::Uid { action: UidAction::Block { target: "com.a".into(), force: false } },
            Commands::Uid { action: UidAction::Unblock { target: "com.a".into() } },
            Commands::Uid { action: UidAction::Apply { early: false } },
            Commands::Uid { action: UidAction::List },
            Commands::Ghost { action: GhostAction::Sync },
            Commands::Ghost { action: GhostAction::List },
            Commands::Version,
        ] {
            assert!(
                !serves_injections(&c),
                "the guard must not block diagnosis, removal or the hide list"
            );
        }
    }

    /// The verbs that move an input
    #[test]
    fn every_mutating_verb_resyncs_the_cloak() {
        for c in [
            Commands::Uid { action: UidAction::Block { target: "com.a".into(), force: false } },
            Commands::Uid { action: UidAction::Unblock { target: "com.a".into() } },
            Commands::Uid { action: UidAction::Apply { early: false } },
            Commands::Uid {
                action: UidAction::Preset {
                    name: Some("detectors".into()),
                    dry_run: false,
                    globs: false,
                },
            },
            Commands::Vfs {
                action: VfsAction::Add { virtual_path: "/a".into(), real_path: "/b".into() },
            },
            Commands::Vfs { action: VfsAction::Del { virtual_path: "/a".into() } },
            Commands::Vfs { action: VfsAction::Whiteout { path: "/a".into() } },
            Commands::Vfs { action: VfsAction::Clear },
            Commands::Whiteout { action: WhiteoutAction::Add { path: "/a".into(), force: false } },
            Commands::Whiteout { action: WhiteoutAction::Remove { path: "/a".into() } },
            Commands::Whiteout { action: WhiteoutAction::Apply },
            Commands::Absorb { dry_run: false, include_dirs: false, early: false },
        ] {
            assert!(changes_ghost_inputs(&c), "a mutating verb must re-derive the _ghost tables");
        }
    }

    /// A verb that promises to change nothing must not fork a probe child and rewrite two
    #[test]
    fn read_only_and_self_syncing_verbs_do_not() {
        for c in [
            Commands::Uid { action: UidAction::List },
            Commands::Uid { action: UidAction::Isolated { mode: None } },
            Commands::Uid {
                action: UidAction::Preset { name: None, dry_run: true, globs: false },
            },
            Commands::Uid {
                action: UidAction::Preset { name: None, dry_run: false, globs: false },
            },
            Commands::Vfs { action: VfsAction::List },
            Commands::Whiteout { action: WhiteoutAction::List },
            Commands::Whiteout { action: WhiteoutAction::Suggest },
            Commands::Absorb { dry_run: true, include_dirs: false, early: false },
            Commands::Mount,
            Commands::Reload,
            Commands::Plan,
            Commands::Check { plan: false, device: false, json: false, write: false },
            Commands::Snapshot,
            Commands::Verify,
            Commands::Export { dir: None },
            Commands::Ghost { action: GhostAction::List },
            Commands::Version,
        ] {
            assert!(!changes_ghost_inputs(&c), "a read-only verb must not re-derive anything");
        }
    }
}
