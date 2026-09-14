pub mod handlers;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "nomount",
    version = env!("CARGO_PKG_VERSION"),
    about = "NoMount Suite metamodule + CLI for the Prism VFS engine (nm netlink)",
    after_help = "\
Start here:
  nomount check              is anything wrong, and is what I serve detectable?
  nomount reload             pick up a module you just installed, without rebooting
  nomount uid block <pkg>    hide everything the Suite serves from one app

The boot scripts run `mount`, `absorb`, `reload` and `ghost sync` themselves;
you rarely need those by hand."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// The boot pass: classify enabled modules and route them into Prism injections
    Mount,
    /// Live engine rules - add, remove or inspect one injection at a time
    Vfs {
        #[command(subcommand)]
        action: VfsAction,
    },
    /// The per-app hide list: who cannot see what the Suite serves
    Uid {
        #[command(subcommand)]
        action: UidAction,
    },
    /// Take over bind mounts other modules made: re-serve each as an injection, then unmount it
    #[command(after_help = "Runs itself every boot. `--dry-run` first if you want to see the plan.")]
    Absorb {
        /// Show what would be absorbed, dropped or left alone; change nothing
        #[arg(long)]
        dry_run: bool,
        /// Also absorb whole-directory binds, not just file binds
        #[arg(long)]
        include_dirs: bool,
        /// The pre-zygote pass: may take my_* mounts, which the runtime pass refuses
        #[arg(long)]
        early: bool,
    },
    /// The durable hide-a-path list, re-applied on every boot
    Whiteout {
        #[command(subcommand)]
        action: WhiteoutAction,
    },
    /// THE diagnostic: is anything wrong, and is what the Suite serves detectable?
    #[command(after_help = "\
Verdicts: FAIL, REBOOT, UNMEASURED, WARN, PASS, N/A, NOTE. \"nothing to test\" and
\"something stopped me testing\" are deliberately different, and neither is a pass.
Exits 1 on a FAIL.

  nomount check              both sections
  nomount check --device     only what can be measured on this device
  nomount check --json       machine-readable, for a script or a bug report")]
    Check {
        /// Static only: does the module set resolve into a bad rule?
        #[arg(long)]
        plan: bool,
        /// Measured only: is what we serve detectable, and is it actually being served?
        #[arg(long)]
        device: bool,
        /// Emit the report as JSON on stdout
        #[arg(long)]
        json: bool,
        /// Also write the report to /data/adb/nomount for the WebUI to read
        #[arg(long)]
        write: bool,
    },
    /// Print what the mount pass would resolve to, without applying it
    Plan,
    /// Reconcile live rules to the current module set, delta only - use after installing a module
    Reload,
    /// Freeze the current fingerprint as the baseline `verify` compares against
    Snapshot,
    /// Diff live against the snapshot baseline and name what drifted
    Verify,
    /// Dump diagnostics to a folder for a bug report
    #[command(after_help = "\
On shared storage (/sdcard) everything naming the apps you hide is withheld - the
hide-list files, spoof.conf and boot.log - and the bundle says so. Export to a
private path (e.g. /data/local/tmp/nm-report) to include them.")]
    Export {
        /// Where to write the bundle (default: a timestamped folder in /sdcard/Download)
        dir: Option<String>,
    },
    /// The existence cloak: make injected-only paths look absent, not merely unreadable
    Ghost {
        #[command(subcommand)]
        action: GhostAction,
    },
    /// Unmount the real binds recorded in binds.list (the my_* ones)
    Unbind,
    /// Print the version
    Version,
}

#[derive(Subcommand)]
pub enum GhostAction {
    /// Work out which injected-only paths can be made to look absent, and program them
    Sync,
    /// Show what the cloak currently covers
    List,
}

#[derive(Subcommand)]
pub enum VfsAction {
    /// Serve the contents of <REAL_PATH> at <VIRTUAL_PATH>
    Add {
        /// The ROM path an app will read
        virtual_path: String,
        /// The file that actually gets served, normally under /data/adb
        real_path: String,
    },
    /// Remove one live rule
    Del {
        /// The ROM path whose rule to drop
        virtual_path: String,
    },
    /// Make a path appear absent - this rule only, not the durable list
    Whiteout {
        /// The ROM path to hide
        path: String,
    },
    /// Flush every live rule (the boot pass puts them back on the next reboot)
    #[command(after_help = "\
Nothing is served afterwards until the rules come back. `nomount mount` rebuilds them from
the installed modules without a reboot; a reboot does the same. Your hide list, whiteouts
and settings are untouched - this clears the engine's live table only.")]
    Clear,
    /// Show live rules
    List,
}

#[derive(Subcommand)]
pub enum UidAction {
    /// Hide everything the Suite serves from an app
    #[command(alias = "hide", after_help = "\
Matches on appid, so one entry covers the app in every user profile, its clones
and its sandbox.

  nomount uid block com.example.app
  nomount uid block 'com.example.*'      a glob; refused if it is dangerously broad")]
    Block {
        /// A package name, a numeric uid, or a glob over package names
        target: String,
        /// Override the two refusals: a glob that matches far more packages than expected,
        /// and a target below the app range (1000 system_server, 2000 shell, 0 root)
        #[arg(long)]
        force: bool,
    },
    /// Stop hiding from an app
    #[command(alias = "unhide")]
    Unblock {
        /// A package name or numeric uid
        target: String,
    },
    /// Who is hidden
    List,
    /// Re-apply the hide list (run automatically when a package is installed or removed)
    Apply {
        /// The pre-zygote pass
        #[arg(long)]
        early: bool,
    },
    /// Add a curated set of known detectors to the hide list
    Preset {
        /// Which preset; omit to list what is available
        name: Option<String>,
        /// Show what the preset would add, and change nothing
        #[arg(long)]
        dry_run: bool,
        /// Add the preset's glob patterns as well as its exact package names
        #[arg(long)]
        globs: bool,
    },
    /// Which isolated-process pools are hidden
    Isolated {
        /// both | appzygote | platform | none; omit to print the current setting
        mode: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum WhiteoutAction {
    /// Hide a path now and on every boot
    Add {
        /// The ROM path to hide
        path: String,
        /// Silence the "leaves a measurable hole" note; nothing is refused on that ground
        #[arg(long)]
        force: bool,
    },
    /// Stop hiding a path
    Remove {
        /// The ROM path to stop hiding
        path: String,
    },
    /// The durable list, and whether each entry is currently applied
    List,
    /// Re-apply the whole list
    Apply,
    /// Propose paths on this device worth hiding
    Suggest,
}

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
