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
  nomount uid ksu on         hide from whoever KernelSU's DenyList covers

The boot scripts run `absorb` and `reload` themselves; you rarely need those by hand.
Boot-only verbs, not listed above: mount, unbind, ghost, pathhide, absorb --early,
uid apply --early."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// The boot pass: classify enabled modules and route them into Prism injections
    #[command(hide = true)]
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
        #[arg(long, hide = true)]
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
Exits 1 on a FAIL or a REBOOT. A WARN or an UNMEASURED row exits 0, or 2 with --strict.

  nomount check              both sections
  nomount check --device     only what can be measured on this device
  nomount check --json       machine-readable, for a script or a bug report
  nomount check --strict     for scripts: 0 only for a complete run with no WARN")]
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
        /// Exit 2 when nothing failed but a WARN or an UNMEASURED row leaves it not clean
        #[arg(long)]
        strict: bool,
    },
    /// Print what the mount pass would resolve to, without applying it
    Plan,
    /// Reconcile live rules to the current module set, delta only - use after installing a module
    Reload,
    /// Freeze the current fingerprint as the baseline `verify` compares against
    Snapshot,
    /// Diff live against the snapshot baseline and name what drifted
    Verify,
    /// Dump diagnostics to a folder, and a .zip of it, for a bug report
    #[command(after_help = "\
On shared storage (/sdcard) and under /data/local/tmp everything naming the apps you
hide is withheld - the hide-list files, spoof.conf, boot.log, and dmesg-nomount.txt is
replaced by a stub - and WITHHELD.txt in the bundle says so. Under /data/local/tmp
the bundle belongs to shell (uid 2000, folder 0700, files 0600), so adb pull works and
apps cannot read it.
Export to a private path (e.g. /data/adb/nomount/report) to include them; that bundle is
root-only.")]
    Export {
        /// Where to write the bundle (default: a timestamped folder in /sdcard/Download)
        dir: Option<String>,
    },
    /// The existence cloak: make injected-only paths look absent, not merely unreadable
    #[command(hide = true)]
    Ghost {
        #[command(subcommand)]
        action: GhostAction,
    },
    /// The maps cloak: keep the root stack's own libraries out of app mapping lists
    #[command(hide = true)]
    Pathhide {
        #[command(subcommand)]
        action: PathhideAction,
    },
    /// Unmount the real binds recorded in binds.list (the my_* ones)
    #[command(hide = true)]
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
pub enum PathhideAction {
    /// Program the rule set that keeps the root stack out of app mapping lists
    Sync,
    /// Show what the maps cloak currently covers
    List,
}

#[derive(Subcommand)]
pub enum VfsAction {
    /// Serve the contents of <REAL_PATH> at <VIRTUAL_PATH>
    #[command(after_help = "\
A rule added here is LIVE, not durable, and the two forms differ in how long they last.
Without --uid-excluded the rule is unscoped, and `nomount reload` (which the boot
scripts run, and the WebUI's Reload button) prunes any unscoped rule the installed
module set does not account for - so it is gone at the next reload or reboot. WITH
--uid-excluded the rule is scoped, which reload reads as another writer's and leaves
alone. Neither form is written to disk: for content that must come back every boot,
ship it in a module, or use `nomount whiteout add` for a durable hide.")]
    Add {
        /// The ROM path an app will read
        virtual_path: String,
        /// The file that actually gets served, normally under /data/adb
        real_path: String,
        /// Apps that must NOT see it - package names, globs or appids, comma separated
        /// (e.g. com.google.android.gms). One entry covers that app under every user.
        #[arg(long, value_name = "APPS")]
        uid_excluded: Option<String>,
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
the installed modules without a reboot; a reboot does the same. Your hide list and settings
are untouched; the durable whiteout list is kept on disk but stops being applied until the
next `nomount mount`, so every path it hides is readable again until then.")]
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
        #[arg(long, hide = true)]
        early: bool,
    },
    /// Add a curated set of known detectors to the hide list
    Preset {
        /// Which preset; omit to list what is available
        name: Option<String>,
        /// Show what the preset would add, and change nothing
        #[arg(long)]
        dry_run: bool,
        /// Add ONLY the preset's glob patterns. Without this both the globs and the
        /// exact package names are added.
        #[arg(long)]
        globs: bool,
    },
    /// Follow KernelSU's DenyList (App Profile "Umount modules") as a hide-list source
    #[command(alias = "denylist", after_help = "\
The Suite has no mounts to unmount, so it cannot inherit KernelSU's DenyList the way
a magic-mount or overlay metamodule does. Turning this on makes it ask the kernel per
app instead (`UID_SHOULD_UMOUNT`), and hide its injections from whoever the DenyList
covers - the global default, per-app profiles and root grants all included.

The hide list keeps working alongside it; this is an extra source, not a replacement.

  nomount uid ksu          what the DenyList covers right now
  nomount uid ksu on       follow it
  nomount uid ksu off      stop following it")]
    Ksu {
        /// on | off; omit to show what the DenyList covers
        state: Option<String>,
        /// Follow the DenyList even when KernelSU's global "umount modules by default"
        /// is on, which makes it cover every app without a profile of its own
        #[arg(long)]
        force: bool,
    },
    /// Which isolated-process pools are hidden
    Isolated {
        /// both | appzygote | platform | off; omit to print the current setting
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

/// Both predicates below listed the verbs they care about and sent everything else to a
/// `_ => false` catch-all, so a new verb joined the quiet side by default and no test said
/// which side it was on. For the bootloop guard that is the failure the guard exists to
/// prevent: a serving verb silently exempt from it keeps injecting on a device that could
/// not finish booting three times. The catch-alls are gone, so adding a `Commands` variant
/// now fails to COMPILE until someone classifies it, and so does a new sub-verb.
pub fn serves_injections(cmd: &Commands) -> bool {
    match cmd {
        Commands::Mount | Commands::Reload => true,
        Commands::Absorb { dry_run, .. } => !dry_run,
        Commands::Vfs { action } => match action {
            VfsAction::Add { .. } | VfsAction::Whiteout { .. } => true,
            VfsAction::Del { .. } | VfsAction::Clear | VfsAction::List => false,
        },
        Commands::Whiteout { action } => match action {
            WhiteoutAction::Add { .. } | WhiteoutAction::Apply => true,
            WhiteoutAction::Remove { .. } | WhiteoutAction::List | WhiteoutAction::Suggest => false,
        },
        // Diagnosis, removal and the hide list must stay reachable on a parked device: that
        // is how the operator finds out why it parked and gets out of it. `Unbind` only
        // unmounts what is already recorded, which is removal too.
        Commands::Uid { .. }
        | Commands::Check { .. }
        | Commands::Plan
        | Commands::Snapshot
        | Commands::Verify
        | Commands::Export { .. }
        | Commands::Ghost { .. }
        | Commands::Pathhide { .. }
        | Commands::Unbind
        | Commands::Version => false,
    }
}

pub fn changes_ghost_inputs(cmd: &Commands) -> bool {
    match cmd {
        Commands::Uid { action } => match action {
            UidAction::Block { .. } | UidAction::Unblock { .. } | UidAction::Apply { .. } => true,
            UidAction::Ksu { state, .. } => state.is_some(),
            UidAction::Preset { name, dry_run, .. } => name.is_some() && !dry_run,
            UidAction::List | UidAction::Isolated { .. } => false,
        },
        Commands::Vfs { action } => match action {
            VfsAction::Add { .. }
            | VfsAction::Del { .. }
            | VfsAction::Whiteout { .. }
            | VfsAction::Clear => true,
            VfsAction::List => false,
        },
        Commands::Whiteout { action } => match action {
            WhiteoutAction::Add { .. } | WhiteoutAction::Remove { .. } | WhiteoutAction::Apply => {
                true
            }
            WhiteoutAction::List | WhiteoutAction::Suggest => false,
        },
        Commands::Absorb { dry_run, .. } => !dry_run,
        // Mount and Reload re-derive the cloak themselves at the end of their own pass
        // (ghost::sync_after_pass), so routing them through main.rs's post-command resync
        // would sync twice. Unbind changes which paths exist but not which rules are served,
        // and ghost::candidates() reads the RULE list. Isolated {mode: Some(_)} writes an
        // engine knob but not a cloak input: ghost_uids() is built from the live appids,
        // device users and sdksandbox expansion, and never reads hide_isolated().
        Commands::Mount
        | Commands::Reload
        | Commands::Unbind
        | Commands::Check { .. }
        | Commands::Plan
        | Commands::Snapshot
        | Commands::Verify
        | Commands::Export { .. }
        | Commands::Ghost { .. }
        | Commands::Pathhide { .. }
        | Commands::Version => false,
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
                action: VfsAction::Add {
                    virtual_path: "/a".into(),
                    real_path: "/b".into(),
                    uid_excluded: None,
                },
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
            Commands::Check { plan: false, device: false, json: false, write: false, strict: false },
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
            Commands::Pathhide { action: PathhideAction::Sync },
            Commands::Pathhide { action: PathhideAction::List },
            Commands::Uid { action: UidAction::Isolated { mode: None } },
            Commands::Uid { action: UidAction::Isolated { mode: Some("off".into()) } },
            Commands::Uid { action: UidAction::Ksu { state: None, force: false } },
            Commands::Uid { action: UidAction::Ksu { state: Some("on".into()), force: false } },
            Commands::Unbind,
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
            Commands::Uid { action: UidAction::Apply { early: true } },
            Commands::Uid { action: UidAction::Ksu { state: Some("on".into()), force: false } },
            Commands::Uid {
                action: UidAction::Preset {
                    name: Some("detectors".into()),
                    dry_run: false,
                    globs: false,
                },
            },
            Commands::Vfs {
                action: VfsAction::Add {
                    virtual_path: "/a".into(),
                    real_path: "/b".into(),
                    uid_excluded: None,
                },
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
            Commands::Uid {
                action: UidAction::Preset {
                    name: Some("detectors".into()),
                    dry_run: true,
                    globs: false,
                },
            },
            Commands::Vfs { action: VfsAction::List },
            Commands::Whiteout { action: WhiteoutAction::List },
            Commands::Whiteout { action: WhiteoutAction::Suggest },
            Commands::Absorb { dry_run: true, include_dirs: false, early: false },
            Commands::Mount,
            Commands::Reload,
            Commands::Plan,
            Commands::Check { plan: false, device: false, json: false, write: false, strict: false },
            Commands::Snapshot,
            Commands::Verify,
            Commands::Export { dir: None },
            Commands::Ghost { action: GhostAction::List },
            Commands::Pathhide { action: PathhideAction::Sync },
            Commands::Pathhide { action: PathhideAction::List },
            // The write form, which no list enumerated before. It programs the engine's
            // isolated-pool knob, but ghost_uids() never reads hide_isolated(), so it is
            // not a cloak input and must NOT trigger a resync.
            Commands::Uid { action: UidAction::Isolated { mode: Some("both".into()) } },
            Commands::Uid { action: UidAction::Ksu { state: None, force: false } },
            // Changes which paths exist, not which rules are served; candidates() reads the
            // rule list.
            Commands::Unbind,
            Commands::Version,
        ] {
            assert!(!changes_ghost_inputs(&c), "a read-only verb must not re-derive anything");
        }
    }
}
