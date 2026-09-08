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
    /// Metamodule mount pass: classify enabled modules and route them
    /// (Prism inject / RRO overlay). su is external (sucompat).
    ///
    /// BOOT VERB. It clears the rule table and rebuilds it, so an app that
    /// already has an injected file mapped keeps the OLD inode and shows it as
    /// `(deleted)` in its own /proc/self/maps -- which is one of the oracles
    /// `check` reports. Use `reload` mid-session: same result, applied as a
    /// delta, nothing to see.
    Mount,
    /// Direct VFS-engine operations via the Prism `nm` client
    Vfs {
        #[command(subcommand)]
        action: VfsAction,
    },
    /// Per-UID hiding (sus_path substitute)
    Uid {
        #[command(subcommand)]
        action: UidAction,
    },
    /// Take over bind mounts other modules made: re-serve each as a Prism
    /// injection, then unmount it. Restores the zero-mount posture even when a
    /// module mounts its own content without knowing about NoMount.
    Absorb {
        /// Report what would be absorbed without changing anything
        #[arg(long)]
        dry_run: bool,
        /// Also absorb directory binds. Off by default: injection snapshots the
        /// listing, so files the owning module adds later would never appear.
        #[arg(long)]
        include_dirs: bool,
        /// PRE-ZYGOTE pass. Only post-fs-data may pass this.
        ///
        /// It permits exactly one thing the ordinary pass refuses: taking over a
        /// bind whose target is on a `my_*` partition. Refused at runtime because
        /// re-asserting a my_* rule on a live system has rebooted a device --
        /// measured on an OP11, four rules in a burst, clean sys.boot.reason with
        /// no tombstone. Before zygote there is no live system to lose, which is
        /// what makes the same work safe here and only here.
        #[arg(long)]
        early: bool,
    },
    /// Durable whiteouts: hide stock ROM files that are themselves a tell.
    /// The list survives reboots and is re-applied at boot.
    Whiteout {
        #[command(subcommand)]
        action: WhiteoutAction,
    },
    // History, deliberately NOT a doc comment: clap renders every `///` line as
    // `--help`, and seven lines about four verbs that no longer exist are
    // addressed to a maintainer, not to someone asking what `check` does.
    //
    // Replaces `doctor`, `audit`, `posture` and `selfcheck`. Those were four
    // verbs over two verdict enums, three JSON shapes and a fourth key=value
    // one, and the WebUI merged all of it back into one list in JavaScript --
    // which is what one list means. `posture` ran a strict SUBSET of the device
    // checks, so it is gone for good. `plan` went with them and came BACK: it
    // had no caller inside this repo, which is not the same as no caller, and
    // the module test harness parses it to lint a staged module before it is
    // ever applied -- something nothing else can do.
    /// Is this setup sound, and is what it serves detectable? One report, one
    /// shape, two sections.
    ///
    /// The PLAN section is static: it resolves the enabled module set into the
    /// rules a mount pass would build and names the ones that are a bad idea.
    /// It reads no running process, so it answers before anything is served.
    /// The DEVICE section is measured: it asks this running system whether what
    /// is already served can be told apart from stock. With no flag you get
    /// both, and both is what you want unless you know why not.
    ///
    /// Verdicts are FAIL, REBOOT, UNMEASURED, WARN, PASS, N/A and NOTE. UNMEASURED
    /// and N/A are deliberately distinct: "nothing here to test" is not a warning,
    /// "something stopped me testing" is, and neither is ever a pass.
    Check {
        /// Only the static half: does the module set resolve into a bad rule?
        /// Cheap, reads no running process, safe at post-fs-data.
        #[arg(long)]
        plan: bool,
        /// Only the measured half: is what we serve detectable on this device,
        /// and is it being served? Several of these need a process to have opened
        /// an injected file, so the answer depends on when you ask.
        #[arg(long)]
        device: bool,
        /// Emit one JSON object instead of prose. The WebUI reads this; the human
        /// output is unchanged and is still the default.
        #[arg(long)]
        json: bool,
        /// Also cache to /data/adb/nomount/audit.json, and (unless --plan) write
        /// the fingerprint to health.txt. Written by the boot pass so the WebUI
        /// and the module card have a verdict on open instead of a dash.
        #[arg(long)]
        write: bool,
    },
    /// Print what the mount pass would do (resolved target, kind, source) without
    /// applying anything. Read-only.
    Plan,
    /// Gap-free hot load/unload: reconcile live rules to the current module set,
    /// applying only the delta (no clear). Run after installing/removing a module.
    Reload,
    /// Freeze the current healthy fingerprint as the baseline for `verify`.
    ///
    /// Kept where `posture` and `plan` were dropped: this answers a question
    /// `check` structurally cannot, because it needs a baseline the USER chose --
    /// not "is this device healthy now" but "has anything moved since the boot I
    /// was happy with". Same fingerprint `check` reports, same renderer.
    Snapshot,
    /// Diff the live fingerprint against the saved snapshot; name what drifted
    Verify,
    /// Dump diagnostics to a timestamped folder (default /sdcard/Download)
    Export {
        /// Destination directory (a nm-diag-<ts> subfolder is created inside)
        dir: Option<String>,
    },
    /// Re-derive the kernel's `_ghost` tables from the live rule set.
    ///
    /// Run automatically at the end of `mount` and `reload`; exposed because
    /// `service.sh` calls it once after boot (when the hide list has been
    /// applied and the uid cache is warm) and because it is the one repair for
    /// a table that has gone stale. Inert, and silent, on a kernel without the
    /// _ghost patch set.
    Ghost {
        #[command(subcommand)]
        action: GhostAction,
    },
    /// Print version
    Version,
}

#[derive(Subcommand)]
pub enum GhostAction {
    /// Rebuild both tables (paths and uids) to match the live rule set.
    Sync,
    /// Print what the kernel currently holds, unchanged. Reads `nm l g`.
    List,
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
    /// Hide injections from an app — accepts a package name (durable), a bare
    /// UID, or a glob over package names (`*.duckdetector`, `me.garfieldhan.*`,
    /// `*chunqiu*`). Persists across reboots; a glob re-matches every apply, so
    /// it also covers apps installed later.
    Block {
        target: String,
        /// Allow a platform appid (< 10000: root, system_server, shell …).
        /// Hiding from those hides injections from Android itself.
        #[arg(long)]
        force: bool,
    },
    /// Re-show injections to an app — package name or bare UID. Also removes it
    /// from the persistent list.
    Unblock { target: String },
    /// Show the persistent hide list with each entry's resolved UID and state
    List,
    /// Re-apply the persistent hide list to the kernel. Run from the mount pass
    /// (which clears the kernel's set) and again once boot completes.
    Apply {
        /// Early-boot pass: resolve from the cached appid mirror first, so it
        /// works at post-fs-data before `packages.list` is meaningful.
        #[arg(long)]
        early: bool,
    },
    /// Add a curated preset to the hide list — `detectors` covers the known
    /// root/environment detectors. No argument lists the available presets.
    Preset {
        /// Preset name, e.g. `detectors`
        name: Option<String>,
        /// Print what would be added without touching the list
        #[arg(long)]
        dry_run: bool,
        /// Only the glob rules, not the exact package names. These are the part a
        /// scan of installed apps cannot give you: they keep matching detectors
        /// installed later, or repackaged under a new name.
        #[arg(long)]
        globs: bool,
    },
    /// Which isolated-process pools hiding covers. Hiding from them stops a
    /// hidden app probing through an isolated helper; leaving them visible stops
    /// an *unhidden* app spotting the injection by diffing its own view against
    /// its own isolated child's. No argument = show the current setting.
    Isolated {
        /// both (default) | appzygote | platform | off
        mode: Option<String>,
    },
}

#[derive(Subcommand)]
pub enum WhiteoutAction {
    /// Hide a path now and on every boot
    Add {
        path: String,
        /// Hide it anyway on a filesystem where the hole is measurable (see the
        /// refusal message). Only for a target you have decided is worth it.
        #[arg(long)]
        force: bool,
    },
    /// Stop hiding a path
    Remove { path: String },
    /// Show the list and whether each entry is currently applied
    List,
    /// Re-apply the whole list (run at boot)
    Apply,
    /// Propose paths that exist on THIS device and are worth hiding
    Suggest,
}

/// Would this verb put injection state INTO the engine?
///
/// These are the verbs the bootloop guard exists to hold off. `disabled` means
/// "this device could not finish booting three times in a row with these rules",
/// and it was enforced by the five shell entry points and NOWHERE ELSE -- so it
/// bound the boot path and nothing else. The WebUI's Reload button called
/// `nomount reload` directly through `ksu.exec` and re-injected the whole rule
/// set on a parked device, on the same screen that says "the bootloop guard
/// tripped · the Suite disabled itself", without a word. Measured on an OP11:
/// two rules live on a boot where the mount pass had correctly refused to run.
///
/// The cut is SERVING, not mutating, and the difference is what keeps the
/// recovery path open:
///
///   * refused -- `mount`, `reload`, `absorb`, `vfs add`/`whiteout`,
///     `whiteout add`/`apply`. Each of these ends with more being served than
///     before, which is the one thing the marker denies.
///   * allowed -- everything that DIAGNOSES (`check`, `plan`, `absorb --dry-run`,
///     `export`, `snapshot`, `verify`), everything that REMOVES (`vfs del`,
///     `vfs clear`, `whiteout remove`), the whole `uid` family (hiding is not
///     serving, and a parked Suite still has a hide list worth managing), and
///     `ghost` (on a parked device it clears two tables that describe nothing).
///
/// Refusing without a `--force` is deliberate. The marker IS the switch, and a
/// per-verb override would be a second way past it that nothing else knows
/// about -- so the refusal names the one command that lifts it, which is also
/// the documented recovery (`health.rs`: "Delete /data/adb/nomount/disabled once
/// you know why, and reboot").
///
/// No shell caller can hit this: all five entry points already test the marker
/// before they invoke anything here, so the gate only ever fires on a manual or
/// WebUI invocation -- which is precisely the hole it closes.
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
///
/// [`crate::ghost`] populates two tables: the injected-only PATHS a hidden reader
/// must not be able to prove exist, and the hidden UIDS they are hidden from. Both
/// are derived state, so anything that moves either input leaves the tables
/// describing the previous one -- and that module's header is explicit that the
/// stale state is WORSE than an empty one, because a path ghosted for a uid the
/// engine no longer hides from answers `stat` = OK and `chmod`/`listxattr` =
/// ENOENT at the same time, which no real file can do.
///
/// `mount` and `reload` are deliberately absent: they call
/// [`crate::ghost::sync_after_pass`] themselves, while the pass lock is still
/// held. Everything else that touches a rule or the hide list is listed here.
///
/// The read-only verbs must stay out of it -- `uid list`, `whiteout list`,
/// `absorb --dry-run`, `check`, `plan`, `export` -- because a re-sync forks a
/// probe child and issues netlink writes, and a verb that promises to change
/// nothing must not.
pub fn changes_ghost_inputs(cmd: &Commands) -> bool {
    match cmd {
        // The hide list. `Isolated` is NOT here: it moves the isolated-pool knob,
        // which is not an input to either table.
        Commands::Uid { action } => matches!(
            action,
            UidAction::Block { .. }
                | UidAction::Unblock { .. }
                | UidAction::Apply { .. }
                // A preset is `add_many` + an apply pass, i.e. the largest hide-list
                // change this tool makes (~50 entries).
                //
                // `name: Some(_)`, not `..`. With no name the verb PRINTS THE LIST
                // of available presets and changes nothing -- and it was still
                // forking the probe child and rewriting both kernel tables on the
                // way out, which is the exact cost `read_only_and_self_syncing
                // _verbs_do_not` exists to keep off read-only verbs.
                | UidAction::Preset { name: Some(_), dry_run: false, .. }
        ),
        // The rule set, by hand.
        Commands::Vfs { action } => matches!(
            action,
            VfsAction::Add { .. }
                | VfsAction::Del { .. }
                | VfsAction::Whiteout { .. }
                // CLEAR_ALL drops the rules AND the kernel's hidden-uid set, so it
                // moves both inputs at once.
                | VfsAction::Clear
        ),
        // Durable whiteouts are applied live by add/remove/apply.
        Commands::Whiteout { action } => matches!(
            action,
            WhiteoutAction::Add { .. } | WhiteoutAction::Remove { .. } | WhiteoutAction::Apply
        ),
        // absorb adds injections and drops the binds behind them -- the single
        // biggest mid-session change to the rule set there is.
        Commands::Absorb { dry_run, .. } => !dry_run,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The verbs the bootloop guard has to hold off: each ends with more being
    /// served than before, which is the one thing `disabled` denies.
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

    /// ...and the guard must not block its own recovery. Diagnosis, removal and
    /// the hide list all stay open: `check` is how you find out WHY it tripped,
    /// `vfs clear` and `whiteout remove` take rules away rather than adding them,
    /// and hiding from an app is not serving anything to it.
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

    /// The verbs that move an input. Each of these was silently leaving the
    /// tables describing the previous state; `uid unblock` is the WebUI's un-hide
    /// button and produced the stat=OK / chmod=ENOENT contradiction with one tap.
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

    /// A verb that promises to change nothing must not fork a probe child and
    /// rewrite two kernel tables. `mount` and `reload` are here because they do it
    /// themselves, under the pass lock -- doing it twice would pay for a second
    /// full probe during post-fs-data, which is the root-exec burst the batching
    /// work exists to avoid.
    #[test]
    fn read_only_and_self_syncing_verbs_do_not() {
        for c in [
            Commands::Uid { action: UidAction::List },
            Commands::Uid { action: UidAction::Isolated { mode: None } },
            Commands::Uid {
                action: UidAction::Preset { name: None, dry_run: true, globs: false },
            },
            // No name: this prints the list of presets and changes nothing.
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
