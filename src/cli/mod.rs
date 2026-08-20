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
    },
    /// Durable whiteouts: hide stock ROM files that are themselves a tell.
    /// The list survives reboots and is re-applied at boot.
    Whiteout {
        #[command(subcommand)]
        action: WhiteoutAction,
    },
    /// Prove the hiding holds on THIS device: replay every detection oracle we
    /// have closed and report what was actually measured. A skipped check is not
    /// a pass.
    Audit,
    /// Lint the mount plan (and live rules) for known bootloop/no-op hazards
    Doctor,
    /// Print what the mount pass would do (resolved target, kind, source) without
    /// applying anything. Read-only.
    Plan,
    /// Gap-free hot load/unload: reconcile live rules to the current module set,
    /// applying only the delta (no clear). Run after installing/removing a module.
    Reload,
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
