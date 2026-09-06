mod absorb;
mod audit;
mod bind;
mod check;
mod blocklist;
mod cli;
mod dirshape;
mod doctor;
mod ghost;
mod health;
mod json;
mod manager;
mod mount;
mod nm;
mod pmcache;
mod presets;
mod statefile;
mod whiteout;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Commands};

fn main() -> Result<()> {
    // Every state file this binary writes lives in /data/adb/nomount, and the
    // umask inherited from init at post-fs-data is 0, so File::create landed them
    // 0666 -- observed on absorbed.list, binds.lock, uidhide and uidhide.cache.
    // The 0700 directory is what actually gates access, but uidhide IS the
    // per-app hiding policy and should not depend on its parent alone. One call
    // here covers every writer in the crate; nothing this binary creates is meant
    // to be group- or world-readable. Also inherited by anything it execs.
    // SAFETY: umask() is always successful and only touches this process.
    unsafe { libc::umask(0o077) };

    let cli = Cli::parse();
    // Does this verb change what the `_ghost` tables describe? Decided ONCE, in
    // `cli::changes_ghost_inputs`, and acted on below rather than at each verb.
    //
    // `crate::ghost`'s header is explicit that a table describing the PREVIOUS
    // state is worse than an empty one -- a path ghosted for a uid the engine no
    // longer hides from answers stat=OK and chmod/listxattr=ENOENT at once. It
    // then wired the re-sync into `mount` and `reload` and stopped there, so the
    // verbs that change the OTHER input -- the hidden-uid set -- did not have it:
    // `nomount uid unblock`, i.e. the WebUI's un-hide button, left the appid in
    // the `u` table and produced exactly that contradiction with one tap, and
    // `uid block` left a newly hidden app out of it, so every oracle stayed open
    // for the app it was just asked to hide from.
    //
    // Here rather than inside each handler for two reasons: `handle_uid` returns
    // early from four arms and bails from three more (after the state has already
    // changed), so a per-arm call is seven calls and a standing invitation to miss
    // the eighth; and a reader asking "what re-derives the cloak?" gets one list
    // instead of a grep. `mount` and `reload` keep their own call, because theirs
    // runs while the pass lock is still held.
    let resync_ghost = cli::changes_ghost_inputs(&cli.command);
    // The bootloop guard binds EVERY caller, not just the boot scripts.
    //
    // `disabled` was tested by the five shell entry points and nowhere else, so
    // it parked the boot path and left every other route open: the WebUI's
    // Reload button drives `nomount reload` straight through `ksu.exec`, which
    // re-injected the whole rule set on a device that had just disabled itself
    // -- on the same screen that reports "the Suite disabled itself". Measured on
    // an OP11: two live rules on a boot whose mount pass had correctly refused.
    //
    // Only the SERVING verbs; diagnosis and removal stay open, or the guard would
    // block its own recovery. See `cli::serves_injections`.
    if cli::serves_injections(&cli.command) && mount::guard_tripped() {
        anyhow::bail!(
            "the bootloop guard has parked the Suite ({}), so nothing is being injected — \
             this device failed to finish booting three times in a row. `nomount check` and \
             {}/incident.log say what happened; once you know why, clear the marker and reboot: \
             rm {}",
            mount::DISABLED_MARKER,
            "/data/adb/nomount",
            mount::DISABLED_MARKER
        );
    }
    let r = match cli.command {
        Commands::Mount => mount::run_mount(),
        Commands::Vfs { action } => cli::handlers::handle_vfs(action),
        Commands::Uid { action } => cli::handlers::handle_uid(action),
        Commands::Check { plan, device, json, write } => {
            check::run_check(plan, device, json, write)
        }
        Commands::Plan => mount::run_plan(),
        Commands::Reload => mount::run_reload(),
        Commands::Absorb { dry_run, include_dirs, early } => {
            absorb::run_absorb(dry_run, include_dirs, early)
        }
        Commands::Whiteout { action } => match action {
            cli::WhiteoutAction::Add { path, force } => whiteout::add(&path, force),
            cli::WhiteoutAction::Remove { path } => whiteout::remove(&path),
            cli::WhiteoutAction::List => whiteout::list(),
            cli::WhiteoutAction::Apply => whiteout::apply(),
            cli::WhiteoutAction::Suggest => whiteout::suggest(),
        },
        Commands::Snapshot => health::run_snapshot(),
        Commands::Verify => health::run_verify(),
        Commands::Export { dir } => health::run_export(dir),
        Commands::Ghost { action } => match action {
            cli::GhostAction::Sync => ghost::run_sync(true),
            cli::GhostAction::List => {
                print!("{}", nm::Nm::new().ghost_list()?);
                Ok(())
            }
        },
        Commands::Version => {
            println!("nomount v{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    };
    // AFTER the verb, and regardless of its status. Several of these change state
    // and then bail (`uid apply` reports a partial failure that way, and so does
    // `whiteout add` when the list write succeeded and the engine refused), so
    // gating the re-sync on success would skip it in precisely the runs where the
    // two tables and the engine have most likely diverged.
    // `sync_quietly`, not `sync_after_pass`: this rides on another verb, whose
    // stdout is that verb's answer and IS parsed -- `whiteout add`'s WebUI
    // handler toasts `stdout.split("\n").pop()`, so a summary line appended here
    // would become the toast. Nothing on the happy path; stderr when the cloak
    // could not be rebuilt.
    if resync_ghost {
        ghost::sync_quietly(&nm::Nm::new());
    }
    r
}
