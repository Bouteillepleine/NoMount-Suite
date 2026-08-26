mod absorb;
mod accept;
mod audit;
mod bind;
mod blocklist;
mod cli;
mod dirshape;
mod doctor;
mod health;
mod history;
mod json;
mod manager;
mod mount;
mod nm;
mod pmcache;
mod preflight;
mod presets;
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
    match cli.command {
        Commands::Mount => mount::run_mount(),
        Commands::Vfs { action } => cli::handlers::handle_vfs(action),
        Commands::Uid { action } => cli::handlers::handle_uid(action),
        Commands::Doctor { json } => doctor::run_doctor(json),
        Commands::Audit { json, write } => audit::run_audit(json, write),
        Commands::Posture { json } => audit::run_posture(json),
        Commands::Accept { check, reason, remove, list } => {
            audit::run_accept(check, reason, remove, list)
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
        Commands::Selfcheck { write, json } => health::run_selfcheck(write, json),
        Commands::Snapshot => health::run_snapshot(),
        Commands::Verify => health::run_verify(),
        Commands::Export { dir } => health::run_export(dir),
        Commands::Version => {
            println!("nomount v{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}
