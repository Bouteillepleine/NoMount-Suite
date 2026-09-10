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
    unsafe { libc::umask(0o077) };

    let cli = Cli::parse();
    let resync_ghost = cli::changes_ghost_inputs(&cli.command);
    if cli::serves_injections(&cli.command) && mount::guard_tripped() {
        anyhow::bail!(
            "the bootloop guard has parked the Suite ({}), so nothing is being injected - \
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
        Commands::Unbind => {
            if bind::teardown_all() {
                Ok(())
            } else {
                // Non-zero, so uninstall.sh can say so rather than wiping binds.list
                // on top of a bind that is still mounted.
                anyhow::bail!(
                    "at least one recorded bind could not be umounted; its row is kept in                      binds.list so a later pass can retry it"
                )
            }
        }
        Commands::Version => {
            println!("nomount v{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    };
    if resync_ghost {
        ghost::sync_quietly(&nm::Nm::new());
    }
    r
}
