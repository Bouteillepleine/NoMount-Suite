mod absorb;
mod bind;
mod blocklist;
mod cli;
mod dirshape;
mod doctor;
mod health;
mod mount;
mod nm;
mod preflight;
mod whiteout;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Mount => mount::run_mount(),
        Commands::Vfs { action } => cli::handlers::handle_vfs(action),
        Commands::Uid { action } => cli::handlers::handle_uid(action),
        Commands::Doctor => doctor::run_doctor(),
        Commands::Plan => mount::run_plan(),
        Commands::Reload => mount::run_reload(),
        Commands::Absorb { dry_run, include_dirs } => absorb::run_absorb(dry_run, include_dirs),
        Commands::Whiteout { action } => match action {
            cli::WhiteoutAction::Add { path, force } => whiteout::add(&path, force),
            cli::WhiteoutAction::Remove { path } => whiteout::remove(&path),
            cli::WhiteoutAction::List => whiteout::list(),
            cli::WhiteoutAction::Apply => whiteout::apply(),
            cli::WhiteoutAction::Suggest => whiteout::suggest(),
        },
        Commands::Selfcheck { write } => health::run_selfcheck(write),
        Commands::Snapshot => health::run_snapshot(),
        Commands::Verify => health::run_verify(),
        Commands::Export { dir } => health::run_export(dir),
        Commands::Version => {
            println!("nomount v{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}
