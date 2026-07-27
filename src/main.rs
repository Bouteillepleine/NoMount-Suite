mod cli;
mod mount;
mod nm;
mod overlay;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Mount => mount::run_mount(),
        Commands::Vfs { action } => cli::handlers::handle_vfs(action),
        Commands::Uid { action } => cli::handlers::handle_uid(action),
        Commands::Version => {
            println!("nomount v{}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
    }
}
