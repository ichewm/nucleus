//! Nucleus - Extremely lightweight Docker alternative for agents
//!
//! A minimalist container runtime designed specifically for AI agents running on Linux.

mod cli;
mod cgroup;
mod error;
mod filesystem;
mod gvisor;
mod launcher;
mod namespace;
mod security;

use clap::Parser;
use cli::{Cli, Commands};
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::error::Result;

fn main() -> Result<()> {
    // Initialize tracing/logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run(run_args) => {
            info!("Starting nucleus run command");
            launcher::run_container(&run_args)?;
        }
    }

    Ok(())
}
