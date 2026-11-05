#![forbid(unsafe_code)]

mod cli;
mod config;
mod scope;
mod target;

use std::process::ExitCode;

use clap::Parser;
use thiserror::Error;

use cli::{Cli, Commands};
use config::{Config, ConfigError};
use scope::{AuthorizationError, Scope, ScopeError};

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

/// Runs the requested command after enforcing the authorization scope.
fn run(cli: Cli) -> Result<(), AppError> {
    let config_path = cli.config.ok_or(AppError::MissingConfig)?;

    match cli.command {
        Commands::Scan(args) => {
            let config = Config::load(config_path)?;
            let scope = Scope::from_config(&config)?;
            scope.authorize(&args.target)?;

            println!("Scanning is not implemented yet (target: {}).", args.target);
        }
    }

    Ok(())
}

/// Errors that terminate the program with a failure exit status.
#[derive(Debug, Error)]
enum AppError {
    #[error("no configuration file selected; use --config PATH")]
    MissingConfig,

    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    Scope(#[from] ScopeError),

    #[error(transparent)]
    Authorization(#[from] AuthorizationError),
}
