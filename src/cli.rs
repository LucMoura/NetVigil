//! Command-line interface definition for NetVigil.

use clap::{Args, Parser, Subcommand};

/// Network intelligence and reconnaissance CLI.
#[derive(Debug, Parser)]
#[command(
    name = "netvigil",
    version,
    about = "Network intelligence and reconnaissance CLI"
)]
pub struct Cli {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: Commands,
}

/// Supported NetVigil subcommands.
#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Scan a target for open ports and services.
    Scan(ScanArgs),
}

/// Arguments accepted by the `scan` subcommand.
#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Target to scan, such as a hostname or IP address.
    #[arg(value_name = "TARGET", value_parser = parse_target)]
    pub target: String,
}

/// Validates a positional scan target.
///
/// Only rejects empty or whitespace-containing values for now. Target format
/// validation belongs to the scanner once it is implemented.
fn parse_target(value: &str) -> Result<String, String> {
    if value.trim().is_empty() {
        return Err("target must not be empty".to_owned());
    }

    if value.chars().any(char::is_whitespace) {
        return Err("target must not contain whitespace".to_owned());
    }

    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn command_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_scan_with_target() {
        let cli = Cli::try_parse_from(["netvigil", "scan", "127.0.0.1"]);

        match cli {
            Ok(Cli {
                command: Commands::Scan(args),
            }) => assert_eq!(args.target, "127.0.0.1"),
            other => panic!("expected scan subcommand, got {other:?}"),
        }
    }

    #[test]
    fn scan_requires_a_target() {
        assert!(Cli::try_parse_from(["netvigil", "scan"]).is_err());
    }

    #[test]
    fn rejects_empty_target() {
        assert!(Cli::try_parse_from(["netvigil", "scan", ""]).is_err());
    }

    #[test]
    fn rejects_target_with_whitespace() {
        assert!(Cli::try_parse_from(["netvigil", "scan", "example host"]).is_err());
    }

    #[test]
    fn help_lists_scan_subcommand() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("scan"));
    }

    #[test]
    fn help_flag_is_supported() {
        let error = Cli::try_parse_from(["netvigil", "--help"])
            .expect_err("--help must be handled by clap");

        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn version_flag_is_supported() {
        let error = Cli::try_parse_from(["netvigil", "--version"])
            .expect_err("--version must be handled by clap");

        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(error.to_string().contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn scan_help_documents_required_target() {
        let error = Cli::try_parse_from(["netvigil", "scan", "--help"])
            .expect_err("scan --help must be handled by clap");

        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
        assert!(error.to_string().contains("TARGET"));
    }
}
