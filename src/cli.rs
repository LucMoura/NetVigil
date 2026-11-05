//! Command-line interface definition for NetVigil.

use std::ffi::OsStr;
use std::path::PathBuf;

use clap::builder::TypedValueParser;
use clap::error::ErrorKind;
use clap::{Arg, Args, Command, Parser, Subcommand};

use crate::target::{Target, TargetError};

/// Network intelligence and reconnaissance CLI.
#[derive(Debug, Parser)]
#[command(
    name = "netvigil",
    version,
    about = "Network intelligence and reconnaissance CLI"
)]
pub struct Cli {
    /// Path to the configuration file.
    ///
    /// There is no implicit default. The operator must select the file
    /// explicitly so that configuration is never loaded from the current
    /// working directory by accident.
    #[arg(long, global = true, value_name = "PATH")]
    pub config: Option<PathBuf>,

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
    #[arg(value_name = "TARGET", value_parser = TargetParser)]
    pub target: Target,
}

/// Value parser that validates targets without echoing the raw input.
///
/// Clap's built-in function parser includes the rejected value in its error
/// message. Returning a [`clap::Error`] directly keeps error output generic,
/// preventing terminal escape and log injection from hostile targets.
#[derive(Debug, Clone, Copy)]
struct TargetParser;

impl TypedValueParser for TargetParser {
    type Value = Target;

    fn parse_ref(
        &self,
        cmd: &Command,
        _arg: Option<&Arg>,
        value: &OsStr,
    ) -> Result<Self::Value, clap::Error> {
        let value = value
            .to_str()
            .ok_or_else(|| invalid_target_error(cmd, "target must be valid UTF-8"))?;

        Target::parse(value).map_err(|error| invalid_target_error(cmd, safe_error_reason(&error)))
    }
}

/// Builds a Clap error that never includes the rejected input.
fn invalid_target_error(cmd: &Command, reason: &str) -> clap::Error {
    let mut command = cmd.clone();
    command.error(
        ErrorKind::ValueValidation,
        format!("invalid target: {reason}"),
    )
}

/// Returns a user-facing reason that never contains input-derived data.
///
/// The match is exhaustive on purpose: adding a [`TargetError`] variant forces
/// a decision about what is safe to display to the user.
fn safe_error_reason(error: &TargetError) -> &'static str {
    match error {
        TargetError::Empty => "target must not be empty",
        TargetError::Whitespace => "target must not contain whitespace",
        TargetError::TooLong => "target is too long",
        TargetError::LabelTooLong => "target contains an overly long label",
        TargetError::EmptyLabel => "target contains empty labels",
        TargetError::LabelStartsWithHyphen => "target contains a label starting with a hyphen",
        TargetError::LabelEndsWithHyphen => "target contains a label ending with a hyphen",
        TargetError::InvalidCharacter(_) => "target contains invalid characters",
        TargetError::NumericTopLevelLabel => "target must not end with a numeric label",
    }
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
                ..
            }) => assert_eq!(args.target.to_string(), "127.0.0.1"),
            other => panic!("expected scan subcommand, got {other:?}"),
        }
    }

    #[test]
    fn normalizes_hostname_target() {
        let cli = Cli::try_parse_from(["netvigil", "scan", "Example.COM."]);

        match cli {
            Ok(Cli {
                command: Commands::Scan(args),
                ..
            }) => assert_eq!(args.target.as_hostname(), Some("example.com")),
            other => panic!("expected scan subcommand, got {other:?}"),
        }
    }

    #[test]
    fn normalizes_ipv4_mapped_ipv6_target() {
        let cli = Cli::try_parse_from(["netvigil", "scan", "::ffff:127.0.0.1"]);

        match cli {
            Ok(Cli {
                command: Commands::Scan(args),
                ..
            }) => {
                assert_eq!(
                    args.target.as_ip(),
                    Some(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
                );
                assert_eq!(args.target.to_string(), "127.0.0.1");
            }
            other => panic!("expected scan subcommand, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_hostname_target() {
        assert!(Cli::try_parse_from(["netvigil", "scan", "-invalid.com"]).is_err());
        assert!(Cli::try_parse_from(["netvigil", "scan", "exa_mple.com"]).is_err());
    }

    #[test]
    fn rejects_control_characters_without_echoing_input() {
        let error = Cli::try_parse_from(["netvigil", "scan", "evil\u{1b}host"])
            .expect_err("control character must be rejected");

        assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);

        let message = error.to_string();
        assert!(message.contains("invalid target"));
        assert!(!message.contains("evil"), "error leaked input: {message:?}");
        assert!(!message.contains('\u{1b}'), "error leaked ESC: {message:?}");
    }

    #[test]
    fn rejects_unicode_format_characters_without_echoing_input() {
        for character in ['\u{9b}', '\u{200b}', '\u{202e}', '\u{2066}', '\u{feff}'] {
            let input = format!("evil{character}host");
            let error = Cli::try_parse_from(["netvigil", "scan", input.as_str()])
                .expect_err("format character must be rejected");
            let message = error.to_string();

            assert!(
                !message.contains(character),
                "error leaked {character:?}: {message:?}"
            );
            assert!(!message.contains("evil"), "error leaked input: {message:?}");
            assert!(message.contains("invalid target"));
        }
    }

    #[test]
    fn rejects_line_separators_without_echoing_input() {
        for character in ['\u{2028}', '\u{2029}'] {
            let input = format!("evil{character}host");
            let error = Cli::try_parse_from(["netvigil", "scan", input.as_str()])
                .expect_err("line separator must be rejected");
            let message = error.to_string();

            assert!(
                !message.contains(character),
                "error leaked {character:?}: {message:?}"
            );
            assert!(!message.contains("evil"), "error leaked input: {message:?}");
        }
    }

    #[test]
    fn invalid_target_error_is_generic() {
        let error = Cli::try_parse_from(["netvigil", "scan", "exa_mple.com"])
            .expect_err("invalid hostname must be rejected");
        let message = error.to_string();

        assert!(message.contains("invalid target"));
        assert!(
            !message.contains("exa_mple.com"),
            "error leaked input: {message:?}"
        );
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

    #[test]
    fn config_is_not_selected_by_default() {
        let cli = Cli::try_parse_from(["netvigil", "scan", "192.0.2.10"])
            .expect("scan arguments must be valid");

        assert_eq!(cli.config, None);
    }

    #[test]
    fn help_does_not_advertise_an_implicit_config_default() {
        let help = Cli::command().render_help().to_string();

        assert!(!help.contains("default: netvigil.toml"), "help: {help}");
    }

    #[test]
    fn accepts_config_before_subcommand() {
        let cli = Cli::try_parse_from([
            "netvigil",
            "--config",
            "/tmp/scope.toml",
            "scan",
            "192.0.2.10",
        ])
        .expect("global config option must be accepted before the subcommand");

        assert_eq!(cli.config, Some(PathBuf::from("/tmp/scope.toml")));
    }

    #[test]
    fn accepts_config_after_subcommand() {
        let cli = Cli::try_parse_from([
            "netvigil",
            "scan",
            "--config",
            "/tmp/scope.toml",
            "192.0.2.10",
        ])
        .expect("global config option must be accepted after the subcommand");

        assert_eq!(cli.config, Some(PathBuf::from("/tmp/scope.toml")));
    }
}
