//! Loading of the NetVigil configuration file.
//!
//! The configuration currently contains only the authorization scope. There
//! are no default targets and no implicit allow rules: a missing, unreadable
//! or malformed file is an error, and an empty target list authorizes nothing.
//!
//! Configuration files are treated as untrusted input. The loader requires a
//! regular file selected explicitly by the operator, applies platform trust
//! checks where available, reads at most [`MAX_CONFIG_BYTES`] bytes and rejects
//! configurations with more than [`MAX_SCOPE_RULES`] entries. Paths and TOML
//! diagnostics are sanitized before they are shown to the user.

use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::Path;

#[cfg(unix)]
use std::fs::OpenOptions;

use serde::Deserialize;
use serde::de::{self, SeqAccess, Visitor};
use thiserror::Error;

/// Maximum size of a configuration file, in bytes.
pub const MAX_CONFIG_BYTES: usize = 1024 * 1024;

/// Maximum number of entries accepted in `[scope] targets`.
pub const MAX_SCOPE_RULES: usize = 4096;

/// Maximum number of characters kept when displaying untrusted text.
pub(crate) const MAX_DISPLAY_CHARS: usize = 200;

/// Root of the `netvigil.toml` configuration.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Authorization scope declared by the operator.
    pub scope: ScopeConfig,
}

/// Contents of the `[scope]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeConfig {
    /// Targets the operator explicitly authorizes.
    ///
    /// Entries are validated by [`crate::scope::Scope::from_config`]. An
    /// absent or empty list authorizes no targets. The loader rejects lists
    /// larger than [`MAX_SCOPE_RULES`].
    #[serde(default, deserialize_with = "deserialize_targets")]
    pub targets: Vec<String>,
}

/// Errors produced while loading the configuration file.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The configuration file could not be read.
    #[error("failed to read configuration file {path}: {source}")]
    Read {
        /// Sanitized path that could not be read.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The selected path is not a regular file.
    #[error("configuration path {path} is not a regular file")]
    NotRegularFile {
        /// Sanitized path.
        path: String,
    },

    /// The selected path is a symbolic link, which is not trusted.
    #[error("configuration path {path} is a symbolic link, which is not trusted")]
    Symlink {
        /// Sanitized path.
        path: String,
    },

    /// The file is writable by group or other users.
    #[error(
        "configuration file {path} has insecure permissions: it is writable by group or others"
    )]
    InsecurePermissions {
        /// Sanitized path.
        path: String,
    },

    /// The file is not owned by the current effective user.
    #[error("configuration file {path} is not owned by the current user")]
    UntrustedOwner {
        /// Sanitized path.
        path: String,
    },

    /// The current effective user ID could not be determined on Linux.
    #[error(
        "cannot determine the current effective user ID for configuration file {path}; refusing to trust its ownership"
    )]
    EuidUnavailable {
        /// Sanitized path.
        path: String,
    },

    /// The file is not valid UTF-8.
    #[error("configuration file {path} is not valid UTF-8")]
    NotUtf8 {
        /// Sanitized path.
        path: String,
    },

    /// The file exceeds the configured size limit.
    #[error("configuration file {path} exceeds the maximum size of {limit} bytes")]
    TooLarge {
        /// Sanitized path.
        path: String,
        /// Maximum accepted size in bytes.
        limit: usize,
    },

    /// The file declares more scope rules than allowed.
    #[error("configuration file {path} declares too many scope rules (maximum {limit})")]
    TooManyRules {
        /// Sanitized path.
        path: String,
        /// Maximum accepted number of rules.
        limit: usize,
    },

    /// The configuration file is not valid TOML or does not match the schema.
    ///
    /// The reason never contains raw TOML source lines. It includes the error
    /// category, a sanitized message and, when available, line and column.
    #[error("invalid configuration file {path}: {reason}")]
    Parse {
        /// Sanitized path.
        path: String,
        /// Sanitized diagnostic.
        reason: String,
    },
}

/// Deserializes `scope.targets` while enforcing [`MAX_SCOPE_RULES`].
///
/// The count is checked while reading the sequence, so a 4097th entry is
/// rejected during deserialization. The reported size hint is intentionally
/// ignored to avoid reserving memory based on untrusted input.
fn deserialize_targets<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct TargetsVisitor;

    impl<'de> Visitor<'de> for TargetsVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("an array of strings")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut targets = Vec::new();
            while let Some(value) = seq.next_element::<String>()? {
                if targets.len() >= MAX_SCOPE_RULES {
                    return Err(de::Error::custom(format!(
                        "too many scope rules (maximum {MAX_SCOPE_RULES})"
                    )));
                }
                targets.push(value);
            }
            Ok(targets)
        }
    }

    deserializer.deserialize_seq(TargetsVisitor)
}

impl Config {
    /// Loads and parses a configuration file selected explicitly by the
    /// operator.
    ///
    /// The path must refer to a regular file. On Unix, the final component is
    /// opened with `O_NOFOLLOW` and `O_NONBLOCK`, and regular-file, permission,
    /// ownership and size checks are applied to the opened handle. On Linux,
    /// the loader fails closed if the effective user ID cannot be determined.
    /// The file is read with an explicit byte limit.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the path is not a trusted regular file,
    /// when the file cannot be read, when it exceeds [`MAX_CONFIG_BYTES`], when
    /// it declares more than [`MAX_SCOPE_RULES`] rules or when its contents are
    /// invalid.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let display = display_path(path);
        let file = open_trusted(path, &display)?;

        let mut contents = String::new();
        let mut reader = file.take(MAX_CONFIG_BYTES as u64 + 1);
        reader.read_to_string(&mut contents).map_err(|source| {
            if source.kind() == std::io::ErrorKind::InvalidData {
                ConfigError::NotUtf8 {
                    path: display.clone(),
                }
            } else {
                ConfigError::Read {
                    path: display.clone(),
                    source,
                }
            }
        })?;

        if contents.len() > MAX_CONFIG_BYTES {
            return Err(ConfigError::TooLarge {
                path: display,
                limit: MAX_CONFIG_BYTES,
            });
        }

        Self::parse(&contents).map_err(|error| match error {
            ParseError::Toml(source) => ConfigError::Parse {
                path: display,
                reason: format_parse_error(&source, &contents),
            },
            ParseError::TooManyRules { limit } => ConfigError::TooManyRules {
                path: display,
                limit,
            },
        })
    }

    /// Parses configuration from a TOML string.
    fn parse(contents: &str) -> Result<Self, ParseError> {
        let config: Self = toml::from_str(contents)?;

        if config.scope.targets.len() > MAX_SCOPE_RULES {
            return Err(ParseError::TooManyRules {
                limit: MAX_SCOPE_RULES,
            });
        }

        Ok(config)
    }
}

/// Internal parse failures before they are tied to a path.
#[derive(Debug, Error)]
enum ParseError {
    /// The document is not valid TOML or does not match the schema.
    #[error(transparent)]
    Toml(#[from] toml::de::Error),

    /// The document declares too many scope rules.
    #[error("declares too many scope rules (maximum {limit})")]
    TooManyRules {
        /// Maximum accepted number of rules.
        limit: usize,
    },
}

/// Opens a path and applies the trust model to the opened handle.
///
/// On Unix the final component is opened with `O_NOFOLLOW` and `O_NONBLOCK`.
/// The former rejects a symbolic link at open time; the latter prevents a
/// substituted FIFO from blocking the process. All trust decisions use the
/// metadata returned by `fstat` on the resulting handle.
#[cfg(unix)]
fn open_trusted(path: &Path, display: &str) -> Result<File, ConfigError> {
    open_trusted_with_euid(path, display, system_effective_uid())
}

/// Testable variant of [`open_trusted`] with an explicit effective UID.
#[cfg(unix)]
fn open_trusted_with_euid(
    path: &Path,
    display: &str,
    effective_uid: EffectiveUid,
) -> Result<File, ConfigError> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|source| classify_open_error(path, display, source))?;

    let metadata = file.metadata().map_err(|source| ConfigError::Read {
        path: display.to_owned(),
        source,
    })?;

    if !metadata.is_file() {
        return Err(ConfigError::NotRegularFile {
            path: display.to_owned(),
        });
    }

    verify_trust(&metadata, display, effective_uid)?;

    if metadata.len() > MAX_CONFIG_BYTES as u64 {
        return Err(ConfigError::TooLarge {
            path: display.to_owned(),
            limit: MAX_CONFIG_BYTES,
        });
    }

    Ok(file)
}

/// Classifies an open failure without using the path as a source of trust.
///
/// `O_NOFOLLOW` reports a final-component symbolic link with a platform-specific
/// error code. A post-failure `symlink_metadata` lookup keeps the diagnostic
/// portable; it is never used to accept a file.
#[cfg(unix)]
fn classify_open_error(path: &Path, display: &str, source: std::io::Error) -> ConfigError {
    if fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return ConfigError::Symlink {
            path: display.to_owned(),
        };
    }

    ConfigError::Read {
        path: display.to_owned(),
        source,
    }
}

/// Applies platform-specific ownership and permission checks to an open handle.
#[cfg(unix)]
fn verify_trust(
    metadata: &Metadata,
    display: &str,
    effective_uid: EffectiveUid,
) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;

    if metadata.mode() & 0o022 != 0 {
        return Err(ConfigError::InsecurePermissions {
            path: display.to_owned(),
        });
    }

    match effective_uid {
        EffectiveUid::Known(uid) => {
            if metadata.uid() != uid {
                return Err(ConfigError::UntrustedOwner {
                    path: display.to_owned(),
                });
            }
        }
        EffectiveUid::Unavailable => {
            #[cfg(target_os = "linux")]
            {
                return Err(ConfigError::EuidUnavailable {
                    path: display.to_owned(),
                });
            }
        }
    }

    Ok(())
}

/// Windows and other non-Unix platforms expose ACLs rather than POSIX mode
/// bits. The regular-file check is applied to the opened handle; symbolic-link
/// rejection remains best-effort because no portable no-follow flag is used.
#[cfg(not(unix))]
fn open_trusted(path: &Path, display: &str) -> Result<File, ConfigError> {
    let link_metadata = fs::symlink_metadata(path).map_err(|source| ConfigError::Read {
        path: display.to_owned(),
        source,
    })?;

    if link_metadata.file_type().is_symlink() {
        return Err(ConfigError::Symlink {
            path: display.to_owned(),
        });
    }

    let file = File::open(path).map_err(|source| ConfigError::Read {
        path: display.to_owned(),
        source,
    })?;

    let metadata = file.metadata().map_err(|source| ConfigError::Read {
        path: display.to_owned(),
        source,
    })?;

    if !metadata.is_file() {
        return Err(ConfigError::NotRegularFile {
            path: display.to_owned(),
        });
    }

    verify_trust(&metadata, display)?;

    if metadata.len() > MAX_CONFIG_BYTES as u64 {
        return Err(ConfigError::TooLarge {
            path: display.to_owned(),
            limit: MAX_CONFIG_BYTES,
        });
    }

    Ok(file)
}

/// Windows and other non-Unix platforms do not expose POSIX ownership or mode
/// bits through `Metadata`; ACL inspection is a documented limitation.
#[cfg(not(unix))]
fn verify_trust(_metadata: &Metadata, _display: &str) -> Result<(), ConfigError> {
    Ok(())
}

/// Effective user ID used for ownership checks on Unix.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectiveUid {
    /// The effective user ID was determined successfully.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Known(u32),
    /// The effective user ID is unavailable.
    Unavailable,
}

/// Returns the effective user ID on Linux.
///
/// Rust's standard library does not expose `geteuid`, and calling the libc
/// function would require `unsafe`, which the crate forbids. `/proc/self/status`
/// provides the value without unsafe code. A read or parse failure is reported
/// as unavailable so that the caller can fail closed.
#[cfg(all(unix, target_os = "linux"))]
fn system_effective_uid() -> EffectiveUid {
    match fs::read_to_string("/proc/self/status") {
        Ok(status) => {
            parse_effective_uid(&status).map_or(EffectiveUid::Unavailable, EffectiveUid::Known)
        }
        Err(_) => EffectiveUid::Unavailable,
    }
}

/// Parses the effective UID from `/proc/self/status` content.
#[cfg(all(unix, target_os = "linux"))]
fn parse_effective_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|values| values.split_whitespace().nth(1))
        .and_then(|value| value.parse().ok())
}

/// Ownership cannot be determined safely on this platform without additional
/// dependencies or unsafe code; the check is skipped and documented.
#[cfg(all(unix, not(target_os = "linux")))]
fn system_effective_uid() -> EffectiveUid {
    EffectiveUid::Unavailable
}

/// Builds a sanitized, bounded diagnostic for a TOML error.
fn format_parse_error(error: &toml::de::Error, contents: &str) -> String {
    let message = error.message();
    let is_schema = is_schema_error(message);
    let is_too_many_rules = message.starts_with("too many scope rules");
    let category = if is_schema {
        "configuration schema error"
    } else if is_too_many_rules {
        "too many scope rules"
    } else {
        "TOML syntax error"
    };

    match error.span() {
        Some(span) => {
            let (line, column) = line_column(contents, span.start);
            if is_schema {
                format!("{category} at line {line}, column {column}")
            } else {
                let sanitized = sanitize_text(message);
                format!("{category} at line {line}, column {column}: {sanitized}")
            }
        }
        None => {
            if is_schema {
                category.to_owned()
            } else {
                let sanitized = sanitize_text(message);
                format!("{category}: {sanitized}")
            }
        }
    }
}

/// Best-effort classification of deserialization errors.
fn is_schema_error(message: &str) -> bool {
    [
        "unknown field",
        "missing field",
        "invalid type",
        "invalid value",
        "duplicate field",
    ]
    .iter()
    .any(|prefix| message.starts_with(prefix))
}

/// Converts a byte offset into a 1-based line and column.
fn line_column(contents: &str, byte_offset: usize) -> (usize, usize) {
    let offset = floor_char_boundary(contents, byte_offset.min(contents.len()));
    let prefix = &contents[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let line_start = prefix.rfind('\n').map_or(0, |index| index + 1);
    let column = contents[line_start..offset].chars().count() + 1;

    (line, column)
}

/// Returns the largest character boundary at or below `offset`.
fn floor_char_boundary(contents: &str, mut offset: usize) -> usize {
    while offset > 0 && !contents.is_char_boundary(offset) {
        offset -= 1;
    }

    offset
}

/// Returns a bounded, terminal-safe rendering of untrusted text.
///
/// Printable ASCII is preserved. Control characters, Unicode format controls
/// and other non-ASCII characters are escaped with [`char::escape_debug`], so
/// ANSI, OSC, bidi and line-separator sequences cannot reach the terminal.
pub(crate) fn sanitize_text(input: &str) -> String {
    let mut output = String::new();
    let mut truncated = false;

    for (index, character) in input.chars().enumerate() {
        if index >= MAX_DISPLAY_CHARS {
            truncated = true;
            break;
        }

        if character.is_ascii_graphic() || character == ' ' {
            output.push(character);
        } else {
            output.extend(character.escape_debug());
        }
    }

    if truncated {
        output.push_str("...");
    }

    output
}

/// Renders a path without exposing control characters.
fn display_path(path: &Path) -> String {
    sanitize_text(&path.to_string_lossy())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path() -> PathBuf {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "netvigil-config-test-{}-{}.toml",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        path
    }

    fn write_fixture(path: &Path, contents: impl AsRef<[u8]>) {
        fs::write(path, contents).expect("write fixture");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("set fixture permissions");
        }
    }

    #[test]
    fn parses_example_configuration() {
        let config = Config::parse(
            r#"
[scope]
targets = [
    "192.168.1.0/24",
    "10.0.0.15",
    "203.0.113.10",
    "scan.exemplo.com",
]
"#,
        )
        .expect("example configuration must be valid");

        assert_eq!(
            config.scope.targets,
            [
                "192.168.1.0/24",
                "10.0.0.15",
                "203.0.113.10",
                "scan.exemplo.com",
            ]
        );
    }

    #[test]
    fn accepts_empty_target_list() {
        let config = Config::parse("[scope]\ntargets = []\n").expect("empty scope is valid");

        assert!(config.scope.targets.is_empty());
    }

    #[test]
    fn accepts_scope_without_targets_field() {
        let config = Config::parse("[scope]\n").expect("scope table alone is valid");

        assert!(config.scope.targets.is_empty());
    }

    #[test]
    fn rejects_missing_scope_table() {
        assert!(Config::parse("").is_err());
        assert!(Config::parse("other = 1\n").is_err());
    }

    #[test]
    fn rejects_invalid_toml() {
        assert!(Config::parse("[scope\ntargets = []\n").is_err());
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(Config::parse("[scope]\ntargets = []\nallow_all = true\n").is_err());
        assert!(Config::parse("[scope]\ntargets = []\n[other]\n").is_err());
    }

    #[test]
    fn rejects_wrong_field_type() {
        assert!(Config::parse("[scope]\ntargets = \"192.0.2.10\"\n").is_err());
        assert!(Config::parse("[scope]\ntargets = [10]\n").is_err());
    }

    #[test]
    fn rejects_too_many_rules_during_parse() {
        let mut contents = String::from("[scope]\ntargets = [\n");
        for _ in 0..=MAX_SCOPE_RULES {
            contents.push_str("  \"192.0.2.1\",\n");
        }
        contents.push_str("]\n");

        let error = Config::parse(&contents).expect_err("excessive rules must fail");

        assert!(matches!(error, ParseError::Toml(_)));
    }

    #[test]
    fn missing_file_returns_read_error() {
        let path = temp_path();
        let error = Config::load(&path).expect_err("missing file must fail");

        assert!(matches!(error, ConfigError::Read { .. }));
    }

    #[test]
    fn invalid_file_returns_parse_error() {
        let path = temp_path();
        write_fixture(&path, b"[scope]\ntargets = [\n");
        let error = Config::load(&path).expect_err("invalid TOML must fail");
        let _ = fs::remove_file(&path);

        assert!(matches!(error, ConfigError::Parse { .. }));
    }

    #[test]
    fn loads_valid_file() {
        let path = temp_path();
        write_fixture(&path, b"[scope]\ntargets = [\"192.0.2.10\"]\n");
        let config = Config::load(&path).expect("valid configuration must load");
        let _ = fs::remove_file(&path);

        assert_eq!(config.scope.targets, ["192.0.2.10"]);
    }

    #[test]
    fn rejects_directory_in_place_of_file() {
        let path = temp_path();
        fs::create_dir(&path).expect("create directory fixture");
        let error = Config::load(&path).expect_err("directory must fail");
        let _ = fs::remove_dir(&path);

        assert!(matches!(error, ConfigError::NotRegularFile { .. }));
    }

    #[test]
    fn rejects_oversized_file() {
        let path = temp_path();
        write_fixture(&path, vec![b'\n'; MAX_CONFIG_BYTES + 1]);
        let error = Config::load(&path).expect_err("oversized file must fail");
        let _ = fs::remove_file(&path);

        assert!(matches!(
            error,
            ConfigError::TooLarge { limit, .. } if limit == MAX_CONFIG_BYTES
        ));
    }

    #[test]
    fn rejects_non_utf8_file() {
        let path = temp_path();
        write_fixture(&path, [0xff, 0xfe]);
        let error = Config::load(&path).expect_err("non-UTF-8 file must fail");
        let _ = fs::remove_file(&path);

        assert!(matches!(error, ConfigError::NotUtf8 { .. }));
    }

    #[test]
    fn rejects_file_with_too_many_rules() {
        let path = temp_path();
        let mut contents = String::from("[scope]\ntargets = [\n");
        for _ in 0..=MAX_SCOPE_RULES {
            contents.push_str("  \"192.0.2.1\",\n");
        }
        contents.push_str("]\n");
        write_fixture(&path, contents);
        let error = Config::load(&path).expect_err("excessive rules must fail");
        let _ = fs::remove_file(&path);

        assert!(matches!(error, ConfigError::Parse { .. }));
    }

    #[test]
    fn parse_error_includes_line_and_column() {
        let path = temp_path();
        write_fixture(&path, b"[scope]\ntargets = [\n");
        let error = Config::load(&path).expect_err("invalid TOML must fail");
        let _ = fs::remove_file(&path);

        let message = error.to_string();
        assert!(message.contains("line"), "message: {message}");
        assert!(message.contains("column"), "message: {message}");
    }

    #[test]
    fn parse_error_does_not_reproduce_control_sequences() {
        let path = temp_path();
        write_fixture(&path, b"[scope]\ntargets = [\n  \"\x1b]0;owned\x07\",\n");
        let error = Config::load(&path).expect_err("invalid TOML must fail");
        let _ = fs::remove_file(&path);

        let message = error.to_string();
        assert!(!message.contains('\u{1b}'), "leaked ESC: {message:?}");
        assert!(!message.contains('\u{7}'), "leaked BEL: {message:?}");
    }

    #[cfg(unix)]
    #[test]
    fn read_error_escapes_control_characters_in_path() {
        let path = temp_path();
        let mut name = path.file_name().expect("fixture name").to_os_string();
        name.push("\u{1b}]0;owned\u{7}");
        let path = path.with_file_name(name);

        let error = Config::load(&path).expect_err("missing file must fail");
        let message = error.to_string();

        assert!(!message.contains('\u{1b}'), "leaked ESC: {message:?}");
        assert!(!message.contains('\u{7}'), "leaked BEL: {message:?}");
        assert!(message.contains("\\u{1b}"), "missing escape: {message:?}");
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_or_world_writable_file() {
        use std::os::unix::fs::PermissionsExt;

        let path = temp_path();
        write_fixture(&path, b"[scope]\ntargets = []\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))
            .expect("set insecure permissions");
        let error = Config::load(&path).expect_err("insecure permissions must fail");
        let _ = fs::remove_file(&path);

        assert!(matches!(error, ConfigError::InsecurePermissions { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_link() {
        use std::os::unix::fs::symlink;

        let target = temp_path();
        write_fixture(&target, b"[scope]\ntargets = []\n");
        let link = temp_path();
        symlink(&target, &link).expect("create symlink fixture");
        let error = Config::load(&link).expect_err("symlink must fail");
        let _ = fs::remove_file(&link);
        let _ = fs::remove_file(&target);

        assert!(matches!(error, ConfigError::Symlink { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_fifo_without_blocking() {
        use std::os::unix::fs::FileTypeExt;

        let path = temp_path();
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo failed: {status}");
        assert!(
            fs::metadata(&path)
                .expect("FIFO metadata")
                .file_type()
                .is_fifo()
        );

        let (sender, receiver) = std::sync::mpsc::channel();
        let fifo_path = path.clone();
        let handle = std::thread::spawn(move || {
            let result = Config::load(&fifo_path);
            let _ = sender.send(result.map(|_| ()));
        });

        let result = receiver
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("opening a FIFO must not block");
        let _ = handle.join();
        let _ = fs::remove_file(&path);

        let error = result.expect_err("FIFO must be rejected");
        assert!(matches!(error, ConfigError::NotRegularFile { .. }));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_ownership_mismatch_when_effective_uid_is_known() {
        use std::os::unix::fs::MetadataExt;

        let path = temp_path();
        write_fixture(&path, b"[scope]\ntargets = []\n");
        let metadata = fs::metadata(&path).expect("fixture metadata");
        let other_uid = metadata.uid().wrapping_add(1);

        let error = open_trusted_with_euid(&path, "fixture", EffectiveUid::Known(other_uid))
            .expect_err("ownership mismatch must fail");
        let _ = fs::remove_file(&path);

        assert!(matches!(error, ConfigError::UntrustedOwner { .. }));
    }

    #[cfg(all(unix, target_os = "linux"))]
    #[test]
    fn rejects_configuration_when_effective_uid_is_unavailable() {
        let path = temp_path();
        write_fixture(&path, b"[scope]\ntargets = []\n");

        let error = open_trusted_with_euid(&path, "fixture", EffectiveUid::Unavailable)
            .expect_err("unavailable EUID must fail closed");
        let _ = fs::remove_file(&path);

        assert!(matches!(error, ConfigError::EuidUnavailable { .. }));
    }

    #[cfg(all(unix, target_os = "linux"))]
    #[test]
    fn parses_effective_uid_from_proc_status() {
        assert_eq!(
            parse_effective_uid("Name:\tnetvigil\nUid:\t1000\t1001\t1002\t1003\n"),
            Some(1001)
        );
        assert_eq!(parse_effective_uid("Uid:\t1000\n"), None);
        assert_eq!(parse_effective_uid("Name:\tnetvigil\n"), None);
        assert_eq!(parse_effective_uid("Uid:\t1000\tnot-a-number\n"), None);
    }

    #[test]
    fn default_deny_is_preserved_after_successful_load() {
        let path = temp_path();
        write_fixture(&path, b"[scope]\ntargets = [\"192.0.2.10\"]\n");
        let config = Config::load(&path).expect("valid configuration must load");
        let _ = fs::remove_file(&path);

        let scope = crate::scope::Scope::from_config(&config).expect("valid scope");
        let target = crate::target::Target::parse("192.0.2.11").expect("valid target");

        assert!(scope.authorize(&target).is_err());
    }

    #[test]
    fn schema_error_does_not_reproduce_scalar_value() {
        let path = temp_path();
        write_fixture(&path, b"[scope]\ntargets = 42\n");
        let error = Config::load(&path).expect_err("invalid type must fail");
        let _ = fs::remove_file(&path);

        let message = error.to_string();
        assert!(!message.contains("42"), "leaked value: {message}");
        assert!(message.contains("schema"), "message: {message}");
    }

    #[test]
    fn accepts_4096_scope_rules() {
        let path = temp_path();
        let mut contents = String::from("[scope]\ntargets = [\n");
        for _ in 0..MAX_SCOPE_RULES {
            contents.push_str("  \"192.0.2.1\",\n");
        }
        contents.push_str("]\n");
        write_fixture(&path, contents);
        let config = Config::load(&path).expect("4096 rules must load");
        let _ = fs::remove_file(&path);

        assert_eq!(config.scope.targets.len(), MAX_SCOPE_RULES);
    }

    #[test]
    fn rejects_4097_scope_rules() {
        let path = temp_path();
        let mut contents = String::from("[scope]\ntargets = [\n");
        for _ in 0..=MAX_SCOPE_RULES {
            contents.push_str("  \"192.0.2.1\",\n");
        }
        contents.push_str("]\n");
        write_fixture(&path, contents);
        let error = Config::load(&path).expect_err("4097 rules must fail");
        let _ = fs::remove_file(&path);

        assert!(matches!(error, ConfigError::Parse { .. }));
    }

    #[test]
    fn scope_error_does_not_reproduce_long_entry() {
        let long = "a".repeat(500);
        let config = crate::config::Config {
            scope: crate::config::ScopeConfig {
                targets: vec![long.clone()],
            },
        };
        let error = crate::scope::Scope::from_config(&config).expect_err("invalid entry must fail");
        let message = error.to_string();

        assert!(!message.contains(&long), "entry leaked in full: {message}");
    }

    #[test]
    fn scope_error_does_not_emit_control_sequences() {
        let entry = "bad\u{1b}]0;pwned\u{7}\u{202e}".to_owned();
        let config = crate::config::Config {
            scope: crate::config::ScopeConfig {
                targets: vec![entry],
            },
        };
        let error = crate::scope::Scope::from_config(&config).expect_err("invalid entry must fail");
        let message = error.to_string();

        assert!(!message.contains('\u{1b}'), "leaked ESC: {message:?}");
        assert!(!message.contains('\u{7}'), "leaked BEL: {message:?}");
        assert!(!message.contains('\u{202e}'), "leaked bidi: {message:?}");
    }

    #[test]
    fn sanitizes_and_truncates_display_text() {
        let input = format!("prefix\u{1b}]0;title\u{7}{}", "x".repeat(MAX_DISPLAY_CHARS));
        let sanitized = sanitize_text(&input);

        assert!(!sanitized.contains('\u{1b}'));
        assert!(!sanitized.contains('\u{7}'));
        assert!(sanitized.contains("\\u{1b}"));
        assert!(sanitized.ends_with("..."));
    }
}
