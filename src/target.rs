//! Validation and normalization of scan targets.
//!
//! This module validates user-provided targets before any network operation.
//! It does not perform DNS resolution: hostnames are checked syntactically
//! only and are kept in their normalized form.
//!
//! Only printable ASCII targets are accepted. ASCII control characters and
//! non-ASCII characters (including Unicode format/bidi controls and
//! internationalized hostnames) are rejected. IPv4-mapped IPv6 addresses are
//! normalized to IPv4.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use thiserror::Error;

/// Maximum length of a hostname, excluding an optional trailing dot.
pub const MAX_HOSTNAME_LENGTH: usize = 253;

/// Maximum length of a single hostname label.
pub const MAX_LABEL_LENGTH: usize = 63;

/// A validated scan target.
///
/// The inner representation is private so other modules cannot construct an
/// invalid target. Use [`Target::parse`] or [`Target::from_str`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    inner: TargetKind,
}

/// Private representation of a validated target.
#[derive(Debug, Clone, PartialEq, Eq)]
enum TargetKind {
    /// A normalized IPv4 or IPv6 address.
    Ip(IpAddr),
    /// A syntactically valid hostname, normalized to lowercase.
    Hostname(String),
}

impl Target {
    /// Validates and normalizes a target.
    ///
    /// Returns an IP target when the input is a valid IPv4 or IPv6 address.
    /// IPv4-mapped IPv6 addresses are normalized to their IPv4 representation.
    /// Otherwise the input is validated as a hostname according to the
    /// RFC 1123 rules supported by NetVigil and returned in lowercase, without
    /// an optional trailing dot.
    ///
    /// The input length is checked before attempting to parse it as an IP
    /// address, so the IP parser only ever receives bounded input.
    ///
    /// No DNS resolution or network access is performed.
    ///
    /// # Errors
    ///
    /// Returns a [`TargetError`] describing why the input is not a valid
    /// target.
    pub fn parse(input: &str) -> Result<Self, TargetError> {
        if input.trim().is_empty() {
            return Err(TargetError::Empty);
        }

        if input.chars().any(char::is_whitespace) {
            return Err(TargetError::Whitespace);
        }

        if let Some(character) = input
            .chars()
            .find(|character| is_disallowed_char(*character))
        {
            return Err(TargetError::InvalidCharacter(character));
        }

        // A single trailing dot denotes a fully qualified name; drop it before
        // validating the name. The length check runs before the IP parser so
        // that parser only receives bounded input.
        let name = input.strip_suffix('.').unwrap_or(input);
        if name.is_empty() {
            return Err(TargetError::EmptyLabel);
        }

        if name.len() > MAX_HOSTNAME_LENGTH {
            return Err(TargetError::TooLong);
        }

        if let Ok(ip) = input.parse::<IpAddr>() {
            return Ok(Self {
                inner: TargetKind::Ip(normalize_ip(ip)),
            });
        }

        let mut labels = name.split('.').peekable();
        while let Some(label) = labels.next() {
            validate_label(label)?;

            // DNS top-level labels must not be entirely numeric, so values
            // that look like an IP address but are not one stay invalid.
            if labels.peek().is_none() && label.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(TargetError::NumericTopLevelLabel);
            }
        }

        Ok(Self {
            inner: TargetKind::Hostname(name.to_ascii_lowercase()),
        })
    }

    /// Returns the normalized IP address when this target is an IP literal.
    #[allow(dead_code)] // Used by tests now and by the scanner module later.
    pub fn as_ip(&self) -> Option<IpAddr> {
        match &self.inner {
            TargetKind::Ip(ip) => Some(*ip),
            TargetKind::Hostname(_) => None,
        }
    }

    /// Returns the normalized hostname when this target is a hostname.
    #[allow(dead_code)] // Used by tests now and by the scanner module later.
    pub fn as_hostname(&self) -> Option<&str> {
        match &self.inner {
            TargetKind::Hostname(name) => Some(name.as_str()),
            TargetKind::Ip(_) => None,
        }
    }
}

/// Returns whether a character must be rejected before target parsing.
///
/// Whitespace is reported separately by [`Target::parse`]; this predicate
/// covers ASCII control characters and every non-ASCII character, including
/// Unicode format/bidi controls and line separators. Hostnames are expected
/// in ASCII/punycode form.
fn is_disallowed_char(character: char) -> bool {
    character.is_ascii_control() || !character.is_ascii()
}

/// Normalizes an IPv4-mapped IPv6 address to its IPv4 representation.
fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().map_or(IpAddr::V6(ipv6), IpAddr::V4),
        IpAddr::V4(ipv4) => IpAddr::V4(ipv4),
    }
}

/// Validates a single hostname label.
fn validate_label(label: &str) -> Result<(), TargetError> {
    if label.is_empty() {
        return Err(TargetError::EmptyLabel);
    }

    if label.len() > MAX_LABEL_LENGTH {
        return Err(TargetError::LabelTooLong);
    }

    if label.starts_with('-') {
        return Err(TargetError::LabelStartsWithHyphen);
    }

    if label.ends_with('-') {
        return Err(TargetError::LabelEndsWithHyphen);
    }

    if let Some(character) = label.chars().find(|c| !is_valid_label_char(*c)) {
        return Err(TargetError::InvalidCharacter(character));
    }

    Ok(())
}

/// Returns whether a character is allowed in a hostname label.
fn is_valid_label_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '-'
}

impl fmt::Display for Target {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            TargetKind::Ip(ip) => write!(formatter, "{ip}"),
            TargetKind::Hostname(name) => formatter.write_str(name),
        }
    }
}

impl FromStr for Target {
    type Err = TargetError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

/// Reasons why a target is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TargetError {
    /// The input is empty or contains only whitespace.
    #[error("target must not be empty")]
    Empty,

    /// The input contains whitespace.
    #[error("target must not contain whitespace")]
    Whitespace,

    /// The input is longer than [`MAX_HOSTNAME_LENGTH`].
    #[error("target must not exceed {MAX_HOSTNAME_LENGTH} characters")]
    TooLong,

    /// A hostname label is longer than [`MAX_LABEL_LENGTH`].
    #[error("hostname label must not exceed {MAX_LABEL_LENGTH} characters")]
    LabelTooLong,

    /// The input or one of its labels is empty.
    #[error("hostname must not contain empty labels")]
    EmptyLabel,

    /// A hostname label starts with a hyphen.
    #[error("hostname label must not start with a hyphen")]
    LabelStartsWithHyphen,

    /// A hostname label ends with a hyphen.
    #[error("hostname label must not end with a hyphen")]
    LabelEndsWithHyphen,

    /// The input contains an ASCII control character, a non-ASCII character
    /// (including Unicode format/bidi controls), or a character that is not
    /// allowed in a hostname label. Internationalized names are not supported
    /// yet.
    #[error("target contains an invalid character: {0:?}")]
    InvalidCharacter(char),

    /// The final hostname label is entirely numeric.
    #[error("hostname must not end with a numeric label")]
    NumericTopLevelLabel,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn parse_ok(input: &str) -> Target {
        Target::parse(input).expect("test input must be valid")
    }

    #[test]
    fn accepts_ipv4_address() {
        let target = parse_ok("192.0.2.10");

        assert_eq!(
            target.as_ip(),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        );
        assert_eq!(target.as_hostname(), None);
    }

    #[test]
    fn accepts_ipv6_address() {
        let target = parse_ok("2001:db8::1");

        assert_eq!(
            target.as_ip(),
            Some(IpAddr::V6(
                "2001:db8::1".parse::<Ipv6Addr>().expect("valid IPv6")
            ))
        );
        assert_eq!(target.as_hostname(), None);
    }

    #[test]
    fn accepts_loopback_addresses() {
        assert_eq!(
            parse_ok("127.0.0.1").as_ip(),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(
            parse_ok("::1").as_ip(),
            Some(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
    }

    #[test]
    fn normalizes_ipv4_mapped_ipv6() {
        let cases = [
            ("::ffff:127.0.0.1", Ipv4Addr::new(127, 0, 0, 1)),
            ("::ffff:192.0.2.10", Ipv4Addr::new(192, 0, 2, 10)),
            ("::FFFF:198.51.100.7", Ipv4Addr::new(198, 51, 100, 7)),
        ];

        for (input, expected) in cases {
            let target = parse_ok(input);

            assert_eq!(target.as_ip(), Some(IpAddr::V4(expected)), "input: {input}");
            assert_eq!(target.as_hostname(), None);
            assert_eq!(target.to_string(), expected.to_string());
        }
    }

    #[test]
    fn preserves_conventional_ipv6_addresses() {
        for input in ["2001:db8::1", "::1", "fe80::1", "2001:db8:0:1::1"] {
            let target = parse_ok(input);

            assert!(
                matches!(target.as_ip(), Some(IpAddr::V6(_))),
                "input: {input}"
            );
        }
    }

    #[test]
    fn accepts_hostnames() {
        for input in [
            "example.com",
            "sub.example.com",
            "localhost",
            "a-b.example.co",
        ] {
            let target = parse_ok(input);

            assert_eq!(
                target.as_hostname(),
                Some(input),
                "expected {input:?} to be a valid hostname"
            );
            assert_eq!(target.as_ip(), None);
        }
    }

    #[test]
    fn normalizes_hostname_to_lowercase() {
        assert_eq!(parse_ok("Example.COM").as_hostname(), Some("example.com"));
    }

    #[test]
    fn strips_trailing_dot_from_hostname() {
        assert_eq!(parse_ok("example.com.").as_hostname(), Some("example.com"));
    }

    #[test]
    fn accepts_hostname_at_maximum_label_length() {
        let label = "a".repeat(MAX_LABEL_LENGTH);
        let input = format!("{label}.com");

        assert_eq!(
            parse_ok(&input).as_hostname(),
            Some(input.to_ascii_lowercase().as_str())
        );
    }

    #[test]
    fn accepts_maximum_hostname_length_with_trailing_dot() {
        let label = "a".repeat(MAX_LABEL_LENGTH);
        let name = format!("{label}.{label}.{label}.{}", "a".repeat(61));
        assert_eq!(name.len(), MAX_HOSTNAME_LENGTH);

        let input = format!("{name}.");
        assert_eq!(parse_ok(&input).as_hostname(), Some(name.as_str()));
    }

    #[test]
    fn rejects_empty_target() {
        assert_eq!(Target::parse(""), Err(TargetError::Empty));
        assert_eq!(Target::parse("   "), Err(TargetError::Empty));
        assert_eq!(Target::parse("\t\n"), Err(TargetError::Empty));
    }

    #[test]
    fn rejects_target_with_whitespace() {
        assert_eq!(Target::parse("example host"), Err(TargetError::Whitespace));
        assert_eq!(Target::parse(" example.com"), Err(TargetError::Whitespace));
        assert_eq!(Target::parse("example.com "), Err(TargetError::Whitespace));
    }

    #[test]
    fn rejects_hostname_with_empty_label() {
        assert_eq!(Target::parse("example..com"), Err(TargetError::EmptyLabel));
        assert_eq!(Target::parse(".example.com"), Err(TargetError::EmptyLabel));
        assert_eq!(Target::parse("example.com.."), Err(TargetError::EmptyLabel));
        assert_eq!(Target::parse("."), Err(TargetError::EmptyLabel));
    }

    #[test]
    fn rejects_label_longer_than_maximum() {
        let input = format!("{}.com", "a".repeat(MAX_LABEL_LENGTH + 1));

        assert_eq!(Target::parse(&input), Err(TargetError::LabelTooLong));
    }

    #[test]
    fn rejects_hostname_longer_than_maximum() {
        let label = "a".repeat(MAX_LABEL_LENGTH);
        // 4 * 63 characters plus 3 separators exceeds the hostname limit.
        let input = format!("{label}.{label}.{label}.{label}");

        assert_eq!(Target::parse(&input), Err(TargetError::TooLong));
    }

    #[test]
    fn rejects_oversized_input_before_ip_parsing() {
        let input = "1".repeat(MAX_HOSTNAME_LENGTH + 1);

        assert_eq!(Target::parse(&input), Err(TargetError::TooLong));
    }

    #[test]
    fn rejects_leading_hyphen_in_label() {
        assert_eq!(
            Target::parse("-example.com"),
            Err(TargetError::LabelStartsWithHyphen)
        );
        assert_eq!(
            Target::parse("sub.-example.com"),
            Err(TargetError::LabelStartsWithHyphen)
        );
    }

    #[test]
    fn rejects_trailing_hyphen_in_label() {
        assert_eq!(
            Target::parse("example-.com"),
            Err(TargetError::LabelEndsWithHyphen)
        );
    }

    #[test]
    fn rejects_invalid_characters() {
        assert_eq!(
            Target::parse("exa_mple.com"),
            Err(TargetError::InvalidCharacter('_'))
        );
        assert_eq!(
            Target::parse("example.com/path"),
            Err(TargetError::InvalidCharacter('/'))
        );
        assert_eq!(
            Target::parse("user@example.com"),
            Err(TargetError::InvalidCharacter('@'))
        );
    }

    #[test]
    fn rejects_ascii_control_characters() {
        for character in ['\u{0}', '\u{1}', '\u{7}', '\u{8}', '\u{1b}', '\u{7f}'] {
            let input = format!("evil{character}host");

            assert_eq!(
                Target::parse(&input),
                Err(TargetError::InvalidCharacter(character)),
                "character: U+{:04X}",
                character as u32
            );
        }
    }

    #[test]
    fn rejects_unicode_format_and_bidi_characters() {
        for character in [
            '\u{9b}', '\u{200b}', '\u{200e}', '\u{200f}', '\u{202a}', '\u{202e}', '\u{2066}',
            '\u{2069}', '\u{feff}',
        ] {
            let input = format!("evil{character}host");

            assert_eq!(
                Target::parse(&input),
                Err(TargetError::InvalidCharacter(character)),
                "character: U+{:04X}",
                character as u32
            );
        }
    }

    #[test]
    fn rejects_unicode_line_separators() {
        for character in ['\u{2028}', '\u{2029}'] {
            let input = format!("evil{character}host");

            assert_eq!(
                Target::parse(&input),
                Err(TargetError::Whitespace),
                "character: U+{:04X}",
                character as u32
            );
        }
    }

    #[test]
    fn rejects_internationalized_hostname() {
        assert_eq!(
            Target::parse("exämple.com"),
            Err(TargetError::InvalidCharacter('ä'))
        );
    }

    #[test]
    fn rejects_numeric_top_level_label() {
        assert_eq!(
            Target::parse("999.999.999.999"),
            Err(TargetError::NumericTopLevelLabel)
        );
        assert_eq!(Target::parse("123"), Err(TargetError::NumericTopLevelLabel));
    }

    #[test]
    fn rejects_blank_ipv6_zone_identifier() {
        // Zone identifiers are not supported, so the input is not a valid IP
        // address and fails hostname validation as well.
        assert!(matches!(
            Target::parse("fe80::1%eth0"),
            Err(TargetError::InvalidCharacter(_))
        ));
    }

    #[test]
    fn error_messages_do_not_contain_control_characters() {
        for character in ['\u{1b}', '\u{9b}', '\u{200b}', '\u{202e}', '\u{feff}'] {
            let input = format!("evil{character}host");
            let error = Target::parse(&input).expect_err("input must be rejected");
            let message = error.to_string();

            assert!(
                !message.contains(character),
                "error leaked {character:?}: {message:?}"
            );
        }
    }

    #[test]
    fn display_round_trips_valid_targets() {
        for input in ["192.0.2.10", "2001:db8::1", "example.com"] {
            assert_eq!(parse_ok(input).to_string(), input);
        }
    }

    #[test]
    fn from_str_delegates_to_parse() {
        assert_eq!(
            "example.com"
                .parse::<Target>()
                .map(|target| target.as_hostname().map(str::to_owned)),
            Ok(Some("example.com".to_owned()))
        );
        assert_eq!("".parse::<Target>(), Err(TargetError::Empty));
    }
}
