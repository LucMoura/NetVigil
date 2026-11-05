//! Authorization scope and special-address policy.
//!
//! Authorization is default deny: a target is allowed only when it matches an
//! entry declared by the operator. The scope is independent from target syntax
//! validation and performs no DNS resolution or network access.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::IpNet;
use thiserror::Error;

use crate::config::{Config, MAX_SCOPE_RULES, sanitize_text};
use crate::target::Target;

/// Classification of an IP address for authorization purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressClass {
    /// The unspecified address (`0.0.0.0` or `::`).
    Unspecified,
    /// A loopback address (`127.0.0.0/8` or `::1`).
    Loopback,
    /// A link-local address (`169.254.0.0/16` or `fe80::/10`).
    LinkLocal,
    /// A multicast address.
    Multicast,
    /// The IPv4 broadcast address (`255.255.255.255`).
    Broadcast,
    /// A private address (`10.0.0.0/8`, `172.16.0.0/12`,
    /// `192.168.0.0/16` or `fc00::/7`).
    Private,
    /// Any other address, including documentation and public ranges.
    Global,
}

impl AddressClass {
    /// Returns whether this class can never be an authorized scan target.
    ///
    /// These addresses are not valid unicast destinations and stay denied even
    /// when a scope rule matches them.
    fn is_always_denied(self) -> bool {
        matches!(self, Self::Unspecified | Self::Multicast | Self::Broadcast)
    }
}

impl fmt::Display for AddressClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Unspecified => "unspecified",
            Self::Loopback => "loopback",
            Self::LinkLocal => "link-local",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Private => "private",
            Self::Global => "global",
        };
        formatter.write_str(name)
    }
}

/// Classifies an IP address for authorization.
///
/// IPv4-mapped IPv6 addresses are classified as their IPv4 equivalent so that
/// alternate textual forms cannot bypass the special-address policy.
pub fn classify(ip: IpAddr) -> AddressClass {
    match ip {
        IpAddr::V4(ip) => classify_ipv4(ip),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => classify_ipv4(ip),
            None => classify_ipv6(ip),
        },
    }
}

fn classify_ipv4(ip: Ipv4Addr) -> AddressClass {
    if ip.is_unspecified() {
        AddressClass::Unspecified
    } else if ip.is_loopback() {
        AddressClass::Loopback
    } else if ip.is_link_local() {
        AddressClass::LinkLocal
    } else if ip.is_multicast() {
        AddressClass::Multicast
    } else if ip.is_broadcast() {
        AddressClass::Broadcast
    } else if ip.is_private() {
        AddressClass::Private
    } else {
        AddressClass::Global
    }
}

fn classify_ipv6(ip: Ipv6Addr) -> AddressClass {
    let segments = ip.segments();

    if ip.is_unspecified() {
        AddressClass::Unspecified
    } else if ip.is_loopback() {
        AddressClass::Loopback
    } else if ip.is_multicast() {
        AddressClass::Multicast
    } else if (segments[0] & 0xffc0) == 0xfe80 {
        // fe80::/10, the IPv6 unicast link-local range.
        AddressClass::LinkLocal
    } else if (segments[0] & 0xfe00) == 0xfc00 {
        // fc00::/7, the IPv6 unique-local range.
        AddressClass::Private
    } else {
        AddressClass::Global
    }
}

/// A single entry of the configured scope.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rule {
    /// An individual IP address.
    Ip(IpAddr),
    /// An IPv4 or IPv6 network.
    Network(IpNet),
    /// A normalized hostname.
    Hostname(String),
}

impl Rule {
    /// Returns whether this rule covers the target.
    fn matches(&self, target: &Target) -> bool {
        match self {
            Self::Ip(ip) => target.as_ip() == Some(*ip),
            Self::Network(network) => target
                .as_ip()
                .is_some_and(|ip| network_contains(network, ip)),
            Self::Hostname(name) => target.as_hostname() == Some(name.as_str()),
        }
    }
}

/// Returns whether a network contains an address of the matching family.
fn network_contains(network: &IpNet, ip: IpAddr) -> bool {
    match (network, ip) {
        (IpNet::V4(network), IpAddr::V4(ip)) => network.contains(&ip),
        (IpNet::V6(network), IpAddr::V6(ip)) => network.contains(&ip),
        _ => false,
    }
}

/// Errors produced while building a scope from configuration.
#[derive(Debug, Error)]
pub enum ScopeError {
    /// A scope entry is not a valid IP address, network or hostname.
    #[error("invalid scope entry {entry:?} at index {index}: {reason}")]
    InvalidTarget {
        /// Position of the entry in `scope.targets`.
        index: usize,
        /// The rejected entry, escaped for safe display.
        entry: String,
        /// Why the entry is invalid.
        reason: String,
    },

    /// A scope entry that contains `/` is not a valid CIDR network.
    #[error("invalid CIDR scope entry {entry:?} at index {index}")]
    InvalidCidr {
        /// Position of the entry in `scope.targets`.
        index: usize,
        /// The rejected entry, escaped for safe display.
        entry: String,
    },

    /// The configuration declares more rules than the supported maximum.
    #[error("configuration declares too many scope rules (maximum {limit})")]
    TooManyRules {
        /// Maximum accepted number of rules.
        limit: usize,
    },
}

/// Reasons why a target is not authorized.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuthorizationError {
    /// The target does not match any configured scope entry.
    #[error("target {target} is not authorized by the configured scope")]
    NotInScope {
        /// Normalized target.
        target: String,
    },

    /// The target is an address class that can never be scanned.
    #[error("target {target} is an address of class {class} and cannot be scanned")]
    SpecialAddress {
        /// Normalized target.
        target: String,
        /// Address class that caused the denial.
        class: AddressClass,
    },
}

/// The operator-declared authorization scope.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    rules: Vec<Rule>,
}

impl Scope {
    /// Builds a scope from configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeError`] when any entry is not a valid IP address, CIDR
    /// network or hostname. Invalid scope data never authorizes a target.
    pub fn from_config(config: &Config) -> Result<Self, ScopeError> {
        if config.scope.targets.len() > MAX_SCOPE_RULES {
            return Err(ScopeError::TooManyRules {
                limit: MAX_SCOPE_RULES,
            });
        }

        let mut rules = Vec::with_capacity(config.scope.targets.len());

        for (index, entry) in config.scope.targets.iter().enumerate() {
            rules.push(parse_rule(entry, index)?);
        }

        Ok(Self { rules })
    }

    /// Authorizes a normalized target.
    ///
    /// The target must have been validated by [`Target::parse`]. Hostnames are
    /// matched exactly against hostname entries; no DNS resolution occurs.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationError::SpecialAddress`] for address classes that
    /// cannot be scanned even when declared, and
    /// [`AuthorizationError::NotInScope`] when no rule matches.
    pub fn authorize(&self, target: &Target) -> Result<(), AuthorizationError> {
        if let Some(ip) = target.as_ip() {
            let class = classify(ip);
            if class.is_always_denied() {
                return Err(AuthorizationError::SpecialAddress {
                    target: target.to_string(),
                    class,
                });
            }
        }

        if self.rules.iter().any(|rule| rule.matches(target)) {
            Ok(())
        } else {
            Err(AuthorizationError::NotInScope {
                target: target.to_string(),
            })
        }
    }
}

/// Parses one configured scope entry into a rule.
fn parse_rule(entry: &str, index: usize) -> Result<Rule, ScopeError> {
    if entry.contains('/') {
        let network = IpNet::from_str(entry).map_err(|_| ScopeError::InvalidCidr {
            index,
            entry: sanitize_text(entry),
        })?;
        return Ok(Rule::Network(network));
    }

    let target = Target::parse(entry).map_err(|error| ScopeError::InvalidTarget {
        index,
        entry: sanitize_text(entry),
        reason: sanitize_text(&error.to_string()),
    })?;

    match target.as_ip() {
        Some(ip) => Ok(Rule::Ip(ip)),
        None => match target.as_hostname() {
            Some(hostname) => Ok(Rule::Hostname(hostname.to_owned())),
            // `Target` only has IP and hostname representations; this branch is
            // unreachable but avoids panicking if that invariant changes.
            None => Err(ScopeError::InvalidTarget {
                index,
                entry: sanitize_text(entry),
                reason: sanitize_text("unsupported target representation"),
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScopeConfig;

    fn scope(targets: &[&str]) -> Scope {
        let config = Config {
            scope: ScopeConfig {
                targets: targets.iter().map(|target| (*target).to_owned()).collect(),
            },
        };

        Scope::from_config(&config).expect("test scope must be valid")
    }

    fn target(input: &str) -> Target {
        Target::parse(input).expect("test target must be valid")
    }

    fn assert_authorized(targets: &[&str], input: &str) {
        let result = scope(targets).authorize(&target(input));

        assert_eq!(result, Ok(()), "target {input} should be authorized");
    }

    fn assert_not_in_scope(targets: &[&str], input: &str) {
        let result = scope(targets).authorize(&target(input));

        assert!(
            matches!(result, Err(AuthorizationError::NotInScope { .. })),
            "target {input} should be denied as out of scope, got {result:?}"
        );
    }

    fn assert_special_address(targets: &[&str], input: &str, expected: AddressClass) {
        let result = scope(targets).authorize(&target(input));

        assert_eq!(
            result,
            Err(AuthorizationError::SpecialAddress {
                target: target(input).to_string(),
                class: expected,
            }),
            "target {input} should be denied as {expected}"
        );
    }

    #[test]
    fn authorizes_individual_ipv4_address() {
        assert_authorized(&["192.0.2.10"], "192.0.2.10");
    }

    #[test]
    fn authorizes_ipv4_inside_cidr() {
        assert_authorized(&["192.168.1.0/24"], "192.168.1.42");
    }

    #[test]
    fn cidr_with_host_bits_still_matches_its_network() {
        assert_authorized(&["192.168.1.5/24"], "192.168.1.42");
    }

    #[test]
    fn rejects_ipv4_outside_cidr() {
        assert_not_in_scope(&["192.168.1.0/24"], "192.168.2.1");
    }

    #[test]
    fn authorizes_individual_ipv6_address() {
        assert_authorized(&["2001:db8::1"], "2001:db8::1");
    }

    #[test]
    fn authorizes_ipv6_inside_cidr() {
        assert_authorized(&["2001:db8::/32"], "2001:db8:1::5");
    }

    #[test]
    fn rejects_ipv6_outside_cidr() {
        assert_not_in_scope(&["2001:db8::/32"], "2001:db9::1");
    }

    #[test]
    fn ipv4_cidr_does_not_match_ipv6_address() {
        assert_not_in_scope(&["192.168.1.0/24"], "2001:db8::1");
    }

    #[test]
    fn authorizes_normalized_hostname() {
        assert_authorized(&["scan.example.com"], "SCAN.Example.COM.");
    }

    #[test]
    fn rejects_unauthorized_hostname() {
        assert_not_in_scope(&["scan.example.com"], "other.example.com");
    }

    #[test]
    fn hostname_rule_does_not_match_ip_literal() {
        assert_not_in_scope(&["192.0.2.10"], "example.com");
    }

    #[test]
    fn authorizes_public_ip_when_explicitly_declared() {
        assert_authorized(&["203.0.113.10"], "203.0.113.10");
    }

    #[test]
    fn authorizes_private_ip_when_explicitly_declared() {
        assert_authorized(&["10.0.0.15"], "10.0.0.15");
        assert_authorized(&["172.16.0.0/12"], "172.20.1.1");
        assert_authorized(&["192.168.1.0/24"], "192.168.1.7");
    }

    #[test]
    fn rejects_private_ip_that_is_not_declared() {
        assert_not_in_scope(&["10.0.0.15"], "10.0.0.16");
    }

    #[test]
    fn authorizes_private_ipv6_when_explicitly_declared() {
        assert_authorized(&["fc00::/7"], "fd12:3456::1");
    }

    #[test]
    fn rejects_private_ipv6_that_is_not_declared() {
        assert_not_in_scope(&[], "fd12:3456::1");
    }

    #[test]
    fn empty_scope_denies_every_target() {
        assert_not_in_scope(&[], "192.0.2.10");
        assert_not_in_scope(&[], "2001:db8::1");
        assert_not_in_scope(&[], "example.com");
    }

    #[test]
    fn loopback_requires_explicit_authorization() {
        assert_not_in_scope(&[], "127.0.0.1");
        assert_not_in_scope(&["192.0.2.10"], "127.0.0.1");
        assert_authorized(&["127.0.0.1"], "127.0.0.1");
        assert_authorized(&["127.0.0.0/8"], "127.0.0.2");
    }

    #[test]
    fn link_local_requires_explicit_authorization() {
        assert_not_in_scope(&[], "169.254.169.254");
        assert_authorized(&["169.254.0.0/16"], "169.254.169.254");
        assert_not_in_scope(&[], "fe80::1");
        assert_authorized(&["fe80::/10"], "fe80::1");
    }

    #[test]
    fn unspecified_is_denied_even_when_declared() {
        assert_special_address(&["0.0.0.0"], "0.0.0.0", AddressClass::Unspecified);
        assert_special_address(&["0.0.0.0/0"], "0.0.0.0", AddressClass::Unspecified);
        assert_special_address(&["::"], "::", AddressClass::Unspecified);
    }

    #[test]
    fn multicast_is_denied_even_when_declared() {
        assert_special_address(&["224.0.0.0/4"], "224.0.0.1", AddressClass::Multicast);
        assert_special_address(&["ff00::/8"], "ff02::1", AddressClass::Multicast);
    }

    #[test]
    fn broadcast_is_denied_even_when_declared() {
        assert_special_address(
            &["255.255.255.255"],
            "255.255.255.255",
            AddressClass::Broadcast,
        );
    }

    #[test]
    fn classifies_address_classes() {
        assert_eq!(
            classify("0.0.0.0".parse().unwrap()),
            AddressClass::Unspecified
        );
        assert_eq!(
            classify("127.0.0.1".parse().unwrap()),
            AddressClass::Loopback
        );
        assert_eq!(
            classify("169.254.169.254".parse().unwrap()),
            AddressClass::LinkLocal
        );
        assert_eq!(
            classify("224.0.0.1".parse().unwrap()),
            AddressClass::Multicast
        );
        assert_eq!(
            classify("255.255.255.255".parse().unwrap()),
            AddressClass::Broadcast
        );
        assert_eq!(classify("10.0.0.1".parse().unwrap()), AddressClass::Private);
        assert_eq!(
            classify("192.168.1.1".parse().unwrap()),
            AddressClass::Private
        );
        assert_eq!(
            classify("fd12:3456::1".parse().unwrap()),
            AddressClass::Private
        );
        assert_eq!(
            classify("2001:db8::1".parse().unwrap()),
            AddressClass::Global
        );
        assert_eq!(
            classify("203.0.113.10".parse().unwrap()),
            AddressClass::Global
        );
    }

    #[test]
    fn classifies_ipv4_mapped_ipv6_as_ipv4() {
        assert_eq!(
            classify("::ffff:127.0.0.1".parse().unwrap()),
            AddressClass::Loopback
        );
        assert_eq!(
            classify("::ffff:10.0.0.1".parse().unwrap()),
            AddressClass::Private
        );
    }

    #[test]
    fn rejects_invalid_scope_entries() {
        let config = Config {
            scope: ScopeConfig {
                targets: vec!["exa_mple.com".to_owned()],
            },
        };
        let error = Scope::from_config(&config).expect_err("invalid hostname must fail");

        assert!(matches!(error, ScopeError::InvalidTarget { index: 0, .. }));
    }

    #[test]
    fn rejects_invalid_cidr_entries() {
        let config = Config {
            scope: ScopeConfig {
                targets: vec!["192.168.1.0/33".to_owned()],
            },
        };
        let error = Scope::from_config(&config).expect_err("invalid CIDR must fail");

        assert!(matches!(error, ScopeError::InvalidCidr { index: 0, .. }));
    }

    #[test]
    fn rejects_empty_scope_entry() {
        let config = Config {
            scope: ScopeConfig {
                targets: vec![String::new()],
            },
        };
        let error = Scope::from_config(&config).expect_err("empty entry must fail");

        assert!(matches!(error, ScopeError::InvalidTarget { index: 0, .. }));
    }
}
