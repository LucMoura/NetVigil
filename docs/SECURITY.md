# NetVigil Security Model

> Status: NetVigil 0.1.0. The authorization system is **not implemented**. This
> document defines the security requirements the project must enforce and
> records the controls that exist today. Requirements are not descriptions of
> current behavior.

## Scope

This model applies to NetVigil's command-line interface, target handling and
all future network functionality. NetVigil is intended for authorized network
discovery and diagnostics only. It must not be used against public or
third-party targets without explicit authorization.

## Guiding principles

1. **Default deny.** No target is authorized implicitly.
2. **Explicit authorization.** Only targets inside an explicitly configured
   scope may be used.
3. **Private is not trusted.** Loopback, private, link-local and other
   special-purpose addresses are not automatically authorized.
4. **Validate before use.** Inputs must be validated before they are used for
   DNS resolution, connections or reports.
5. **Fail closed.** Missing, malformed or ambiguous policy must deny access
   rather than widen it.
6. **Bounded operations.** Network operations must use timeouts and bounded
   concurrency.
7. **No stealth or evasion.** These capabilities are permanently out of scope.
8. **Minimal information disclosure.** Errors and reports must not leak
   untrusted input or unnecessary operational data.

## Current implementation status

| Control | Status | Notes |
| --- | --- | --- |
| Target syntax validation | Implemented | `src/target.rs` |
| Target normalization | Implemented | Lowercase hostnames, trailing-dot removal, IPv4-mapped IPv6 to IPv4 |
| Generic, non-echoing target errors | Implemented | `src/cli.rs` |
| `unsafe` code forbidden | Implemented | `#![forbid(unsafe_code)]` |
| Target authorization and scope | **Not implemented** | No allowlist, policy engine or enforcement point |
| Special-address classification | **Not implemented** | Only IP syntax is checked |
| TOML configuration | **Not implemented** | No configuration file is read |
| DNS resolution | **Not implemented** | Hostnames remain unresolved strings |
| TCP connections and port scanning | **Not implemented** | No packets are emitted |
| Timeouts and concurrency limits | **Not implemented** | There are no network operations to bound |
| Audit logging | **Not implemented** | No logging or tracing subsystem |
| Reports | **Not implemented** | No output format exists |

### Current controls in detail

- `Target::parse` accepts only non-empty ASCII input without whitespace.
  ASCII control characters, non-ASCII characters, Unicode format/bidi controls
  and whitespace are rejected. Non-UTF-8 process arguments are rejected by the
  CLI value parser in `src/cli.rs` before `Target::parse` is called.
- Hostnames are validated syntactically according to the subset of RFC 1123
  rules implemented in `src/target.rs`; no DNS lookup occurs.
- IPv4-mapped IPv6 addresses are normalized to IPv4. This prevents a future
  policy check from treating `::ffff:127.0.0.1` differently from `127.0.0.1`.
- Invalid-target errors are generic and never include the rejected input. This
  limits terminal escape injection and log injection from hostile arguments.
- The `scan` subcommand prints a placeholder and performs no network I/O.
- `src/target.rs` performs no special-address classification. Loopback,
  link-local, multicast, unspecified, private and other special-use addresses
  pass syntax validation. This is a gap that the authorization milestone must
  close; it is not permission to use those addresses.

**Syntactic acceptance is not authorization.** The parser currently accepts
`127.0.0.1`, `10.0.0.1`, `169.254.169.254`, `0.0.0.0`, multicast addresses and
hostnames such as `localhost`. They reach the placeholder output because no
authorization layer exists. This is a documented gap, not permission to scan
them.

## Default deny

NetVigil will treat every target as unauthorized unless it matches an explicit
scope entry. The default policy for an absent, empty, unreadable or invalid
configuration is denial. This section describes a requirement for the
authorization milestone; no default-deny check exists in the current code.

Default deny applies regardless of:

- Whether the address is public, private or loopback.
- Whether the target is an IP literal or a hostname.
- Whether the hostname currently resolves to an address inside a private
  network.
- Whether a previous run authorized the same target.
- Whether the target is reachable from the local machine.

Authorization must be affirmative and checked immediately before each network
operation. A parse-time check alone is insufficient because DNS answers can
change between resolution and connection.

## Private addresses are not implicitly authorized

Private and special-purpose addresses are not trusted merely because they are
local, private or reachable from the operator's machine. The following do
**not** constitute authorization:

- Using a private range such as `10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16` or `fc00::/7`.
- Using loopback (`127.0.0.0/8`, `::1`) for local testing.
- Using a link-local address such as `169.254.169.254` or an address in
  `fe80::/10`.
- Using an unspecified address such as `0.0.0.0` or `::`.
- Using a multicast address such as `224.0.0.0/4` or `ff00::/8`.
- Reachability from the local host or a previous successful connection.

Every address, including private and special-purpose addresses, starts denied.
A private address requires an explicit scope rule exactly like a public
address. Some classes remain denied even when a rule exists: multicast and
broadcast addresses are not valid unicast scan targets, and unspecified
addresses must never be connected to. Loopback and link-local addresses may be
used only when the operator explicitly authorizes them and the authorization
model supports that use case.

This policy is a requirement for the authorization milestone. It is not
enforced today: `src/target.rs` validates syntax only, and the `scan` command
performs no network I/O.

## Explicit authorization and scope

- Only targets explicitly covered by the configured scope may be used.
- Scope must be defined by the operator, not inferred from the target syntax or
  from network reachability.
- An empty scope denies all targets.
- Scope errors, resolution failures and ambiguous matches fail closed.
- Network access must not silently expand beyond the authorized set. A hostname
  must not be used as a way to reach an address that is not itself authorized.
- Future configuration is expected to be the source of scope. The TOML
  configuration loader is planned but not implemented; no configuration file
  format or command-line option for scope exists yet.

The authorization model must distinguish between:

1. **Permission to resolve a name**, and
2. **Permission to connect to each address returned by resolution**.

Both are required for hostname targets. A hostname resolving to multiple
addresses must have every address evaluated; any address outside scope must be
denied. Connections must use the exact address that was checked.

## Authorization implementation contract (not implemented)

The authorization system is the next milestone and does not exist yet. When it
is implemented, the following contract is mandatory:

- Every target starts as denied. An allow decision must originate from an
  explicit scope rule supplied by the operator.
- Private, loopback, link-local, multicast, unspecified, broadcast and other
  special-purpose addresses are not authorized by their address class. They
  require an explicit rule and remain subject to special-address validation.
- Syntax validation and authorization remain separate. A valid `Target` is not
  an authorized target.
- No code path may resolve a hostname or open a TCP connection without a prior
  allow decision for that operation.
- A hostname allow decision does not authorize arbitrary resolved addresses.
  Every resolved address must be validated and authorized before use.
- Denials fail closed and use a generic error that does not reveal scope
  entries, other authorized targets or sensitive configuration.
- Malformed, unreadable or incomplete scope configuration is a denial. It must
  not be treated as a warning or as an empty allow-all policy.
- Tests must cover deny-by-default, explicit allow, special-address denial,
  normalization before evaluation and absence of scope leakage in errors.

## Special-purpose address validation

Special-purpose addresses require explicit classification. The current parser
does not classify them; it only checks IP syntax. The following behavior is
required before any network operation is enabled:

| Class | Examples / ranges | Required treatment |
| --- | --- | --- |
| Loopback | `127.0.0.0/8`, `::1` | Deny unless explicitly authorized; never authorize implicitly |
| Link-local | `169.254.0.0/16`, `fe80::/10` | Deny unless explicitly authorized |
| Multicast | `224.0.0.0/4`, `ff00::/8` | Deny; multicast addresses are not valid unicast scan targets |
| Unspecified | `0.0.0.0`, `::` | Deny; never connect to an unspecified address |
| Private | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` | Deny unless explicitly authorized |
| IPv4-mapped IPv6 | `::ffff:0:0/96` | Normalize to IPv4 before policy evaluation |
| Broadcast / reserved | `255.255.255.255`, other special-use ranges | Deny unless a future supported use case explicitly allows them |

The link-local range includes the cloud metadata address `169.254.169.254`.
It must never be reachable through an implicit default or a hostname that
resolves to it.

Additional requirements:

- Classification must cover every IP literal, whether supplied directly or
  returned by DNS, and must run after IPv4-mapped IPv6 normalization and before
  any connection attempt.
- A hostname that resolves to a denied address must be denied, even if the
  hostname itself is listed in scope.
- IPv6 zone identifiers such as `fe80::1%eth0` are currently unsupported and
  rejected by target parsing.
- Special-address rules must not be bypassed by alternate textual forms,
  leading zeros, hostname aliases or mixed IPv4/IPv6 representations.

## DNS and TCP status

DNS resolution and TCP connections have **not** been implemented.

- `Target::parse` never resolves a hostname.
- The `scan` subcommand never opens a socket.
- No timeouts, retry policy or concurrency limit exists because there is no
  network code.

When DNS is introduced, the following risks must be addressed:

- **DNS rebinding and answer changes.** Revalidate every resolved address and
  connect only to the validated address, not by resolving again.
- **Multiple answers.** Evaluate every A and AAAA result.
- **CNAME and alias chains.** Authorization decisions must apply to the final
  addresses actually used.
- **Resolution failure.** Fail closed; do not fall back to another target.
- **Search domains and local resolver behavior.** Do not allow resolver
  configuration to silently redirect a name outside scope.
- **Bounded resolution time.** Resolution must use a configured timeout.

When TCP is introduced, every connection must pass the authorization and
special-address checks. Connection attempts must use configurable timeouts and
bounded concurrency, as required by `AGENTS.md`.

## Network operation gate (required order)

The following order is a requirement for future implementations. It is not
implemented today.

1. Parse and validate the target syntax.
2. Canonicalize the target, including IPv4-mapped IPv6 normalization and
   hostname normalization.
3. Authorize the literal target or the hostname against the configured scope.
4. Resolve the hostname, if applicable, within a bounded timeout.
5. Authorize and classify every resolved address.
6. Reject loopback, link-local, multicast, unspecified and other denied special
   addresses unless explicitly permitted.
7. Connect only to the validated address, with timeouts and bounded
   concurrency.
8. Fail closed on any policy, resolution or validation error.
9. Record only the information needed for the authorized operation.

## Input validation

Current input handling:

- Targets must be valid UTF-8 and non-whitespace ASCII. ASCII control
  characters and non-ASCII characters are rejected.
- The maximum hostname length is 253 bytes and the maximum label length is
  63 bytes.
- Empty labels, leading/trailing hyphens and invalid characters are rejected.
- A final numeric label is rejected.
- IPv6 zone identifiers and internationalized hostnames are not supported.
- Parser errors do not echo the rejected input.

Future user inputs such as configuration paths, scope entries, port ranges and
output paths must receive equivalent validation. Port numbers must be checked
for range and emptiness. Configuration values must be validated before any
network operation. Invalid input must produce a generic error without leaking
control sequences or sensitive file contents.

## Stealth, evasion and exploitation

NetVigil will not implement stealth or evasion features. This is a permanent
scope decision, not a deferred roadmap item.

Prohibited capabilities include:

- Source address spoofing, decoy scanning or packet fragmentation designed to
  evade detection.
- Timing manipulation intended to bypass intrusion detection or logging.
- Evasion of firewalls, IDS/IPS, network monitoring or access controls.
- Exploitation, credential attacks, persistence or lateral movement.
- Unauthorized scanning of public or third-party targets.

Future scanning is expected to use ordinary, observable TCP connections with
explicit authorization, timeouts and bounded concurrency.

## Error handling and information disclosure

- Invalid-target errors use fixed messages and exclude the rejected input.
- The program does not currently store credentials, configuration or scan
  results.
- Future reports must contain only data collected from authorized targets and
  must not include credentials or unrelated local system information.
- Authorization failures must be reported without disclosing the full scope or
  other targets.
- Logs, if added, must not include raw hostile input or secrets.

## Operational guidance

Before using NetVigil on a network:

1. Obtain explicit authorization from the network owner.
2. Define the narrowest possible scope.
3. Verify that the configuration does not grant implicit local, private or
   special-address access.
4. Use controlled test fixtures or localhost only for tests.
5. Stop immediately if the scope needs to expand; obtain new authorization
   first.

## Contributor checklist for security-sensitive changes

- Does the change add a network operation? If so, is it behind the
  authorization gate?
- Are special addresses classified after normalization?
- Are hostnames revalidated after DNS resolution?
- Are timeouts and concurrency bounds present?
- Do errors avoid echoing untrusted input?
- Are unit tests deterministic and free of external network access?
- Is the change free of stealth, evasion, exploitation or persistence
  behavior?
- Have `docs/SECURITY.md`, `docs/ARCHITECTURE.md` and `docs/ROADMAP.md` been
  updated?

## Known gaps

- Authorization and scope enforcement do not exist.
- TOML configuration does not exist.
- DNS resolution and TCP connections do not exist, so the gate above cannot yet
  be exercised.
- Timeouts and concurrency limits are not implemented.
- Audit logging is not implemented.
- The `scan` help text describes intended functionality that is not available.
