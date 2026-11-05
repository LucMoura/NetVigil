# NetVigil Security Model

> Status: NetVigil 0.1.0. Authorization, scope enforcement and configuration
> loading are implemented. Network functionality is not. This document records
> both the controls that exist today and the requirements that future network
> stages must satisfy; requirements are not descriptions of current behavior.

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
| Target authorization and scope | Implemented | Default deny in `src/scope.rs`; enforced before the placeholder |
| Special-address classification | Implemented | Unspecified, loopback, link-local, multicast, broadcast and private classes |
| TOML configuration | Implemented | Explicit `--config PATH`; trust, size and rule checks in `src/config.rs` |
| Configuration trust checks | Implemented | Handle-based regular-file checks, Unix `O_NOFOLLOW`/`O_NONBLOCK`, Unix write permissions, Linux ownership fail-closed |
| Configuration resource limits | Implemented | 1 MiB file limit, 4096 rule limit, bounded read |
| Sanitized configuration errors | Implemented | Escaped paths, no raw TOML lines, category and line/column preserved |
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
- IPv4-mapped IPv6 addresses are normalized to IPv4 before authorization. This
  prevents `::ffff:127.0.0.1` from being treated differently from `127.0.0.1`.
- Invalid-target errors are generic and never include the rejected input. This
  limits terminal escape injection and log injection from hostile arguments.
- `src/config.rs` loads an explicitly selected file with `serde` and rejects
  unknown fields, malformed TOML, missing files and wrong value types. There is
  no implicit `netvigil.toml` default and no default target.
- The configuration path must refer to a regular file. On Unix, the final path
  component is opened with `O_NOFOLLOW` and `O_NONBLOCK`; trust decisions are
  made from the opened handle rather than from a pre-open path lookup. Symbolic
  links, directories, FIFOs and other non-regular files are rejected. On Unix,
  files writable by group or other users are rejected. On Linux, the file must
  be owned by the current effective user; if that user ID cannot be determined,
  loading fails closed with a specific error. Symbolic links in parent
  directories are followed because `openat2` is not used.
- Configuration files are limited to 1 MiB and 4096 scope rules. The loader
  reads with an explicit byte limit, so oversized files are rejected without an
  unbounded allocation.
- Configuration paths and TOML diagnostics are sanitized: control characters,
  ANSI/OSC sequences and bidi controls are escaped, raw TOML source lines are
  not reproduced, and error category plus line/column are retained where
  available.
- `src/scope.rs` implements default deny. Entries may be individual IPs, IPv4
  or IPv6 CIDR networks, or normalized hostnames.
- Unspecified, multicast and broadcast addresses are denied even when a scope
  entry matches them. Loopback, link-local and private addresses require an
  explicit entry.
- Configuration, scope and authorization failures print an error and exit with
  status `1`. No scan output is produced.
- After authorization, the `scan` subcommand prints a placeholder and performs
  no network I/O.

**Syntactic acceptance is not authorization.** The parser accepts
`127.0.0.1`, `10.0.0.1`, `169.254.169.254`, `0.0.0.0`, multicast addresses and
hostnames such as `localhost`. They reach the placeholder only when the
configured scope authorizes them (and, for unspecified, multicast and broadcast
addresses, never).

## Default deny

NetVigil treats every target as unauthorized unless it matches an explicit
scope entry. The default policy for an absent, empty, unreadable or invalid
configuration is denial. This behavior is implemented in `src/scope.rs` and is
enforced by `main.rs` before the scan placeholder.

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

This policy is enforced by `src/scope.rs`: private, loopback and link-local
addresses match only when the operator declares them. Unspecified, multicast
and broadcast addresses are rejected even when declared. The `scan` command
still performs no network I/O.

## Explicit authorization and scope

- Only targets explicitly covered by the configured scope may be used.
- Scope must be defined by the operator, not inferred from the target syntax or
  from network reachability.
- An empty scope denies all targets.
- Scope errors, resolution failures and ambiguous matches fail closed.
- Network access must not silently expand beyond the authorized set. A hostname
  must not be used as a way to reach an address that is not itself authorized.
- Scope is supplied by a TOML file selected explicitly with the global
  `--config` option. There is no implicit path and no built-in target. Omitting
  `--config` is an error, not an empty or permissive policy.

The authorization model must distinguish between:

1. **Permission to resolve a name**, and
2. **Permission to connect to each address returned by resolution**.

Both are required for hostname targets. A hostname resolving to multiple
addresses must have every address evaluated; any address outside scope must be
denied. Connections must use the exact address that was checked.

## Authorization implementation contract

The current implementation satisfies the following contract:

- Every target starts as denied. An allow decision originates from an explicit
  scope rule supplied by the operator.
- Private, loopback and link-local addresses are not authorized by their
  address class; they require an explicit rule. Unspecified, multicast and
  broadcast addresses are always denied.
- Syntax validation and authorization are separate. A valid `Target` is not an
  authorized target.
- Denials fail closed and use normalized target text without revealing scope
  entries.
- Malformed, unreadable or incomplete scope configuration is a denial; it is
  not treated as a warning or as an empty allow-all policy.
- Tests cover deny-by-default, explicit allow, special-address denial,
  normalization before evaluation and absence of scope leakage in errors.

Future network stages must also satisfy:

- No code path may resolve a hostname or open a TCP connection without a prior
  allow decision for that operation.
- A hostname allow decision does not authorize arbitrary resolved addresses.
  Every resolved address must be classified and authorized before use.

## Special-purpose address validation

Special-purpose addresses are classified by `src/scope.rs` after
IPv4-mapped IPv6 normalization. The implemented treatment is:

| Class | Examples / ranges | Implemented treatment |
| --- | --- | --- |
| Loopback | `127.0.0.0/8`, `::1` | Denied unless an explicit scope entry matches |
| Link-local | `169.254.0.0/16`, `fe80::/10` | Denied unless an explicit scope entry matches |
| Multicast | `224.0.0.0/4`, `ff00::/8` | Always denied |
| Unspecified | `0.0.0.0`, `::` | Always denied |
| Private | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` | Denied unless an explicit scope entry matches |
| IPv4-mapped IPv6 | `::ffff:0:0/96` | Normalized to IPv4 before classification |
| Broadcast | `255.255.255.255` | Always denied |

Other special-use ranges are not special-cased, but they are still subject to
default deny and require an explicit scope entry.

The link-local range includes the cloud metadata address `169.254.169.254`.
It is never reachable through an implicit default. Once DNS is implemented, a
hostname that resolves to it must be denied even if the hostname is in scope.

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

Steps 1–3 are implemented for the current placeholder. Steps 4–9 are
requirements for future network implementations.

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
- Configuration files must be regular, non-symlink files selected explicitly
  with `--config`. On Unix, the final component is opened with `O_NOFOLLOW` and
  `O_NONBLOCK`, and checks run on the opened handle. Files writable by group or
  other users are rejected on Unix; Linux additionally requires ownership by the
  current effective user and fails closed if the EUID cannot be determined.
- Configuration files are read as UTF-8 and limited to 1 MiB. Unknown fields,
  wrong value types, malformed TOML and more than 4096 scope rules are rejected.
- Every scope entry is validated as an IP address, CIDR network or hostname
  before authorization. Invalid entries deny the scan.
- Configuration paths and TOML diagnostics are sanitized and bounded. Control
  characters, ANSI/OSC sequences and bidi controls are escaped; raw TOML source
  lines are not reproduced. Scope entries are escaped with Rust debug formatting
  so control characters cannot inject terminal sequences.

Future user inputs such as port ranges and output paths must receive equivalent
validation. Port numbers must be checked for range and emptiness. Invalid input
must produce an error without leaking control sequences or sensitive file
contents.

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
- Configuration errors use sanitized paths and sanitized TOML diagnostics. Raw
  source lines and control sequences are not emitted; line and column are
  retained when available.
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
3. Select the configuration explicitly with `--config PATH` and review it so
   that it lists only the intended targets. Private, loopback and link-local
   targets require explicit entries; unspecified, multicast and broadcast
   targets are always denied.
4. Keep the file owned by the invoking user and not writable by group or other
   users on Unix. Do not use symbolic links.
5. Use controlled test fixtures or localhost only for tests, and authorize them
   explicitly.
6. Stop immediately if the scope needs to expand; obtain new authorization
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

- DNS resolution and TCP connections do not exist, so the gate above cannot yet
  be exercised beyond the initial authorization decision.
- Hostnames are authorized by normalized name only until DNS is implemented.
  Resolved addresses will require separate authorization.
- Timeouts and concurrency limits are not implemented.
- Audit logging is not implemented.
- The `scan` help text describes intended functionality that is not available.
- POSIX ACLs are not inspected on any platform; only POSIX mode bits are
  checked on Unix.
- On non-Unix platforms, POSIX ownership and mode checks do not apply.
  Regular-file checks are applied to the opened handle, but symbolic-link
  rejection uses a best-effort pre-open lookup and is not race-free.
- On Unix platforms other than Linux, effective-user ownership cannot be
  determined without an additional dependency or unsafe code. POSIX
  group/other write checks still apply.
- `O_NOFOLLOW` rejects only a symbolic link in the final path component.
  Symbolic links in parent directories are followed because `openat2` is not
  used.
- On Unix, the opened descriptor retains `O_NONBLOCK`. This has no effect on
  regular-file reads but prevents a substituted FIFO from blocking before the
  handle can be rejected as non-regular.
