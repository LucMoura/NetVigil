# NetVigil Roadmap

> Status: NetVigil 0.1.0. Only the items marked **Implemented** exist in the
> repository. The authorization and scope system is the next milestone.

This roadmap separates what exists today from what is planned and from work
that is intentionally deferred. Status labels are strict:

- **Implemented**: code exists in the repository and runs today.
- **Planned**: committed next steps, not implemented yet.
- **Future**: possible later work, not scheduled and not a commitment.
- **Out of scope**: permanently excluded from the project.

Planned items must not be documented or described as existing features until
they are implemented and tested. None of the planned items exist today. In
particular, DNS resolution and TCP connections are not implemented.

## Planned milestone order

The next implementation sequence is:

| Order | Milestone | Status |
| --- | --- | --- |
| a | Authorization and scope system | Planned |
| b | TOML configuration loading | Planned |
| c | Host discovery | Planned |
| d | Asynchronous TCP scanner | Planned |
| e | Service identification | Planned |
| f | JSON reports | Planned |

Authorization comes before configuration so the policy can be implemented and
tested independently of the TOML schema. No later milestone may bypass the
authorization gate.

## Status Overview

| Area | Status |
| --- | --- |
| Binary crate and module layout | Implemented |
| Clap CLI with `scan` subcommand | Implemented |
| Required `TARGET` argument | Implemented |
| Target syntax validation and normalization | Implemented |
| Safe, non-echoing target errors | Implemented |
| Unit tests for CLI and target parsing | Implemented |
| Authorization and scope enforcement | Planned |
| TOML configuration loading | Planned |
| DNS resolution and host discovery | Planned |
| Asynchronous TCP scanner | Planned |
| Service identification | Planned |
| JSON reports | Planned |
| Stealth, evasion, exploitation, persistence | Out of scope |

## Implemented

### CLI foundation

- Single binary crate `netvigil` version `0.1.0`, Rust edition 2024.
- `#![forbid(unsafe_code)]`.
- `netvigil --help`, `netvigil --version`, and `netvigil scan --help`.
- One application subcommand: `netvigil scan <TARGET>`. Clap also provides the
  generated `help` subcommand.
- `TARGET` is required and accepts a hostname or IP literal.

### Target validation

- Opaque `Target` type with private representation.
- Printable-ASCII-only policy; control and non-ASCII characters are rejected.
- Hostname limits: 253 bytes overall, 63 bytes per label.
- Rejection of empty labels, leading/trailing hyphens, and numeric top-level
  labels.
- Lowercase normalization and removal of one trailing dot.
- IPv4 and IPv6 parsing with IPv4-mapped IPv6 normalization.
- No DNS resolution or network access during validation.

### Safe error output

- All `TargetError` variants map to fixed user-facing reasons.
- Rejected input is not echoed, preventing terminal escape and log injection.
- Invalid targets produce a Clap validation error and exit status 2.

### Current scan behavior

- `netvigil scan <valid-target>` prints
  `Scanning is not implemented yet (target: <normalized-target>).`
- No network operation is performed.

## Planned

The order below is intentional. Authorization and configuration come first so
that no later network feature can operate without explicit scope. No DNS,
discovery, or TCP functionality should be merged before the authorization
foundation is in place.

### a) Authorization and scope system

**Goal:** enforce default deny for every target before any network operation.

**Scope:**

- Define an explicit authorization model for IP addresses and hostnames.
- Deny targets that are not covered by an explicit allow rule.
- Treat private, loopback, link-local, multicast, unspecified, and other
  special-use addresses as untrusted by default.
- Normalize targets before evaluating authorization, including IPv4-mapped IPv6.
- Fail closed on missing, invalid, or ambiguous authorization data.
- Return clear errors for denied targets without leaking sensitive input.
- Keep authorization decisions separate from syntax validation.
- Remain testable with an in-memory policy; this milestone must not depend on
  the TOML loader.

**Not included:** DNS queries, sockets, probing, or scan output.

**Validation:** unit tests for allowed targets, denied targets, special-use
addresses, normalization, and ambiguous input. No external network access.

**Definition of done:**

- Authorization lives in its own module, separate from target syntax
  validation and from configuration loading.
- Every future DNS or TCP entry point is gated by an authorization decision;
  no alternative code path bypasses the gate.
- Special-address classification runs after IPv4-mapped IPv6 normalization.
- Missing, empty, malformed or unreadable scope data denies all targets.
- `docs/ARCHITECTURE.md` and `docs/SECURITY.md` are updated, and this roadmap
  marks the milestone as implemented only after the tests pass.

### b) TOML configuration loading

**Goal:** load operator-provided configuration, including authorization scope,
from a TOML file.

**Scope:**

- Define and document the configuration schema when it is implemented.
- Parse TOML with error handling for missing files, malformed TOML, unknown
  fields, and invalid values.
- Validate authorization rules before use and fail closed on invalid data.
- Keep configuration loading independent from network operations.
- Add deterministic tests using local fixture files.

**Dependencies:** a TOML parser and Serde support will be required. Neither is a
current dependency; the specific crates must be justified before being added,
according to `AGENTS.md`.

**Not included:** network activity or implicit authorization defaults.

**Definition of done:**

- A missing, unreadable, malformed or partially valid file denies all targets.
- The schema is documented and tested with local fixture files.
- Configuration loading performs no network access and does not grant implicit
  scope.

### c) Host discovery

**Goal:** determine whether explicitly authorized targets are reachable.

**Scope:**

- Check authorization before any resolution or probe.
- Define how hostnames are authorized relative to resolved addresses before DNS
  is enabled.
- Apply configurable timeouts and bounded concurrency.
- Handle resolution failures, unreachable hosts, and timeouts explicitly.
- Keep discovery separate from service identification and reporting.

**Dependencies:** networking support and an asynchronous runtime are expected.
Tokio is listed in `AGENTS.md` as project direction but is not a current
dependency.

**Definition of done:**

- Discovery never runs without an authorization decision.
- Timeouts and concurrency bounds are configurable and enforced.
- Resolution failures, unreachable hosts and timeouts are reported explicitly.
- Discovery remains separate from service identification and reporting.

**Security constraint:** no stealth, evasion, or traffic-hiding behavior.

### d) Asynchronous TCP scanner

**Goal:** detect open TCP ports on authorized targets.

**Scope:**

- Perform TCP connection attempts only against authorized targets.
- Use configurable connection timeouts.
- Bound concurrency to avoid resource exhaustion.
- Distinguish open, closed, filtered, and timed-out results where the platform
  permits.
- Handle partial failures without aborting the whole scan.
- Cover invalid ports, invalid targets, and timeout behavior with tests.

**Dependencies:** asynchronous networking support. Tokio is not yet a
dependency.

**Definition of done:**

- Only authorized addresses are connected to.
- Timeouts and bounded concurrency are enforced.
- Invalid ports, timeouts and partial failures are covered by tests without
  external network access.

**Security constraint:** no raw sockets, SYN stealth scanning, evasion, or
unbounded concurrency.

### e) Service identification

**Goal:** identify services associated with open TCP ports.

**Scope:**

- Collect and interpret service responses from ports already found open.
- Keep identification rules data-driven and documented.
- Respect timeouts and size limits for responses.
- Avoid exploitation or intrusive payloads.
- Record uncertain or unknown services explicitly.

**Dependencies:** the TCP scanner from the previous milestone.

**Definition of done:**

- Identification uses bounded timeouts and response-size limits.
- Unknown or uncertain services are recorded explicitly.
- No exploitation or intrusive payloads are used.

### f) JSON reports

**Goal:** emit structured, machine-readable scan results.

**Scope:**

- Define a stable JSON schema for targets, ports, services, and errors.
- Serialize results with explicit handling of optional and unknown values.
- Keep report generation separate from scanning.
- Add tests for schema stability and serialization of representative results.

**Dependencies:** Serde and a JSON serializer will be required. They are not
current dependencies and must be justified before being added.

**Definition of done:**

- The JSON schema is documented and covered by stability tests.
- Optional and unknown values are represented explicitly.
- Report generation is independent of scanning and does not expose
  unauthorized data.

## Future

The following items are not scheduled. They may change or be dropped.

- Internationalized domain names (IDN) and punycode conversion.
- IPv6 zone identifier support.
- Additional report formats beyond JSON.
- Configuration profiles for different authorized scopes.
- Richer audit logging for authorization decisions.
- Property-based or fuzz testing of target and configuration parsing.
- Continuous integration for formatting, linting, and tests.
- Refined IPv6 special-address classification.

## Out of Scope

NetVigil will not implement:

- Exploitation.
- Stealth or evasion.
- Persistence.
- Scanning without explicit authorization.

## Testing Expectations

Every milestone should follow the project checks:

```sh
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo check
```

Network-related tests must prefer localhost and controlled local fixtures, must
not depend on external network access, and must cover invalid targets, invalid
ports, and timeout behavior where applicable.
