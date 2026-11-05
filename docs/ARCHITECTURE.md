# NetVigil Architecture

> Current state: NetVigil 0.1.0. This document describes only the code that
> exists in the repository. Features that are not implemented are explicitly
> marked as planned or absent.

## Purpose and current scope

NetVigil is a network intelligence and reconnaissance CLI written in Rust.
The current implementation provides:

- A Clap-based command-line interface with a single application subcommand,
  `scan`. Clap also provides the generated `help` subcommand.
- Validation and normalization of one required target argument.
- Generic, non-echoing error messages for invalid targets.
- Loading of an explicitly selected TOML configuration and validation of its
  `[scope]` table, with regular-file, ownership, permission, size and rule-count
  checks.
- Default-deny authorization against individual IPs, CIDR networks and
  hostnames, including special-address classification.

The `scan` subcommand does not perform any network operation. It prints a
placeholder message only after authorization succeeds. DNS resolution, host
discovery, TCP scanning, service identification and report generation are not
implemented.

## Repository layout

```text
NetVigil/
├── Cargo.toml
├── Cargo.lock
├── AGENTS.md
├── README.md
├── src/
│   ├── main.rs
│   ├── cli.rs
│   ├── config.rs
│   ├── scope.rs
│   └── target.rs
├── tests/
│   └── cli.rs
└── docs/
    ├── ARCHITECTURE.md
    ├── SECURITY.md
    └── ROADMAP.md
```

`README.md` is the short entry point for building, running and finding the
detailed documents. Tooling directories such as `.opencode/` and the generated
`target/` directory are omitted from the layout. The package produces only a
binary target named `netvigil`. There is no library crate, `build.rs` or feature
flag. `tests/cli.rs` is the only integration test file. The `docs/` directory is
documentation only; no build step consumes it.

## Module responsibilities

### `src/main.rs`

The crate root and process entry point.

- Declares `#![forbid(unsafe_code)]`.
- Declares the `cli`, `config`, `scope` and `target` modules.
- Parses the process arguments with `clap::Parser`.
- Loads the configuration, builds the scope and authorizes the target before
  dispatching the scan placeholder.

The only dispatch arm currently implemented is:

```rust
Commands::Scan(args) => {
    let config = Config::load(config_path)?;
    let scope = Scope::from_config(&config)?;
    scope.authorize(&args.target)?;

    println!("Scanning is not implemented yet (target: {}).", args.target);
}
```

`config_path` comes from `cli.config`, which is an `Option<PathBuf>`. When it is
`None`, `run` returns `AppError::MissingConfig` and the process exits with
status `1`; no file is loaded from the current working directory.

`main` returns `ExitCode`. Configuration, scope and authorization errors are
printed to standard error and exit with status `1`; Clap still owns usage and
target-syntax errors. The program installs no logging/tracing subscriber and
opens no network connections.

### `src/cli.rs`

Defines the command-line interface and connects Clap parsing to target
validation.

- `Cli` is the top-level parser. It sets the command name `netvigil`, reads the
  package version and uses the about text `Network intelligence and
  reconnaissance CLI`.
- `Cli::config` is a global `--config PATH` option. It has no default; the
  operator must select the configuration file explicitly.
- `Commands` is the subcommand enum. It currently contains only
  `Scan(ScanArgs)`. Clap's generated `help` subcommand is not a variant of this
  enum.
- `ScanArgs` contains one required positional argument, `TARGET`.
- `TargetParser` implements `clap::builder::TypedValueParser` so the target is
  validated during argument parsing. Non-UTF-8 arguments are rejected.
- `invalid_target_error` builds a Clap `ValueValidation` error without
  including the rejected input.
- `safe_error_reason` maps every `TargetError` variant to a fixed message. The
  match is exhaustive so adding a new error variant requires an explicit
  decision about what is safe to display.

The module exposes no options for ports, timeouts, concurrency or output
formats. Those options do not exist and must not be assumed.

### `src/target.rs`

Defines the validated target type and its parsing rules.

- `Target` is the public, validated representation of a scan target.
- `TargetKind` is private and has two variants: `Ip(IpAddr)` and
  `Hostname(String)`. Keeping the representation private preserves the
  invariant that every `Target` value has passed validation.
- `Target::parse` performs validation and normalization. It performs no DNS
  resolution and no network access.
- `Target::as_ip` and `Target::as_hostname` expose the normalized
  representation. They are used by `src/scope.rs` and tests and are annotated
  with `#[allow(dead_code)]` for the future scanner.
- `TargetError` enumerates rejection reasons.
- `MAX_HOSTNAME_LENGTH` is 253 bytes and `MAX_LABEL_LENGTH` is 63 bytes.

`Target` implements `Display` and `FromStr`. `Display` prints the normalized
value, so a hostname is lowercase and without a trailing dot, and an
IPv4-mapped IPv6 address is printed in IPv4 form.

### `src/config.rs`

Loads, validates and deserializes the explicitly selected configuration file.

- `Config` has one required table, `scope`; `ScopeConfig::targets` is a list of
  strings and defaults to an empty list.
- Both structures use `#[serde(deny_unknown_fields)]`, so misspelled or
  unsupported fields are rejected instead of silently ignored.
- `Config::load` applies a trust model to the opened handle before parsing:
  - On Unix, the final component is opened with `O_NOFOLLOW` and `O_NONBLOCK`.
    The first flag rejects a final-component symbolic link; the second prevents
    a substituted FIFO from blocking the loader.
  - The file is opened once, and regular-file, permission, ownership and size
    checks use `File::metadata` (`fstat`) on that handle. No pre-open `lstat`
    identity comparison is used as the trust boundary.
  - On Unix, POSIX mode bits must not grant write permission to group or other
    users. On Linux, the file owner must match the current effective user ID;
    if the EUID cannot be read or parsed, loading fails closed.
  - The file size must not exceed `MAX_CONFIG_BYTES` (1 MiB). The read uses an
    explicit `take(MAX + 1)` bound, so a growing file cannot cause an unbounded
    allocation.
  - The parsed `[scope] targets` list must not exceed `MAX_SCOPE_RULES` (4096).
- `ConfigError` distinguishes read failures, non-regular paths, symbolic links,
  insecure permissions, untrusted ownership, unavailable EUID, non-UTF-8
  content, oversized files, excessive rule counts and TOML/schema errors.
- Paths in errors are sanitized and bounded. TOML errors use `message()` and
  `span()` only: the raw source line is never reproduced, control sequences are
  escaped and line/column are preserved when available.
- There are no default targets. A missing file is an error and an empty target
  list authorizes nothing.

### `src/scope.rs`

Builds and evaluates the authorization scope.

- `Scope::from_config` turns each configured entry into an individual IP, a
  CIDR network or a normalized hostname. Invalid entries produce `ScopeError`
  and prevent the scan.
- Scope entries without `/` are validated with `Target::parse`, so they follow
  the same normalization and character rules as scan targets.
- `Scope::authorize` implements default deny: a target must match a rule.
- `classify` identifies unspecified, loopback, link-local, multicast,
  broadcast, private and global addresses. Unspecified, multicast and broadcast
  addresses are always denied, even when a rule matches. Loopback, link-local
  and private addresses require an explicit rule.
- Hostnames are matched exactly against normalized hostname entries. No DNS
  resolution occurs.

## Target validation and normalization

`Target::parse` applies the following checks in order:

1. **Empty input.** Input that is empty or whitespace-only is rejected with
   `TargetError::Empty`.
2. **Whitespace.** Any Unicode whitespace, including Unicode line separators,
   is rejected with `TargetError::Whitespace`.
3. **Disallowed characters.** ASCII control characters and non-ASCII
   characters that are not whitespace are rejected with
   `TargetError::InvalidCharacter`. This includes Unicode format/bidi controls.
   Hostnames are accepted only in ASCII form; internationalized names are not
   converted or supported.
4. **Trailing dot.** One trailing dot is removed before hostname validation.
   `example.com.` is treated as the fully qualified form of `example.com`.
5. **Empty name.** If removing the trailing dot leaves an empty name, the input
   is rejected with `TargetError::EmptyLabel`.
6. **Length.** Names longer than 253 bytes are rejected with
   `TargetError::TooLong`. Because only ASCII is accepted, bytes equal
   characters at this point.
7. **IP literal.** The original input is parsed as an `IpAddr`. A valid IPv4 or
   IPv6 literal becomes an IP target and is not processed as a hostname.
8. **IPv4-mapped IPv6 normalization.** IPv4-mapped IPv6 addresses such as
   `::ffff:127.0.0.1` are normalized to their IPv4 representation. This
   normalization happens before any future policy check.
9. **Hostname labels.** The remaining input is split on dots. Every label must
   be non-empty, at most 63 bytes, must not start or end with a hyphen, and may
   contain only ASCII letters, digits and hyphens.
10. **Numeric top-level label.** A final label composed only of digits is
    rejected with `TargetError::NumericTopLevelLabel`. This prevents values that
    look like malformed IP addresses, such as `999.999.999.999`, from being
    treated as hostnames.
11. **Case normalization.** Accepted hostnames are converted to ASCII
    lowercase.

Examples of current behavior:

| Input | Result |
| --- | --- |
| `192.0.2.10` | Accepted as IPv4 |
| `2001:db8::1` | Accepted as IPv6 |
| `::ffff:127.0.0.1` | Accepted and normalized to `127.0.0.1` |
| `Example.COM.` | Accepted and normalized to `example.com` |
| `localhost` | Accepted as a hostname |
| `exa_mple.com` | Rejected: invalid character `_` |
| `999.999.999.999` | Rejected: numeric top-level label |
| `fe80::1%eth0` | Rejected: IPv6 zone identifiers are not supported |
| `exämple.com` | Rejected: non-ASCII character |

Syntactic acceptance is not authorization. The parser still accepts loopback,
private, link-local, multicast and unspecified addresses; the authorization
step decides whether they may be used. See `docs/SECURITY.md`.

## CLI execution flow

```text
process arguments
        |
        v
clap::Parser (Cli::parse)
        |
        v
Commands::Scan(ScanArgs)
        |
        v
TargetParser -> Target::parse
        |                |
        | invalid        | valid
        v                v
clap ValueValidation    Config::load -> Scope::from_config
error (generic text)             |
                                 v
                         Scope::authorize
                          |            |
                       deny           allow
                          |            |
                          v            v
                    error, exit 1   prints placeholder
```

1. `main` calls `Cli::parse`.
2. Clap parses the global `--config` option, the subcommand and the required
   `TARGET` argument. Missing arguments, unknown subcommands and invalid targets
   are handled by Clap.
3. `TargetParser` validates the target through `Target::parse`.
4. Invalid targets produce a `ValueValidation` error. The message contains a
   fixed reason and never echoes the rejected input. The observed exit status
   for an invalid target is `2`.
5. Valid targets reach the `Commands::Scan` arm. If `--config` was omitted, the
   program prints an error and exits with status `1`. Otherwise it loads the
   configuration, builds the scope and authorizes the target.
6. A missing `--config`, an unreadable, untrusted or invalid configuration, an
   invalid scope entry or an unauthorized target prints an error to standard
   error and exits with status `1`.
7. Authorized targets print the normalized target in a placeholder line. No
   network I/O occurs.

Verified examples:

```console
$ cargo run --quiet -- --help
Network intelligence and reconnaissance CLI

Usage: netvigil [OPTIONS] <COMMAND>

Commands:
  scan  Scan a target for open ports and services
  help  Print this message or the help of the given subcommand(s)

Options:
      --config <PATH>  Path to the configuration file
  -h, --help           Print help
  -V, --version        Print version
```

```console
$ cargo run --quiet -- scan --help
Scan a target for open ports and services

Usage: netvigil scan [OPTIONS] <TARGET>

Arguments:
  <TARGET>  Target to scan, such as a hostname or IP address

Options:
      --config <PATH>  Path to the configuration file
  -h, --help           Print help
```

```console
$ cargo run --quiet -- --version
netvigil 0.1.0
```

The following examples assume `netvigil.toml` authorizes `127.0.0.1` and
`example.com`:

```console
$ cargo run --quiet -- --config netvigil.toml scan 127.0.0.1
Scanning is not implemented yet (target: 127.0.0.1).
```

```console
$ cargo run --quiet -- --config netvigil.toml scan Example.COM.
Scanning is not implemented yet (target: example.com).
```

```console
$ cargo run --quiet -- --config netvigil.toml scan 198.51.100.7
error: target 198.51.100.7 is not authorized by the configured scope
```

```console
$ cargo run --quiet -- scan exa_mple.com
error: invalid target: target contains invalid characters

Usage: netvigil scan [OPTIONS] <TARGET>

For more information, try '--help'.
```

Target syntax is validated by Clap before the configuration is loaded, so the
last example exits with status `2` even if no configuration file exists.

The help text for `scan` describes its intended purpose ("open ports and
services"). That behavior is not implemented yet.

## Technologies and dependencies

The actual dependency set is intentionally small:

| Dependency | Version | Purpose |
| --- | --- | --- |
| Rust | stable, edition 2024 | Implementation language; no MSRV is declared |
| `clap` (feature `derive`) | 4.6.7 | CLI parsing, help and version output |
| `ipnet` | 2.12.2 | CIDR parsing and containment checks |
| `serde` (feature `derive`) | 1.0.229 | Configuration deserialization |
| `thiserror` | 2.0.21 | Error implementations |
| `toml` (features `parse`, `serde`, `std`) | 1.2.0 | TOML configuration parsing |

`Cargo.lock` is committed. The crate has no development dependencies; tests use
the standard library, Clap and the binary under test.

`AGENTS.md` lists Tokio, Serde, Anyhow and Thiserror as the intended technology
stack. Tokio and Anyhow are **not** linked or used. Serde and Thiserror are used
for configuration parsing and error types. Future additions must be justified
under the dependency policy in `AGENTS.md`.

The crate root enables `#![forbid(unsafe_code)]`.

## Build and execution

The project uses the standard Cargo workflow:

```console
cargo build
cargo run -- --help
cargo run -- scan --help
cargo run -- --config netvigil.toml scan 127.0.0.1
```

The debug binary is produced at `target/debug/netvigil`. There is currently no
installation, packaging or release configuration.

## Error handling

- **CLI syntax and usage errors:** handled by Clap. This includes missing
  subcommands, missing `TARGET`, unknown flags, `--help` and `--version`.
  Usage and validation errors exit with status `2`; `--help` and `--version`
  exit with status `0`.
- **Invalid targets:** `TargetError` is converted to a Clap `ValueValidation`
  error with a static, generic reason.
- **Terminal and log injection:** rejected input is never included in the
  error. Control characters, Unicode format characters and bidi controls are
  rejected during validation and are also excluded from parser error text.
- **Configuration and scope errors:** a missing `--config`, an unreadable,
  untrusted or invalid configuration, and invalid scope entries are reported
  through `AppError` and exit with status `1`.
- **Configuration trust and limits:** final-component symbolic links,
  non-regular paths, insecure Unix permissions, untrusted ownership, files
  larger than 1 MiB and more than 4096 rules are rejected before or during
  loading. Unix trust checks run on the opened handle; Linux fails closed when
  the effective user ID cannot be determined.
- **Configuration diagnostics:** paths are sanitized and bounded; TOML errors
  use only the error message and span, so raw source lines, ANSI/OSC sequences
  and control characters are not emitted. Line and column are retained when
  available.
- **Authorization denials:** out-of-scope targets and always-denied address
  classes exit with status `1` and produce no scan output.
- **Unimplemented scan:** after authorization, prints a normal message to
  standard output. It does not report an error.

`AppError` is a private `thiserror` enum that wraps `ConfigError`, `ScopeError`
and `AuthorizationError`. The program does not use `anyhow`.

## Testing

Unit tests are inline in `src/cli.rs`, `src/config.rs`, `src/scope.rs` and
`src/target.rs`. `tests/cli.rs` contains integration tests that execute the
compiled binary against local configuration fixtures. They are deterministic
and do not require external network access.

At the time of this document, `cargo test` reports 114 passing tests on Linux
(101 unit tests and 13 integration tests). The tests cover:

- CLI command definition, help, version and explicit `--config` behavior.
- Required `TARGET` handling and parsing of valid IP and hostname targets.
- Normalization of case, trailing dots and IPv4-mapped IPv6 addresses.
- Rejection of empty, whitespace-containing, oversized, malformed and
  non-ASCII targets.
- Non-echoing error messages for control, format, bidi and line separator
  characters.
- Configuration parsing, missing files, invalid TOML and unknown fields.
- Regular-file, directory, symbolic-link, FIFO, permission, ownership and size
  checks, including a non-blocking FIFO open and EUID-unavailable failure.
- Non-UTF-8 content, excessive rule counts and sanitized TOML/path errors.
- Individual IPs, IPv4/IPv6 CIDR membership and hostname authorization.
- Default deny, empty scope and special-address policy.
- CLI denial of unauthorized targets, missing `--config` and fail-closed
  configuration errors.

Per `AGENTS.md`, the expected validation commands are:

```console
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo check
```

## Current limitations and absent functionality

The following capabilities are **not implemented**:

- DNS resolution. Hostnames remain unresolved strings.
- Host discovery.
- TCP connections or port scanning.
- Service identification.
- JSON or any other report output.
- An asynchronous runtime. Tokio is not a dependency.
- Timeouts and concurrency limits. There are no network operations to bound.
- Logging, tracing or audit output.
- Internationalized domain name conversion.
- IPv6 zone identifiers.
- Packaging and installation.
- POSIX ACL inspection on any platform; only POSIX mode bits are checked on
  Unix.
- POSIX ownership and permission inspection on non-Unix platforms. On Windows,
  the regular-file check uses the opened handle, but symbolic-link rejection is
  a best-effort pre-open lookup.
- Effective-user ownership checks on Unix platforms other than Linux. POSIX
  write-permission checks still apply there.
- Parent-directory symbolic-link rejection. `O_NOFOLLOW` covers only the final
  component, and `openat2` is not used.
- Race-free symbolic-link rejection on non-Unix platforms, where no portable
  no-follow open flag is used.

A syntactically valid target does not imply permission to scan it. The current
program never emits network traffic.

## Authorization boundary

The authorization boundary exists and is enforced before the placeholder:

```text
Cli::parse
    |
    v
Target::parse
    |
    v
Config::load -> Scope::from_config
    |
    v
Scope::authorize --deny--> error, exit 1
    |
   allow
    |
    v
placeholder output
```

`src/config.rs` owns file loading and schema validation. `src/scope.rs` owns
scope entries, address classification and the allow/deny decision. `target.rs`
remains responsible only for syntax validation and normalization; it does not
know about scope, configuration or network I/O.

The current contract:

- `Scope::authorize` consumes a normalized `Target` and never resolves DNS or
  opens sockets.
- Missing, unreadable or invalid configuration produces denial.
- Unspecified, multicast and broadcast addresses are denied even when listed.
- Loopback, link-local and private addresses require an explicit scope entry.
- Authorization failures use normalized target text and do not reveal scope
  entries.

When DNS and TCP are added, every resolved address must be classified and
authorized before a connection is attempted. A hostname authorization decision
must not authorize arbitrary addresses returned by resolution. The network
operation gate is specified in `docs/SECURITY.md`.

`AGENTS.md` requires CLI, scanning, discovery and reporting to remain separate
modules. Future work should preserve the `Target` validation invariant, place
authorization before every network operation and avoid unbounded concurrency.
The ordered implementation plan and phase boundaries are recorded in
`docs/ROADMAP.md`.
