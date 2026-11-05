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

The `scan` subcommand does not perform any network operation. It prints a
placeholder message and exits successfully. There is no authorization system,
configuration loading, DNS resolution, host discovery, TCP scanning, service
identification or report generation yet.

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
│   └── target.rs
└── docs/
    ├── ARCHITECTURE.md
    ├── SECURITY.md
    └── ROADMAP.md
```

`README.md` is the short entry point for building, running and finding the
detailed documents. Tooling directories such as `.opencode/` and the generated
`target/` directory are omitted from the layout. The package produces only a
binary target named `netvigil`. There is no library crate, `build.rs`, feature
flag or integration test directory. The `docs/` directory is documentation
only; no build step consumes it.

## Module responsibilities

### `src/main.rs`

The crate root and process entry point.

- Declares `#![forbid(unsafe_code)]`.
- Declares the `cli` and `target` modules.
- Parses the process arguments with `clap::Parser`.
- Dispatches the parsed command.

The only dispatch arm currently implemented is:

```rust
match cli.command {
    Commands::Scan(args) => {
        println!("Scanning is not implemented yet (target: {}).", args.target);
    }
}
```

`main` returns `()`. It does not use `Result`, install a logging/tracing
subscriber, read files or open network connections.

### `src/cli.rs`

Defines the command-line interface and connects Clap parsing to target
validation.

- `Cli` is the top-level parser. It sets the command name `netvigil`, reads the
  package version and uses the about text `Network intelligence and
  reconnaissance CLI`.
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

The module exposes no options for ports, timeouts, concurrency, configuration
files or output formats. Those options do not exist and must not be assumed.

### `src/target.rs`

Defines the validated target type and its parsing rules.

- `Target` is the public, validated representation of a scan target.
- `TargetKind` is private and has two variants: `Ip(IpAddr)` and
  `Hostname(String)`. Keeping the representation private preserves the
  invariant that every `Target` value has passed validation.
- `Target::parse` performs validation and normalization. It performs no DNS
  resolution and no network access.
- `Target::as_ip` and `Target::as_hostname` expose the normalized
  representation. They are currently used by tests and are annotated with
  `#[allow(dead_code)]` for the future scanner.
- `TargetError` enumerates rejection reasons.
- `MAX_HOSTNAME_LENGTH` is 253 bytes and `MAX_LABEL_LENGTH` is 63 bytes.

`Target` implements `Display` and `FromStr`. `Display` prints the normalized
value, so a hostname is lowercase and without a trailing dot, and an
IPv4-mapped IPv6 address is printed in IPv4 form.

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

Syntactic acceptance is not authorization. For example, loopback, private,
link-local, multicast and unspecified addresses are accepted by the parser
today because there is no authorization layer. See `docs/SECURITY.md`.

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
clap ValueValidation    main match arm
error (generic text)    prints placeholder
```

1. `main` calls `Cli::parse`.
2. Clap parses the subcommand and required `TARGET` argument. Missing arguments,
   unknown subcommands and invalid targets are handled by Clap.
3. `TargetParser` validates the target through `Target::parse`.
4. Invalid targets produce a `ValueValidation` error. The message contains a
   fixed reason and never echoes the rejected input. The observed exit status
   for an invalid target is `2`.
5. Valid targets reach the `Commands::Scan` arm. The program prints the
   normalized target in a placeholder line and exits without performing network
   I/O.

Verified examples:

```console
$ cargo run --quiet -- --help
Network intelligence and reconnaissance CLI

Usage: netvigil <COMMAND>

Commands:
  scan  Scan a target for open ports and services
  help  Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

```console
$ cargo run --quiet -- scan --help
Scan a target for open ports and services

Usage: netvigil scan <TARGET>

Arguments:
  <TARGET>  Target to scan, such as a hostname or IP address

Options:
  -h, --help  Print help
```

```console
$ cargo run --quiet -- --version
netvigil 0.1.0
```

```console
$ cargo run --quiet -- scan 127.0.0.1
Scanning is not implemented yet (target: 127.0.0.1).
```

```console
$ cargo run --quiet -- scan Example.COM.
Scanning is not implemented yet (target: example.com).
```

```console
$ cargo run --quiet -- scan exa_mple.com
error: invalid target: target contains invalid characters

Usage: netvigil scan <TARGET>

For more information, try '--help'.
```

The help text for `scan` describes its intended purpose ("open ports and
services"). That behavior is not implemented yet.

## Technologies and dependencies

The actual dependency set is intentionally small:

| Dependency | Version | Purpose |
| --- | --- | --- |
| Rust | stable, edition 2024 | Implementation language; no MSRV is declared |
| `clap` (feature `derive`) | 4.6.7 | CLI parsing, help and version output |
| `thiserror` | 2.0.21 | `Error` implementation for `TargetError` |

`Cargo.lock` is committed. The crate has no development dependencies; tests use
the standard library and Clap.

`AGENTS.md` lists Tokio, Serde, Anyhow and Thiserror as the intended technology
stack. At the current commit only Clap and Thiserror are manifest dependencies.
Tokio, Serde, Anyhow and a TOML parser are **not** linked or used. Future
additions must be justified under the dependency policy in `AGENTS.md`.

The crate root enables `#![forbid(unsafe_code)]`.

## Build and execution

The project uses the standard Cargo workflow:

```console
cargo build
cargo run -- --help
cargo run -- scan --help
cargo run -- scan 127.0.0.1
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
- **Unimplemented scan:** prints a normal message to standard output. It does
  not report an error.

There is no application-level error type, no `anyhow` usage and no custom exit
code handling.

## Testing

Tests are inline unit tests in `src/cli.rs` and `src/target.rs`. They are
deterministic and do not require external network access.

At the time of this document, `cargo test` reports 44 passing tests. The tests
cover:

- CLI command definition, help and version behavior.
- Required `TARGET` handling and parsing of valid IP and hostname targets.
- Normalization of case, trailing dots and IPv4-mapped IPv6 addresses.
- Rejection of empty, whitespace-containing, oversized, malformed and
  non-ASCII targets.
- Non-echoing error messages for control, format, bidi and line separator
  characters.
- `Display` and `FromStr` behavior.

Per `AGENTS.md`, the expected validation commands are:

```console
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo check
```

## Current limitations and absent functionality

The following capabilities are **not implemented**:

- Target authorization or scope enforcement.
- TOML configuration loading.
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

A syntactically valid target does not imply permission to scan it. The current
program never emits network traffic.

## Planned authorization boundary (not implemented)

No authorization module, policy type or scope loader exists in the current
code. The following is a proposed layout for the authorization milestone, not a
commitment to specific file names. It is recorded so implementation does not
couple policy to target syntax:

```text
src/
├── main.rs        # dispatch only
├── cli.rs         # argument parsing and target value parser
├── target.rs      # syntax validation and normalization (exists)
├── auth.rs        # planned: authorization decisions and special-address policy
└── config.rs      # planned: TOML loading and scope definitions
```

The planned insertion point in the execution flow is:

```text
Cli::parse
    |
    v
Target::parse
    |
    v
authorization (planned) --deny--> denial (planned)
    |
    v
DNS (planned)
    |
    v
TCP (planned)
```

`Cli::parse`, `Target::parse` and the placeholder dispatch exist today. The
authorization, DNS and TCP stages do not.

Design constraints for that milestone:

- `target.rs` remains responsible only for syntax validation and
  normalization. It must not know about scope, configuration or network I/O.
- The planned authorization module consumes a normalized `Target` and returns
  an explicit allow or deny decision. It must not resolve DNS or open sockets.
- The planned configuration module supplies scope to the authorization module.
  Missing, unreadable or invalid configuration must produce denial.
- `main.rs` must consult authorization before any future DNS or TCP operation.
  A target that is syntactically valid but not authorized must not reach the
  network layer.
- Authorization failures must use the same non-echoing error discipline as
  invalid-target errors.
- Module names and the exact configuration schema are not fixed by this
  document; they must be defined and tested when the milestone is implemented.

`AGENTS.md` requires CLI, scanning, discovery and reporting to remain separate
modules. Future work should preserve the `Target` validation invariant, place
authorization before every network operation and avoid unbounded concurrency.
The ordered implementation plan and phase boundaries are recorded in
`docs/ROADMAP.md`; the default-deny policy requirements are recorded in
`docs/SECURITY.md`. Those documents describe requirements, not implemented
behavior.
