# NetVigil

NetVigil is a network intelligence and reconnaissance CLI written in Rust.

> **Status:** 0.1.0. The CLI and target validation are implemented. The
> authorization system, TOML configuration, DNS resolution, host discovery, TCP
> scanning, service identification and JSON reports are **not implemented**.
> See [docs/ROADMAP.md](docs/ROADMAP.md) for the planned order.

## Requirements

- Rust stable with edition 2024 support.
- No minimum supported Rust version (MSRV) is declared.

## Build and run

```console
cargo build
cargo run -- --help
cargo run -- scan --help
cargo run -- scan 127.0.0.1
```

The debug binary is written to `target/debug/netvigil`.

## Current CLI

The only application subcommand is `scan`; Clap also provides the generated
`help` subcommand. `scan` requires one positional `TARGET` argument:

```text
netvigil scan <TARGET>
```

`TARGET` accepts an IPv4 address, an IPv6 address or an ASCII hostname. The
target is validated and normalized during argument parsing. The current `scan`
command does not perform DNS resolution or network I/O; it prints a placeholder
message.

Examples:

```console
$ cargo run --quiet -- scan Example.COM.
Scanning is not implemented yet (target: example.com).

$ cargo run --quiet -- scan exa_mple.com
error: invalid target: target contains invalid characters

Usage: netvigil scan <TARGET>

For more information, try '--help'.
```

There are no options for ports, timeouts, concurrency, configuration files or
output formats yet.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY.md)
- [Roadmap](docs/ROADMAP.md)

## Security

NetVigil is intended for authorized network discovery and diagnostics only.
The project's security model requires default deny: only explicitly authorized
targets may be used, and private or special-purpose addresses are not
automatically authorized. Enforcement is **not implemented yet**; the current
`scan` command performs no network operations. Stealth, evasion, exploitation
and persistence are out of scope.

See [docs/SECURITY.md](docs/SECURITY.md) for the required controls and current
gaps.

## Testing

```console
cargo fmt --check
cargo clippy -- -D warnings
cargo test
cargo check
```

Tests are inline unit tests and do not require external network access.
