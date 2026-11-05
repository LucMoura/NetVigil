# NetVigil

NetVigil is a network intelligence and reconnaissance CLI written in Rust.

> **Status:** 0.1.0. The CLI, target validation and the authorization scope are
> implemented. DNS resolution, host discovery, TCP scanning, service
> identification and JSON reports are **not implemented**. See
> [docs/ROADMAP.md](docs/ROADMAP.md) for the planned order.

## Requirements

- Rust stable with edition 2024 support.
- No minimum supported Rust version (MSRV) is declared.

## Build and run

```console
cargo build
cargo run -- --help
cargo run -- scan --help
```

The debug binary is written to `target/debug/netvigil`.

## Configuration and authorization

NetVigil uses default deny: a target is allowed only when it matches an entry
declared in the configuration file. The file must be selected explicitly with
`--config PATH`. There is **no implicit default** such as `netvigil.toml` in the
current working directory.

```toml
[scope]
targets = [
    "192.168.1.0/24",
    "10.0.0.15",
    "203.0.113.10",
    "scan.exemplo.com",
]
```

The selected path is treated as untrusted input:

- It must be a regular file. On Unix, the final path component is opened with
  `O_NOFOLLOW` and `O_NONBLOCK`, so symbolic links, directories, FIFOs and
  other non-regular files are rejected without blocking. On other platforms,
  symbolic-link rejection is a best-effort check before opening.
- The file must be at most 1 MiB. Larger files are rejected without being
  read.
- The configuration may declare at most 4096 scope rules.
- On Unix, permissions, ownership and size are checked on the opened handle.
  Files writable by group or other users are rejected. On Linux, the file must
  also be owned by the current effective user; if that user ID cannot be
  determined, loading fails closed.
- Symbolic links in parent directories are followed. NetVigil does not use
  `openat2` or equivalent resolution controls, and non-Unix platforms do not
  provide POSIX ownership or ACL checks.
- Paths and TOML errors are sanitized: control characters, ANSI/OSC sequences
  and bidi controls are escaped, and raw TOML source lines are not reproduced.
  Syntax diagnostics still include the error category and, when available,
  line and column.

Scope entries may be:

- An individual IPv4 or IPv6 address.
- An IPv4 or IPv6 CIDR network.
- A hostname, matched exactly after case normalization and trailing-dot
  removal.

A missing `--config`, an unreadable or invalid configuration file, an untrusted
file, or an oversized/excessive configuration is an error and denies the scan.
An empty `targets` list authorizes nothing.

Public and private addresses are authorized only when declared. Loopback and
link-local addresses require an explicit entry as well. Unspecified, multicast
and broadcast addresses are never valid scan targets, even when listed.

There is no DNS resolution yet, so hostnames are authorized by their normalized
name only. Resolved addresses will require their own authorization when DNS is
implemented.

## Current CLI

```text
netvigil --config PATH scan <TARGET>
```

The only application subcommand is `scan`; Clap also provides the generated
`help` subcommand. `scan` requires one positional `TARGET` argument.
`--config PATH` is required; omitting it fails closed with exit status `1`.

`TARGET` accepts an IPv4 address, an IPv6 address or an ASCII hostname. The
target is validated and normalized during argument parsing. The current `scan`
command does not perform DNS resolution or network I/O; after authorization it
prints a placeholder message.

Examples:

```console
$ cargo run --quiet -- --config netvigil.toml scan 192.168.1.42
Scanning is not implemented yet (target: 192.168.1.42).

$ cargo run --quiet -- --config netvigil.toml scan SCAN.Exemplo.COM.
Scanning is not implemented yet (target: scan.exemplo.com).

$ cargo run --quiet -- --config netvigil.toml scan 198.51.100.7
error: target 198.51.100.7 is not authorized by the configured scope

$ cargo run --quiet -- --config missing.toml scan 192.0.2.10
error: failed to read configuration file missing.toml: No such file or directory (os error 2)

$ cargo run --quiet -- scan 192.0.2.10
error: no configuration file selected; use --config PATH
```

The last three commands exit with status `1` and produce no scan output. Invalid
target syntax is still handled by Clap and exits with status `2`.

There are no options for ports, timeouts, concurrency or output formats yet.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Security model](docs/SECURITY.md)
- [Roadmap](docs/ROADMAP.md)

## Security

NetVigil is intended for authorized network discovery and diagnostics only.
Only targets explicitly declared in the configured scope may be scanned.
Private or special-purpose addresses are not authorized automatically.
Stealth, evasion, exploitation and persistence are out of scope.

See [docs/SECURITY.md](docs/SECURITY.md) for the full policy and remaining gaps.

## Testing

```console
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo check
```

Tests are deterministic and do not require external network access. Unit tests
cover target parsing, configuration and scope decisions; integration tests
execute the binary against local configuration fixtures.
