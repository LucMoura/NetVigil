# NetVigil - Project Guidelines

## Project
NetVigil is a network intelligence and reconnaissance
CLI written entirely in Rust.

## Technology
- Rust stable
- Tokio for asynchronous operations
- Clap for CLI parsing
- Serde for serialization
- Anyhow and Thiserror for error handling

## Architecture
- Keep modules independent and organized.
- Separate CLI, scanning, discovery and reporting.
- Prefer simple and maintainable solutions.
- Avoid unnecessary dependencies.

## Rust Guidelines
- Follow idiomatic Rust practices.
- Use Result and Option appropriately.
- Avoid unnecessary unwrap() and expect().
- Document public functions.
- Handle errors explicitly.

## Testing
After every implementation:
- Run cargo fmt --check
- Run cargo clippy -- -D warnings
- Run cargo test
- Run cargo check

## Security
- Only scan explicitly authorized targets.
- Never implement stealth or evasion features.
- Validate all user-provided inputs.
- Use configurable connection timeouts.
- Avoid unbounded concurrency.

## Workflow
- Do not rewrite unrelated code.
- Explain architectural decisions.
- Implement features incrementally.
- Never claim tests passed without executing them.

## Scope
- NetVigil is intended for authorized network discovery and diagnostics.
- Do not implement exploitation, stealth, evasion or persistence features.
- Do not scan public or third-party targets without explicit authorization

## Dependencies
- Justify every new dependecy before adding it.
- Prefer maintained crates with minimal dependecy trees.
- Avoid dependecies that duplicate existing funcionality

## Teste Strategy
- Prefer deterministic tests that do not require external network access.
- Use localhost and controlled test fixtures for network tests.
- Include edge cases for invalid targets, ports and timeouts.
