---
description: Implement a NetVigil feature following project architecture and Rust best practices
agent: rust-engineer
---

Implement the following feature or change in NetVigil:

$ARGUMENTS

## Workflow

1. Read AGENTS.md and understand the project guidelines.
2. Inspect the existing project structure and relevant source files.
3. Understand how the requested feature fits into the current architecture.
4. Identify the files that need to be created or modified.
5. Implement the feature incrementally.
6. Add or update tests where appropriate.
7. Update documentation if the feature changes user-facing behavior.

## Constraints

- Do not rewrite unrelated code.
- Do not introduce unnecessary dependencies.
- Preserve existing functionality.
- Validate all user-provided inputs.
- Use explicit error handling.
- Avoid unnecessary unwrap() and expect().
- Never implement stealth or evasion functionality.
- Only implement authorized network reconnaissance functionality.
- Avoid unbounded concurrency.

## Validation

Run the following commands after implementation:

- cargo fmt --check
- cargo clippy -- -D warnings
- cargo test
- cargo check

If any command fails, investigate and report the problem. Do not hide failures or claim successful validation without execution.

## Final Report

Summarize:

- What was implemented.
- Files created or modified.
- Architectural decisions.
- Tests performed and their results.
- Known limitations or remaining tasks.
