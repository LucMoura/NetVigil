---
description: Run tests and validate code quality in NetVigil
agent: test-engineer
---

Perform a complete test and quality validation of NetVigil.

Additional instructions from the user:

$ARGUMENTS

## Workflow

1. Read AGENTS.md.
2. Inspect the project structure and existing tests.
3. Identify missing test coverage and potential regressions.
4. Run the existing test suite.
5. Add tests only when explicitly requested.
6. Do not modify production code.

## Validation

Run:

- cargo fmt --check
- cargo clippy -- -D warnings
- cargo test
- cargo check

## Analysis

For each failure, report:

- Command that failed.
- Relevant error message.
- Possible cause.
- Recommended solution.

## Constraints

- Do not remove or weaken existing tests.
- Do not modify production code.
- Do not hide failures.
- Do not claim a test passed without executing it.

## Final Report

Summarize:

- Tests executed.
- Results of each command.
- Potential regressions.
- Missing test coverage.
- Recommended next steps.
