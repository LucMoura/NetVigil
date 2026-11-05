---
description: Perform a security audit of NetVigil and identify vulnerabilities and risks
agent: security-reviewer
---

Perform a security review of the NetVigil project.

Additional focus requested by the user:

$ARGUMENTS

## Workflow

1. Read AGENTS.md and understand the project guidelines.
2. Inspect the project structure and relevant source files.
3. Analyze the implementation for security vulnerabilities.
4. Review error handling, input validation and resource management.
5. Examine dependencies and configuration for potential risks.
6. Identify weaknesses in network scanning and service detection logic.

## Security Checklist

Pay special attention to:

- IP address and port validation.
- TCP connection handling.
- Connection timeouts.
- Concurrency limits and resource exhaustion.
- IPv4 and IPv6 handling.
- Malformed network responses.
- Banner parsing and service identification.
- JSON serialization and output handling.
- File and path handling.
- Error messages and information disclosure.
- Unsafe Rust usage.
- Dependency vulnerabilities and outdated packages.

## Constraints

- This is a read-only security review.
- Do not create, modify or delete files.
- Do not implement fixes.
- Do not introduce stealth, evasion or unauthorized scanning features.
- Distinguish confirmed vulnerabilities from potential risks.
- Do not report speculative issues as confirmed vulnerabilities.

## Findings Format

For each finding, report:

- **Severity:** Critical, High, Medium, Low or Informational.
- **Location:** File and relevant line number.
- **Description:** What is wrong.
- **Impact:** What could happen.
- **Recommendation:** How to fix it.

## Final Report

Provide:

1. Executive summary.
2. Findings ordered by severity.
3. Positive security practices identified.
4. Areas that need further investigation.
5. Recommended remediation priorities.

If no vulnerabilities are identified, state that clearly and explain the scope and limitations of the review.
