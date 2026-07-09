# Security Policy

`open-secret-guard` is a local-first tool for finding accidental secret leaks in source files. Security reports are welcome, especially for false negatives, unsafe output behavior, or cases where the tool could expose secrets while reporting findings.

## Supported versions

The `main` branch is the supported development line. Until the project starts publishing tagged releases, security fixes will land on `main`.

## Reporting a vulnerability

Please report security issues privately instead of opening a public issue with sensitive details.

If GitHub private vulnerability reporting is enabled for this repository, use that channel. Otherwise, contact the repository owner through GitHub and include enough detail to reproduce the problem without sharing real credentials.

Please include:

- The affected command or output format, such as `scan`, `rules`, JSON, or SARIF.
- A minimal synthetic fixture that reproduces the behavior.
- The expected result and the actual result.
- Your operating system and Go version, if relevant.

Do not include live API keys, tokens, private keys, customer data, or private repository contents in a report. Use placeholder values or intentionally invalid examples.

## Scope

Useful reports include:

- Secret patterns that should be detected but are missed.
- Findings that expose too much of a secret in redacted output.
- JSON or SARIF output that could leak sensitive data unexpectedly.
- Allowlist behavior that hides findings more broadly than intended.
- Pre-commit hook generation issues that could skip scans unexpectedly.

Reports about unsupported third-party tools, hosted scanners, or secrets already committed to unrelated repositories are outside this project's scope.

## Response expectations

This is a small open source project, so response times may vary. The goal is to acknowledge valid reports, reproduce them with synthetic fixtures, add regression coverage, and release the fix through `main`.
