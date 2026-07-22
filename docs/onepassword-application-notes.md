# 1Password for Open Source application notes

This document tracks information that will be useful when the project is old enough to apply for 1Password for Open Source.

## Eligibility checklist

- The project is open source.
- The project uses the MIT license.
- The project is non-commercial.
- The repository has been active for at least 30 days.
- The applicant is a founder, owner, or core maintainer.

## Draft short description

open-secret-guard is a local CLI and GitHub Action that helps open source maintainers detect leaked secrets, generate safer configuration examples, and document secure secret workflows for contributors.

## Why the project can use 1Password

The project can use 1Password to store release credentials, test tokens, package publishing credentials, and shared maintainer access without putting secrets in source files or local plaintext notes.

## Activity log

- 2026-06-04: Created the initial Go CLI, scanner rules, tests, CI, README, and MIT license.
- 2026-06-08: Added SARIF output for GitHub code scanning integrations.
- 2026-06-09: Added allowlist support for reviewed demo or fixture findings.
- 2026-06-16: Added OpenAI and Anthropic API key detection and hardened scanner fixtures.
- 2026-06-17: Added `.env.example` generation for safer configuration documentation.
- 2026-06-17: Added pre-commit hook generation for local secret checks.
- 2026-07-09: Added SECURITY.md for private vulnerability reporting guidance.
- 2026-07-15: Added minimum severity filtering for scan output and CI gates.
- 2026-07-22: Extended detection for GitHub fine-grained PATs, Slack webhooks, PyPI, DigitalOcean, and Shopify tokens.
