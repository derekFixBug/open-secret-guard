# open-secret-guard

`open-secret-guard` is a small local CLI for open source maintainers who want to catch accidental secret leaks before they reach a public repository.

It scans source files for common high-risk patterns such as GitHub and GitLab tokens, Slack tokens and webhooks, Discord bot tokens, AI service tokens, JWT bearer tokens, AWS access key identifiers, npm and PyPI tokens, DigitalOcean and Shopify tokens, Terraform Cloud tokens, private key headers, database URLs with inline credentials, and suspicious secret assignments.

## Why this exists

Open source projects often need to document configuration without exposing real credentials. This tool helps maintainers:

- scan a repository before pushing code;
- generate clear findings that can be used in CI;
- teach contributors which values belong in a password manager or secret store;
- keep example configuration files safe.

## Install

From this repository:

```sh
go install ./cmd/open-secret-guard
```

Or run it directly:

```sh
go run ./cmd/open-secret-guard scan .
```

## Usage

Scan the current directory:

```sh
open-secret-guard scan .
```

Return JSON for automation:

```sh
open-secret-guard scan . -format json
```

Return SARIF for GitHub code scanning integrations:

```sh
open-secret-guard scan . -format sarif
```

Fail CI when findings are detected:

```sh
open-secret-guard scan . -fail-on-findings
```

Only report high and critical findings:

```sh
open-secret-guard scan . -min-severity high
```

Only report selected rule IDs:

```sh
open-secret-guard scan . -only-rules github-token,private-key
```

Scan hidden files and directories:

```sh
open-secret-guard scan . -include-hidden
```

Exclude demo or fixture paths:

```sh
open-secret-guard scan . -exclude examples,testdata
```

Allow a reviewed finding without skipping the whole file:

```sh
open-secret-guard scan . -allowlist .open-secret-guard.allowlist
```

Allowlist entries use this format:

```text
rule-id path-glob [line]
```

For example:

```text
database-url examples/leaky.env 4
```

Validate an allowlist before using it in CI. The scanner also performs this validation automatically when `-allowlist` is supplied, so misspelled rule IDs and duplicate entries do not silently weaken a scan:

```sh
open-secret-guard allowlist-check .open-secret-guard.allowlist
```

List the built-in rule IDs, severity levels, and descriptions:

```sh
open-secret-guard rules
```

Return the rule metadata as JSON for scripts or CI configuration:

```sh
open-secret-guard rules -format json
```

Only list rules at or above a severity level:

```sh
open-secret-guard rules -min-severity high
```

Print the rules as a Markdown table for project documentation:

```sh
open-secret-guard rules -format markdown
```

Print a CI-friendly scan summary without paths or matched values:

```sh
open-secret-guard scan . -format summary
```

Generate a safe `.env.example` from a local `.env` file:

```sh
open-secret-guard env-example .env -output .env.example
```

Generate a local pre-commit hook:

```sh
open-secret-guard install-hook -allowlist .open-secret-guard.allowlist -output .git/hooks/pre-commit
```

Generate a minimal GitHub Actions workflow:

```sh
open-secret-guard github-action -allowlist .open-secret-guard.allowlist -output .github/workflows/secret-guard.yml
```

Generate a Code Scanning-ready workflow that uploads SARIF results:

```sh
open-secret-guard github-action -allowlist .open-secret-guard.allowlist -sarif-output open-secret-guard.sarif -output .github/workflows/secret-guard.yml
```

For a monorepo, generate a workflow that runs only when selected directories change and scans only those directories:

```sh
open-secret-guard github-action -trigger-paths 'services/api/**,packages/shared/**' -scan-paths 'services/api,packages/shared' -output .github/workflows/secret-guard.yml
```

## Example output

```text
Found 1 likely secret(s):

config/.env:3:1 [medium] assigned-secret
  This assignment looks like it may contain a secret value.
  matched: API_********alue
```

## GitHub Actions

```yaml
name: Secret guard

on:
  pull_request:
  push:
    branches: [main]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: "1.22"
      - run: go run ./cmd/open-secret-guard scan . -allowlist .open-secret-guard.allowlist -fail-on-findings
```

Pass `-sarif-output open-secret-guard.sarif` to `github-action` to generate a workflow with the required `security-events: write` permission and an `upload-sarif` step. The upload step uses `if: always()` so GitHub can receive findings even when the scan fails the build.

## Project status

This project is intentionally small and early. The first goal is to provide a clear, auditable baseline for maintainers who want lightweight local checks without sending repository content to a hosted service.

Maintenance docs:

- `ROADMAP.md` tracks near-term work.
- `CHANGELOG.md` tracks user-visible changes until tagged releases begin.
- `CONTRIBUTING.md` explains how to add rules safely with synthetic fixtures.
- `SECURITY.md` explains how to report false negatives, unsafe output behavior, or other security issues privately.

Planned improvements:

- more provider-specific token patterns;
- stronger negative tests for noisy patterns;
- configurable workflow branch filters;
- provider grouping in generated rule documentation;
- tagged releases once the CLI surface stabilizes.

## License

MIT
