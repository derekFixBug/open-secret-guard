# open-secret-guard

`open-secret-guard` is a small local CLI for open source maintainers who want to catch accidental secret leaks before they reach a public repository.

It scans source files for common high-risk patterns such as GitHub, GitLab, and Azure DevOps tokens, Slack tokens and webhooks, Discord bot tokens, AI service tokens, JWT bearer tokens, AWS access key identifiers, npm and PyPI tokens, DigitalOcean and Shopify tokens, Terraform Cloud tokens, private key headers, database URLs with inline credentials, and suspicious secret assignments.

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

Keep every finding in the report but only fail CI for high- or critical-severity findings:

```sh
open-secret-guard scan . -fail-on-severity high
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

Exclude generated credential files everywhere by filename pattern:

```sh
open-secret-guard scan . -exclude '*.env,*.pem'
```

Keep shared exclusions in a text file; blank lines and lines beginning with `#` are ignored:

```text
# .open-secret-guard.exclude
examples
*.generated.env
```

```sh
open-secret-guard scan . -exclude-file .open-secret-guard.exclude
```

Increase the maximum file size for generated or minified configuration files. The default is 2 MiB:

```sh
open-secret-guard scan . -max-file-bytes 8388608
```

Limit the number of reported findings. Findings are sorted by path and line before the limit is applied, so the output stays deterministic:

```sh
open-secret-guard scan . -max-findings 20
```

Allow a reviewed finding without skipping the whole file:

```sh
open-secret-guard scan . -allowlist .open-secret-guard.allowlist
```

Allowlist entries use this format. The optional expiry date is inclusive and prevents a review exception from being used indefinitely:

```text
rule-id path-glob [line]
rule-id path-glob [line] [expires-on:YYYY-MM-DD]
```

For example:

```text
database-url examples/leaky.env 4
github-token docs/token.md 12 2026-12-31
```

Validate an allowlist before using it in CI. The scanner also performs this validation automatically when `-allowlist` is supplied, so misspelled rule IDs and duplicate entries do not silently weaken a scan:

```sh
open-secret-guard allowlist-check .open-secret-guard.allowlist
```

Fail a CI check before temporary allowlist exceptions expire. The window includes entries expiring today and never prints matched values:

```sh
open-secret-guard allowlist-check .open-secret-guard.allowlist -expires-within 30
```

Return the allowlist entry count and expiring entries as JSON for CI scripts. The command still exits non-zero when the requested expiry window contains entries:

```sh
open-secret-guard allowlist-check .open-secret-guard.allowlist -format json -expires-within 30
```

Generate reviewed allowlist candidates from current findings. This command never changes a file and never prints matched values:

```sh
open-secret-guard allowlist-suggest . -min-severity high > .open-secret-guard.allowlist.candidates
```

For a temporary reviewed exception, append the same inclusive expiry date to every generated candidate. Dates in the past are rejected:

```sh
open-secret-guard allowlist-suggest . -min-severity high -expires-on 2026-12-31 > .open-secret-guard.allowlist.candidates
```

Focus a scan or candidate review on selected providers. Multiple providers are comma-separated:

```sh
open-secret-guard scan . -provider github,gitlab
open-secret-guard allowlist-suggest . -provider github -min-severity high
```

List the built-in rule IDs, providers, severity levels, and descriptions:

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

Only list rules for selected providers. Multiple providers are comma-separated:

```sh
open-secret-guard rules -provider github,gitlab
```

Print the rules as a Markdown table for project documentation:

```sh
open-secret-guard rules -format markdown
```

Export rule metadata as CSV for a spreadsheet or audit inventory:

```sh
open-secret-guard rules -format csv > open-secret-guard-rules.csv
```

Print a CI-friendly scan summary without paths or matched values:

```sh
open-secret-guard scan . -format summary
```

Create a Markdown findings table for a pull request or issue. It includes paths, rules, providers, and severity levels, but never matched values:

```sh
open-secret-guard scan . -format markdown
```

Export findings as CSV for a spreadsheet or a CI artifact. The export includes metadata only and never matched values:

```sh
open-secret-guard scan . -format csv > open-secret-guard-findings.csv
```

Emit GitHub Actions annotations so findings link to their source locations in workflow logs. High and critical findings are errors, medium findings are warnings, and low findings are notices; matched values are never included:

```sh
open-secret-guard scan . -format github
```

Generate a safe `.env.example` from a local `.env` file:

```sh
open-secret-guard env-example .env -output .env.example
```

Generate a 1Password CLI template from `.env.example`. It contains only `op://` secret references, not source values:

```sh
open-secret-guard 1password-template .env.example -vault 'Open Source' -item 'open-secret-guard' -output .env.1password
op run --env-file=.env.1password -- your-command
```

When migrating a template that already has selected `op://` references, keep those references while generating missing fields for the supplied vault and item:

```sh
open-secret-guard 1password-template .env.example -vault 'Open Source' -item 'open-secret-guard' -preserve-references
```

Generate a local pre-commit hook:

```sh
open-secret-guard install-hook -allowlist .open-secret-guard.allowlist -output .git/hooks/pre-commit
```

Only block commits for high- or critical-severity findings:

```sh
open-secret-guard install-hook -min-severity high -output .git/hooks/pre-commit
```

Configure the pre-commit scan to share exclusions with CI, scan larger files, and fail only on high or critical findings:

```sh
open-secret-guard install-hook -exclude-file .open-secret-guard.exclude -max-file-bytes 8388608 -fail-on-severity high -output .git/hooks/pre-commit
```

Generate a minimal GitHub Actions workflow:

```sh
open-secret-guard github-action -allowlist .open-secret-guard.allowlist -output .github/workflows/secret-guard.yml
```

Generate a workflow that reports every finding but fails only for high or critical severity:

```sh
open-secret-guard github-action -fail-on-severity high -output .github/workflows/secret-guard.yml
```

Pass selected providers through to the workflow scan step when the repository only needs specific credential families:

```sh
open-secret-guard github-action -provider github,gitlab -output .github/workflows/secret-guard.yml
```

Generate a Code Scanning-ready workflow that uploads SARIF results:

```sh
open-secret-guard github-action -allowlist .open-secret-guard.allowlist -sarif-output open-secret-guard.sarif -output .github/workflows/secret-guard.yml
```

Use the same larger file-size limit in generated CI workflows when repositories contain minified or generated configuration files:

```sh
open-secret-guard github-action -max-file-bytes 8388608 -output .github/workflows/secret-guard.yml
```

Cap the number of findings printed by CI while preserving the scanner's sorted order:

```sh
open-secret-guard github-action -max-findings 20 -output .github/workflows/secret-guard.yml
```

For a monorepo, generate a workflow that runs only when selected directories change and scans only those directories:

```sh
open-secret-guard github-action -trigger-paths 'services/api/**,packages/shared/**' -scan-paths 'services/api,packages/shared' -output .github/workflows/secret-guard.yml
```

Keep generated CI aligned with local scans by excluding demo data or test fixtures:

```sh
open-secret-guard github-action -exclude 'examples,testdata' -output .github/workflows/secret-guard.yml
```

Use a committed exclusion file in generated CI as well:

```sh
open-secret-guard github-action -exclude-file .open-secret-guard.exclude -output .github/workflows/secret-guard.yml
```

Choose the pull request and push branches for repositories that do not use only `main`:

```sh
open-secret-guard github-action -branches 'main,develop,release/**' -output .github/workflows/secret-guard.yml
```

Add a weekly scheduled scan alongside pull request and push checks. GitHub Actions cron uses UTC:

```sh
open-secret-guard github-action -schedule '0 9 * * 1' -output .github/workflows/secret-guard.yml
```

Include a manual **Run workflow** button for an on-demand review from the GitHub Actions page:

```sh
open-secret-guard github-action -manual-trigger -output .github/workflows/secret-guard.yml
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
- provider-aware CI presets;
- tagged releases once the CLI surface stabilizes.

## License

MIT
