# Changelog

All notable changes to `open-secret-guard` are tracked here. The project is early, so changes are grouped by date until tagged releases begin.

## Unreleased

### Added

- Added `github-action -manual-trigger` to generate an on-demand GitHub Actions scan trigger.
- Added `github-action -schedule` to include an optional recurring GitHub Actions cron scan.
- Added `install-hook -min-severity` for pre-commit checks that only block selected risk levels.
- Added `github-action -max-findings` so generated CI workflows can cap findings like local scans.
- Added `github-action -branches` to configure the pull request and push branches generated workflows should watch.
- Added `scan -format markdown` for shareable findings tables that include rule metadata without matched secret values.
- Added `-max-findings` to `scan` and `allowlist-suggest` so very large reports can be capped; findings stay sorted by path and line before the limit is applied.
- Added `-provider` filtering to `scan`, `allowlist-suggest`, and generated GitHub Actions workflows for focused provider-specific checks.
- Added `github-action -max-file-bytes` so generated CI workflows can scan the same larger files as local runs.
- Added provider metadata and `rules -provider` filtering for provider-focused rule documentation and CI setup.
- Added `-max-file-bytes` to scan larger generated or minified configuration files, and support for long lines within the selected limit.
- Added `allowlist-suggest` to generate reviewable allowlist candidates without exposing matched values.
- Added `github-action -trigger-paths` and `-scan-paths` for focused monorepo workflows.
- Added `allowlist-check` and automatic allowlist validation to catch unknown rule IDs and duplicate entries before scans run.
- Added `scan -format summary` for count-only CI output that does not print matched values.
- Added `rules -format markdown` for documentation-ready rule tables.
- Added `github-action -sarif-output` to generate a Code Scanning upload step with the required GitHub Actions permissions.
- Added `github-action` to generate a minimal GitHub Actions secret scanning workflow.
- Documented the current roadmap and contribution workflow.
- Added issue templates for false negatives and rule requests.
- Added `rules -min-severity` so maintainers can list built-in rules at or above a chosen severity.

## 2026-07-23

### Added

- Added `scan -only-rules` for focused scans against selected rule IDs.
- Extended provider-specific detection for common token formats.

## 2026-07-15

### Added

- Added `scan -min-severity` for CI gates that only fail on higher-risk findings.
- Added security reporting guidance in `SECURITY.md`.

## 2026-06

### Added

- Added the initial local scanner, text/JSON/SARIF output, allowlists, `.env.example` generation, pre-commit hook generation, and built-in rule listing.
