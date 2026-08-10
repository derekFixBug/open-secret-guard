# Changelog

All notable changes to `open-secret-guard` are tracked here. The project is early, so changes are grouped by date until tagged releases begin.

## Unreleased

### Added

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
