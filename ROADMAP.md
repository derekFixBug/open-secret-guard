# Roadmap

`open-secret-guard` is a small local scanner for maintainers who want a simple, auditable secret-checking workflow. This roadmap tracks practical improvements that fit that scope.

## Current focus

- Keep rule coverage useful for common open source workflows.
- Make CI and pre-commit usage predictable.
- Improve documentation for safe secret handling.
- Keep outputs machine-readable without exposing raw secrets.

## Planned work

### Rule coverage

- Add more provider-specific token patterns with synthetic fixtures.
- Expand negative tests for patterns that could match normal documentation.
- Group rules by provider in documentation.

### CLI workflow

- Add examples for focused scans using `-only-rules` and `-min-severity`.
- Improve exit-code documentation for CI users.
- Add a command that prints a minimal GitHub Actions workflow.

### Output and integrations

- Keep SARIF output compatible with GitHub code scanning.
- Add regression tests for JSON and SARIF redaction behavior.
- Document how to upload SARIF in a real repository workflow.

### Project maintenance

- Publish tagged releases once the CLI surface stabilizes.
- Track rule additions in `CHANGELOG.md`.
- Keep `SECURITY.md` aligned with the current reporting process.

## Out of scope

- Uploading repository content to a hosted service.
- Replacing full secret-management platforms.
- Guaranteeing that every possible secret format is detected.
