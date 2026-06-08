# open-secret-guard

`open-secret-guard` is a small local CLI for open source maintainers who want to catch accidental secret leaks before they reach a public repository.

It scans source files for common high-risk patterns such as GitHub tokens, AWS access key identifiers, private key headers, database URLs with inline credentials, and suspicious secret assignments.

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

Scan hidden files and directories:

```sh
open-secret-guard scan . -include-hidden
```

Exclude demo or fixture paths:

```sh
open-secret-guard scan . -exclude examples,testdata
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
      - run: go run ./cmd/open-secret-guard scan . -exclude examples -fail-on-findings

      # Optional: write SARIF for upload with github/codeql-action/upload-sarif.
      - run: go run ./cmd/open-secret-guard scan . -exclude examples -format sarif > open-secret-guard.sarif
```

## Project status

This project is intentionally small and early. The first goal is to provide a clear, auditable baseline for maintainers who want lightweight local checks without sending repository content to a hosted service.

Planned improvements:

- configurable allowlists;
- `.env.example` generation;
- more provider-specific token patterns;
- pre-commit hook examples.

## License

MIT
