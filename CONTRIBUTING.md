# Contributing

Thanks for helping improve `open-secret-guard`. The project is intentionally small and local-first, so contributions should keep the scanner easy to audit and safe to run on private repositories.

## Good first contributions

- Add a provider-specific rule with a synthetic test fixture.
- Improve redaction for a finding type that exposes too much context.
- Add documentation for a workflow such as GitHub Actions, pre-commit hooks, or `.env.example` generation.
- Report a false negative using intentionally invalid sample secrets.

## Development

Run the test suite before opening a pull request:

```sh
go test ./...
```

When working in restricted environments where the default Go build cache is not writable, use:

```sh
GOCACHE=/private/tmp/opensource1pass-go-build go test ./...
```

Format Go changes with:

```sh
gofmt -w ./cmd ./internal
```

## Rule changes

Rules should be specific enough to avoid noisy matches in normal source files. When adding a rule:

- use synthetic examples only;
- add at least one positive test;
- add a negative test when the pattern could match common non-secret text;
- make sure output redacts the matched value;
- document the rule ID when it is useful for `scan -only-rules`.

## Security reports

Do not open public issues containing live secrets or private repository content. See `SECURITY.md` for the private reporting process and scope.
