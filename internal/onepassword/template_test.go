package onepassword

import (
	"strings"
	"testing"
)

func TestGenerateCreatesSecretReferencesWithoutSourceValues(t *testing.T) {
	input := stringsJoin(
		"# application settings",
		"API_KEY=super-secret-value",
		"export DATABASE_URL=postgres://demo:password@localhost/app # local database",
		"EMPTY=",
		"PLAIN_LINE",
	)

	got := Generate(input, "Open Source", "open-secret-guard")
	want := stringsJoin(
		"# application settings",
		"API_KEY=op://Open%20Source/open-secret-guard/API_KEY",
		"export DATABASE_URL=op://Open%20Source/open-secret-guard/DATABASE_URL # local database",
		"EMPTY=op://Open%20Source/open-secret-guard/EMPTY",
		"PLAIN_LINE",
	)

	if got != want {
		t.Fatalf("unexpected 1Password template:\nwant:\n%s\n\ngot:\n%s", want, got)
	}
	if strings.Contains(got, "super-secret-value") || strings.Contains(got, "password@") {
		t.Fatalf("template must not contain source values:\n%s", got)
	}
}

func TestGenerateLeavesInvalidEnvironmentAssignmentsUntouched(t *testing.T) {
	input := "INVALID-KEY=keep-this\n"
	if got := Generate(input, "vault", "item"); got != input {
		t.Fatalf("expected invalid assignment to stay unchanged, got %q", got)
	}
}

func stringsJoin(lines ...string) string {
	result := ""
	for index, line := range lines {
		if index > 0 {
			result += "\n"
		}
		result += line
	}
	return result
}
