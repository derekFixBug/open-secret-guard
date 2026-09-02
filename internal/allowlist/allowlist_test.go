package allowlist

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/derekFixBug/open-secret-guard/internal/scanner"
)

func TestLoadParsesEntries(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "allowlist.txt")
	content := "# known demo value\n" +
		"database-url examples/*.env 4 2030-01-02\n" +
		"github-token docs/token.md\n"

	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}

	entries, err := Load(target)
	if err != nil {
		t.Fatalf("load allowlist: %v", err)
	}

	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].RuleID != "database-url" {
		t.Fatalf("unexpected rule id %q", entries[0].RuleID)
	}
	if entries[0].Line != 4 {
		t.Fatalf("expected line 4, got %d", entries[0].Line)
	}
	if got := entries[0].ExpiresAt.Format(time.DateOnly); got != "2030-01-02" {
		t.Fatalf("expected expiry 2030-01-02, got %q", got)
	}
}

func TestLoadParsesExpiryWithoutLine(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "allowlist.txt")
	if err := os.WriteFile(target, []byte("github-token docs/token.md 2030-01-02\n"), 0o600); err != nil {
		t.Fatalf("write allowlist: %v", err)
	}

	entries, err := Load(target)
	if err != nil {
		t.Fatalf("load allowlist: %v", err)
	}
	if entries[0].Line != 0 || entries[0].ExpiresAt.IsZero() {
		t.Fatalf("expected expiry without line number, got %#v", entries[0])
	}
}

func TestIsAllowedMatchesRulePathAndLine(t *testing.T) {
	finding := scanner.Finding{
		RuleID: "database-url",
		Path:   "examples/leaky.env",
		Line:   4,
	}

	allowed := IsAllowed(finding, []Entry{
		{RuleID: "database-url", PathPattern: "examples/*.env", Line: 4},
	})
	if !allowed {
		t.Fatal("expected finding to be allowlisted")
	}
}

func TestIsAllowedRejectsWrongLine(t *testing.T) {
	finding := scanner.Finding{
		RuleID: "database-url",
		Path:   "examples/leaky.env",
		Line:   5,
	}

	allowed := IsAllowed(finding, []Entry{
		{RuleID: "database-url", PathPattern: "examples/*.env", Line: 4},
	})
	if allowed {
		t.Fatal("expected finding not to be allowlisted")
	}
}

func TestIsAllowedAtRejectsExpiredEntries(t *testing.T) {
	finding := scanner.Finding{RuleID: "database-url", Path: "examples/leaky.env", Line: 4}
	entries := []Entry{{
		RuleID:      "database-url",
		PathPattern: "examples/*.env",
		Line:        4,
		ExpiresAt:   mustDate(t, "2026-09-01"),
	}}

	if IsAllowedAt(finding, entries, mustDate(t, "2026-09-02")) {
		t.Fatal("expected expired entry not to allow finding")
	}
}

func TestValidateRejectsUnknownRuleID(t *testing.T) {
	err := Validate([]Entry{{RuleID: "not-a-rule", PathPattern: "examples/*.env"}}, []scanner.RuleMetadata{{ID: "github-token"}})
	if err == nil {
		t.Fatal("expected unknown rule ID to fail")
	}
}

func TestValidateRejectsDuplicateEntry(t *testing.T) {
	entries := []Entry{
		{RuleID: "github-token", PathPattern: "examples/*.env", Line: 4},
		{RuleID: "github-token", PathPattern: "examples/*.env", Line: 4},
	}

	err := Validate(entries, []scanner.RuleMetadata{{ID: "github-token"}})
	if err == nil {
		t.Fatal("expected duplicate entry to fail")
	}
}

func TestValidateAcceptsDistinctKnownEntries(t *testing.T) {
	entries := []Entry{
		{RuleID: "github-token", PathPattern: "examples/*.env", Line: 4},
		{RuleID: "private-key", PathPattern: "fixtures/key.pem"},
	}

	err := Validate(entries, []scanner.RuleMetadata{{ID: "github-token"}, {ID: "private-key"}})
	if err != nil {
		t.Fatalf("validate entries: %v", err)
	}
}

func TestValidateAtRejectsExpiredEntry(t *testing.T) {
	err := ValidateAt(
		[]Entry{{RuleID: "github-token", PathPattern: "examples/*.env", ExpiresAt: mustDate(t, "2026-09-01")}},
		[]scanner.RuleMetadata{{ID: "github-token"}},
		mustDate(t, "2026-09-02"),
	)
	if err == nil {
		t.Fatal("expected expired entry to fail validation")
	}
}

func mustDate(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.DateOnly, value)
	if err != nil {
		t.Fatalf("parse date %q: %v", value, err)
	}
	return parsed
}
