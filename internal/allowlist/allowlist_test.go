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

func TestValidateRejectsMalformedPathGlob(t *testing.T) {
	err := Validate(
		[]Entry{{RuleID: "github-token", PathPattern: "examples/[*.env"}},
		[]scanner.RuleMetadata{{ID: "github-token"}},
	)
	if err == nil {
		t.Fatal("expected malformed path glob to fail validation")
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

func TestExpiringWithinIncludesOnlyActiveEntriesInWindow(t *testing.T) {
	now := mustDate(t, "2026-09-03")
	entries := []Entry{
		{RuleID: "github-token", PathPattern: "expires-today", ExpiresAt: mustDate(t, "2026-09-03")},
		{RuleID: "private-key", PathPattern: "expires-soon", ExpiresAt: mustDate(t, "2026-09-06")},
		{RuleID: "database-url", PathPattern: "expires-later", ExpiresAt: mustDate(t, "2026-09-07")},
		{RuleID: "jwt-token", PathPattern: "expired", ExpiresAt: mustDate(t, "2026-09-02")},
		{RuleID: "slack-token", PathPattern: "no-expiry"},
	}

	expiring := ExpiringWithin(entries, now, 3)
	if len(expiring) != 2 {
		t.Fatalf("expected 2 expiring entries, got %#v", expiring)
	}
	if expiring[0].PathPattern != "expires-today" || expiring[1].PathPattern != "expires-soon" {
		t.Fatalf("unexpected expiring entries: %#v", expiring)
	}
}

func TestExpiringAfterIncludesOnlyEntriesBeyondMaximumWindow(t *testing.T) {
	now := mustDate(t, "2026-09-03")
	entries := []Entry{
		{RuleID: "github-token", PathPattern: "today", ExpiresAt: mustDate(t, "2026-09-03")},
		{RuleID: "github-token", PathPattern: "boundary", ExpiresAt: mustDate(t, "2026-09-10")},
		{RuleID: "github-token", PathPattern: "too-late", ExpiresAt: mustDate(t, "2026-09-11")},
		{RuleID: "github-token", PathPattern: "no-expiry"},
	}

	got := ExpiringAfter(entries, now, 7)
	if len(got) != 1 || got[0].PathPattern != "too-late" {
		t.Fatalf("expected only entries beyond the seven-day window, got %#v", got)
	}
}

func TestExpiringWithinRejectsNegativeWindow(t *testing.T) {
	entries := []Entry{{RuleID: "github-token", PathPattern: "example", ExpiresAt: mustDate(t, "2026-09-03")}}
	if got := ExpiringWithin(entries, mustDate(t, "2026-09-03"), -1); len(got) != 0 {
		t.Fatalf("expected no entries for disabled window, got %#v", got)
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
