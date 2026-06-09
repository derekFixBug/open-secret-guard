package allowlist

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/derekFixBug/open-secret-guard/internal/scanner"
)

func TestLoadParsesEntries(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "allowlist.txt")
	content := "# known demo value\n" +
		"database-url examples/*.env 4\n" +
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
