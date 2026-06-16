package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFindsLikelySecrets(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, ".env")
	content := "GITHUB_TOKEN=" + "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz\n"

	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	report, err := Scan(Options{Paths: []string{target}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(report.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if report.Findings[0].RuleID != "github-token" {
		t.Fatalf("expected github-token, got %q", report.Findings[0].RuleID)
	}
}

func TestScanFindsProviderSpecificTokens(t *testing.T) {
	content := strings.Join([]string{
		"SLACK_BOT_TOKEN=" + slackTokenFixture(),
		"STRIPE_SECRET_KEY=" + stripeLiveKeyFixture(),
		"SENDGRID_API_KEY=" + sendgridKeyFixture(),
		"GOOGLE_API_KEY=" + googleAPIKeyFixture(),
		"OPENAI_API_KEY=" + openAIKeyFixture(),
		"ANTHROPIC_API_KEY=" + anthropicKeyFixture(),
	}, "\n")

	findings := scanContent("config.env", content)
	found := findingRuleIDs(findings)

	for _, ruleID := range []string{
		"slack-token",
		"stripe-live-secret-key",
		"sendgrid-api-key",
		"google-api-key",
		"openai-api-key",
		"anthropic-api-key",
	} {
		if !found[ruleID] {
			t.Fatalf("expected %s finding, got %#v", ruleID, findings)
		}
	}
}

func TestScanExcludesPaths(t *testing.T) {
	dir := t.TempDir()
	fixtureDir := filepath.Join(dir, "fixtures")
	if err := os.Mkdir(fixtureDir, 0o700); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fixtureDir, "demo.env"), []byte("token="+"fixture-secret-value"+"\n"), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	report, err := Scan(Options{Paths: []string{dir}, Exclude: []string{fixtureDir}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(report.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(report.Findings))
	}
}

func TestScanSkipsHiddenDirectoriesByDefault(t *testing.T) {
	dir := t.TempDir()
	hiddenDir := filepath.Join(dir, ".cache")
	if err := os.Mkdir(hiddenDir, 0o700); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(hiddenDir, "token.txt"), []byte(assignedTokenFixture()), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	report, err := Scan(Options{Paths: []string{dir}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(report.Findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(report.Findings))
	}
}

func TestScanIncludesHiddenDirectoriesWhenRequested(t *testing.T) {
	dir := t.TempDir()
	hiddenDir := filepath.Join(dir, ".cache")
	if err := os.Mkdir(hiddenDir, 0o700); err != nil {
		t.Fatalf("mkdir fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(hiddenDir, "token.txt"), []byte(assignedTokenFixture()), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	report, err := Scan(Options{Paths: []string{dir}, IncludeHidden: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(report.Findings) == 0 {
		t.Fatal("expected hidden directory finding")
	}
}

func assignedTokenFixture() string {
	return "tok" + "en=" + "super-secret-token-value\n"
}

func slackTokenFixture() string {
	return "xox" + "b-123456789012-123456789012-abcdefghijklmnopqrstuvwxyz"
}

func stripeLiveKeyFixture() string {
	return "sk_" + "live_" + "1234567890abcdefghijklmn"
}

func sendgridKeyFixture() string {
	return "S" + "G." + "abcdefghijklmnop.qrstuvwxyzABCDEF"
}

func googleAPIKeyFixture() string {
	return "AI" + "za" + "1234567890abcdefghijklmnopqrstuvwxy"
}

func openAIKeyFixture() string {
	return "s" + "k-" + "1234567890abcdefghijklmnopqrstuvwxyzABCDEF"
}

func anthropicKeyFixture() string {
	return "s" + "k-" + "ant-" + "1234567890abcdefghijklmnopqrstuvwxyz"
}

func findingRuleIDs(findings []Finding) map[string]bool {
	ruleIDs := make(map[string]bool)
	for _, finding := range findings {
		ruleIDs[finding.RuleID] = true
	}
	return ruleIDs
}
