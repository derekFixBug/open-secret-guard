package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRulesReturnsPublicMetadata(t *testing.T) {
	rules := Rules()
	if len(rules) != len(defaultRules) {
		t.Fatalf("expected %d rules, got %d", len(defaultRules), len(rules))
	}

	for index, rule := range rules {
		if rule.ID != defaultRules[index].ID {
			t.Fatalf("rule %d: expected ID %q, got %q", index, defaultRules[index].ID, rule.ID)
		}
		if rule.Provider == "" || rule.Severity == "" || rule.Message == "" {
			t.Fatalf("rule %q has incomplete metadata: %#v", rule.ID, rule)
		}
	}
}

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

func TestScanDetectsEncryptedPrivateKey(t *testing.T) {
	findings := scanContent("key.pem", "-----BEGIN ENCRYPTED PRIVATE KEY-----\n")
	if len(findings) != 1 || findings[0].RuleID != "private-key" || findings[0].Severity != "critical" {
		t.Fatalf("expected critical private-key finding, got %#v", findings)
	}
	if findings := scanContent("public.pem", "-----BEGIN PUBLIC KEY-----\n"); len(findings) != 0 {
		t.Fatalf("public key should not be reported: %#v", findings)
	}
}

func TestScanReadsStandardInput(t *testing.T) {
	content := "GITHUB_TOKEN=" + githubTokenFixture() + "\n"
	report, err := scan(Options{Paths: []string{"-"}}, strings.NewReader(content))
	if err != nil {
		t.Fatalf("scan standard input: %v", err)
	}
	if report.ScannedFiles != 1 || len(report.Findings) != 1 {
		t.Fatalf("expected one scanned input and one finding, got %#v", report)
	}
	if report.Findings[0].Path != "stdin" || report.Findings[0].RuleID != "github-token" {
		t.Fatalf("unexpected stdin finding: %#v", report.Findings[0])
	}
}

func TestScanStandardInputRespectsMaximumFileSize(t *testing.T) {
	content := "GITHUB_TOKEN=" + githubTokenFixture() + "\n"
	report, err := scan(Options{
		Paths:        []string{"-"},
		MaxFileBytes: 8,
	}, strings.NewReader(content))
	if err != nil {
		t.Fatalf("scan oversized standard input: %v", err)
	}
	if report.ScannedFiles != 0 || report.SkippedFiles != 1 || len(report.Findings) != 0 {
		t.Fatalf("expected oversized input to be skipped, got %#v", report)
	}
}

func TestScanFindsProviderSpecificTokens(t *testing.T) {
	content := strings.Join([]string{
		"GITHUB_FINE_GRAINED=" + githubFineGrainedTokenFixture(),
		"GITLAB_TOKEN=" + gitlabTokenFixture(),
		"AZURE_DEVOPS_PAT=" + azureDevOpsPATFixture(),
		"SLACK_BOT_TOKEN=" + slackTokenFixture(),
		"SLACK_WEBHOOK_URL=" + slackWebhookFixture(),
		"DISCORD_BOT_TOKEN=" + discordBotTokenFixture(),
		"STRIPE_SECRET_KEY=" + stripeLiveKeyFixture(),
		"SENDGRID_API_KEY=" + sendgridKeyFixture(),
		"GOOGLE_API_KEY=" + googleAPIKeyFixture(),
		"OPENAI_API_KEY=" + openAIKeyFixture(),
		"ANTHROPIC_API_KEY=" + anthropicKeyFixture(),
		"HUGGINGFACE_TOKEN=" + huggingFaceTokenFixture(),
		"NPM_TOKEN=" + npmAccessTokenFixture(),
		"PYPI_TOKEN=" + pypiTokenFixture(),
		"DIGITALOCEAN_TOKEN=" + digitalOceanTokenFixture(),
		"SHOPIFY_ACCESS_TOKEN=" + shopifyAccessTokenFixture(),
		"TERRAFORM_TOKEN=" + terraformCloudTokenFixture(),
		"SESSION_TOKEN=" + jwtTokenFixture(),
	}, "\n")

	findings := scanContent("config.env", content)
	found := findingRuleIDs(findings)

	for _, ruleID := range []string{
		"github-token",
		"gitlab-token",
		"azure-devops-pat",
		"slack-token",
		"slack-webhook",
		"discord-bot-token",
		"stripe-live-secret-key",
		"sendgrid-api-key",
		"google-api-key",
		"openai-api-key",
		"anthropic-api-key",
		"huggingface-token",
		"npm-access-token",
		"pypi-token",
		"digitalocean-token",
		"shopify-access-token",
		"terraform-cloud-token",
		"jwt-token",
	} {
		if !found[ruleID] {
			t.Fatalf("expected %s finding, got %#v", ruleID, findings)
		}
	}
}

func TestScanSkipsInvalidAzureDevOpsPATLengths(t *testing.T) {
	findings := scanContent("config.env", strings.Repeat("a", 75)+"AZDO"+strings.Repeat("b", 4))
	if findingRuleIDs(findings)["azure-devops-pat"] {
		t.Fatalf("expected invalid Azure DevOps PAT length to be skipped, got %#v", findings)
	}
}

func TestScanFindsSecretOnLongLine(t *testing.T) {
	content := strings.Repeat("x", 1024*1024+128) + " GITHUB_TOKEN=" + githubTokenFixture()

	findings := scanContent("minified-config.json", content)
	if !findingRuleIDs(findings)["github-token"] {
		t.Fatalf("expected github-token in long line, got %#v", findings)
	}
}

func TestScanRespectsConfiguredMaximumFileSize(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.env")
	content := "GITHUB_TOKEN=" + githubTokenFixture() + "\n"
	if err := os.WriteFile(target, []byte(content), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	skipped, err := Scan(Options{Paths: []string{target}, MaxFileBytes: 20})
	if err != nil {
		t.Fatalf("scan with small limit: %v", err)
	}
	if skipped.ScannedFiles != 0 || skipped.SkippedFiles != 1 {
		t.Fatalf("expected oversized file to be skipped, got %#v", skipped)
	}

	report, err := Scan(Options{Paths: []string{target}, MaxFileBytes: len(content) + 1})
	if err != nil {
		t.Fatalf("scan with increased limit: %v", err)
	}
	if !findingRuleIDs(report.Findings)["github-token"] {
		t.Fatalf("expected github-token with increased limit, got %#v", report.Findings)
	}
}

func TestScanRejectsNegativeMaximumFileSize(t *testing.T) {
	if _, err := Scan(Options{MaxFileBytes: -1}); err == nil {
		t.Fatal("expected negative maximum file size to fail")
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

func TestScanExcludesFileNameGlob(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "demo.env"), []byte(assignedTokenFixture()), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("safe=true\n"), 0o600); err != nil {
		t.Fatalf("write safe file: %v", err)
	}

	report, err := Scan(Options{Paths: []string{dir}, Exclude: []string{"*.env"}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Findings) != 0 || report.SkippedFiles != 1 {
		t.Fatalf("expected one excluded file and no findings, got %#v", report)
	}
}

func TestScanExcludesExplicitFilePath(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "demo.env")
	if err := os.WriteFile(target, []byte(assignedTokenFixture()), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	report, err := Scan(Options{Paths: []string{target}, Exclude: []string{"*.env"}})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(report.Findings) != 0 || report.SkippedFiles != 1 {
		t.Fatalf("expected explicit file to be excluded, got %#v", report)
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

func slackWebhookFixture() string {
	return "https://hooks." + "slack.com/services/T01234567/B01234567/abcdefghijklmnopqrstuvwx"
}

func githubFineGrainedTokenFixture() string {
	return "github" + "_pat_" + "11AAAAAAA0abcdefghijklmnopqrstuvwxyzABCDEF"
}

func githubTokenFixture() string {
	return "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
}

func gitlabTokenFixture() string {
	return "gl" + "pat-1234567890abcdefghij"
}

func azureDevOpsPATFixture() string {
	return strings.Repeat("a", 75) + "AZDO" + "12345"
}

func pypiTokenFixture() string {
	return "pypi-" + "AgEIcHlwaS5vcmc" + "abcdefghijklmnopqrstuvwxyzABCDEF"
}

func digitalOceanTokenFixture() string {
	return "dop" + "_v1_" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}

func shopifyAccessTokenFixture() string {
	return "shp" + "at_" + "0123456789abcdef0123456789abcdef"
}

func discordBotTokenFixture() string {
	return "M" + "1234567890abcdefghijklm" + "." + "ABC123" + "." + "abcdefghijklmnopqrstuvwxyza"
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

func huggingFaceTokenFixture() string {
	return "h" + "f_" + "1234567890abcdefghijklmnopqrstuvwx"
}

func npmAccessTokenFixture() string {
	return "n" + "pm_" + "1234567890abcdefghijklmnopqrstuvwxyz"
}

func terraformCloudTokenFixture() string {
	return "1234567890abcd" + "." + "atlasv1" + "." +
		"1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12345"
}

func jwtTokenFixture() string {
	return "ey" + "JhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature123456"
}

func findingRuleIDs(findings []Finding) map[string]bool {
	ruleIDs := make(map[string]bool)
	for _, finding := range findings {
		ruleIDs[finding.RuleID] = true
	}
	return ruleIDs
}
