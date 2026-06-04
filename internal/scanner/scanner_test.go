package scanner

import (
	"os"
	"path/filepath"
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
