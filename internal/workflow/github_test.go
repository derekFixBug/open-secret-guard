package workflow

import (
	"strings"
	"testing"
)

func TestGitHubActionsUsesDefaults(t *testing.T) {
	content := GitHubActions(GitHubActionsOptions{})

	required := []string{
		"name: Secret guard",
		"go-version: '1.22'",
		"go run ./cmd/open-secret-guard scan . -fail-on-findings",
	}
	for _, item := range required {
		if !strings.Contains(content, item) {
			t.Fatalf("expected workflow to contain %q:\n%s", item, content)
		}
	}
}

func TestGitHubActionsIncludesScanOptions(t *testing.T) {
	content := GitHubActions(GitHubActionsOptions{
		AllowlistPath: ".open-secret-guard.allowlist",
		MinSeverity:   "high",
		OnlyRules:     "github-token,private-key",
		GoVersion:     "1.23",
	})

	required := []string{
		"go-version: '1.23'",
		"-allowlist '.open-secret-guard.allowlist'",
		"-min-severity 'high'",
		"-only-rules 'github-token,private-key'",
		"-fail-on-findings",
	}
	for _, item := range required {
		if !strings.Contains(content, item) {
			t.Fatalf("expected workflow to contain %q:\n%s", item, content)
		}
	}
}

func TestGitHubActionsCanUploadSARIF(t *testing.T) {
	content := GitHubActions(GitHubActionsOptions{
		SARIFOutput: "reports/open-secret-guard.sarif",
	})

	required := []string{
		"permissions:\n  contents: read\n  security-events: write",
		"scan . -fail-on-findings -format sarif > 'reports/open-secret-guard.sarif'",
		"- uses: github/codeql-action/upload-sarif@v3",
		"if: always()",
		"sarif_file: 'reports/open-secret-guard.sarif'",
	}
	for _, item := range required {
		if !strings.Contains(content, item) {
			t.Fatalf("expected workflow to contain %q:\n%s", item, content)
		}
	}
}

func TestGitHubActionsSupportsTriggerAndScanPaths(t *testing.T) {
	content := GitHubActions(GitHubActionsOptions{
		TriggerPaths: "cmd/**, internal/**",
		ScanPaths:    "cmd,internal",
	})

	required := []string{
		"pull_request:\n    paths:\n      - 'cmd/**'\n      - 'internal/**'",
		"push:\n    branches: [main]\n    paths:\n      - 'cmd/**'\n      - 'internal/**'",
		"go run ./cmd/open-secret-guard scan 'cmd' 'internal' -fail-on-findings",
	}
	for _, item := range required {
		if !strings.Contains(content, item) {
			t.Fatalf("expected workflow to contain %q:\n%s", item, content)
		}
	}
}

func TestGitHubActionsIncludesConfiguredMaximumFileSize(t *testing.T) {
	content := GitHubActions(GitHubActionsOptions{MaxFileBytes: 8 * 1024 * 1024})
	if !strings.Contains(content, "-max-file-bytes 8388608 -fail-on-findings") {
		t.Fatalf("expected workflow to include configured file size:\n%s", content)
	}
}
