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
