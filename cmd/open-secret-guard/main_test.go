package main

import (
	"strings"
	"testing"

	"github.com/derekFixBug/open-secret-guard/internal/scanner"
)

func TestNormalizeScanArgsAllowsFlagsAfterPaths(t *testing.T) {
	args := normalizeScanArgs([]string{"examples", "-format", "sarif", "-allowlist", ".open-secret-guard.allowlist", "-min-severity", "high", "-only-rules", "github-token,private-key", "-include-hidden"})

	want := []string{"-format", "sarif", "-allowlist", ".open-secret-guard.allowlist", "-min-severity", "high", "-only-rules", "github-token,private-key", "-include-hidden", "examples"}
	if len(args) != len(want) {
		t.Fatalf("expected %d args, got %d: %#v", len(want), len(args), args)
	}

	for index := range want {
		if args[index] != want[index] {
			t.Fatalf("arg %d: expected %q, got %q", index, want[index], args[index])
		}
	}
}

func TestLoadAllowlistReturnsNilInterfaceWhenUnset(t *testing.T) {
	matcher, err := loadAllowlist("")
	if err != nil {
		t.Fatalf("load allowlist: %v", err)
	}
	if matcher != nil {
		t.Fatalf("expected nil matcher, got %#v", matcher)
	}
}

func TestNormalizeEnvExampleArgsAllowsOutputAfterPath(t *testing.T) {
	args := normalizeEnvExampleArgs([]string{".env", "-output", ".env.example"})

	want := []string{"-output", ".env.example", ".env"}
	if len(args) != len(want) {
		t.Fatalf("expected %d args, got %d: %#v", len(want), len(args), args)
	}

	for index := range want {
		if args[index] != want[index] {
			t.Fatalf("arg %d: expected %q, got %q", index, want[index], args[index])
		}
	}
}

func TestNormalizeInstallHookArgsAllowsFlagsInAnyOrder(t *testing.T) {
	args := normalizeInstallHookArgs([]string{"-allowlist", ".open-secret-guard.allowlist", "-output", ".git/hooks/pre-commit"})

	want := []string{"-allowlist", ".open-secret-guard.allowlist", "-output", ".git/hooks/pre-commit"}
	if len(args) != len(want) {
		t.Fatalf("expected %d args, got %d: %#v", len(want), len(args), args)
	}

	for index := range want {
		if args[index] != want[index] {
			t.Fatalf("arg %d: expected %q, got %q", index, want[index], args[index])
		}
	}
}

func TestRunRulesRejectsArguments(t *testing.T) {
	if err := runRules([]string{"extra"}); err == nil {
		t.Fatal("expected rules command to reject arguments")
	}
}

func TestRunRulesRejectsUnsupportedFormat(t *testing.T) {
	if err := runRules([]string{"-format", "yaml"}); err == nil {
		t.Fatal("expected rules command to reject unsupported format")
	}
}

func TestRunGitHubActionRejectsArguments(t *testing.T) {
	if err := runGitHubAction([]string{"extra"}); err == nil {
		t.Fatal("expected github-action command to reject arguments")
	}
}

func TestMarkdownCellEscapesTableContent(t *testing.T) {
	got := markdownCell("first|second\nthird")
	if got != "first\\|second third" {
		t.Fatalf("unexpected markdown cell %q", got)
	}
}

func TestSummaryReportIncludesCountsWithoutMatches(t *testing.T) {
	report := scanner.Report{
		ScannedFiles: 4,
		SkippedFiles: 1,
		Findings: []scanner.Finding{
			{RuleID: "private-key", Severity: "critical", RedactedMatch: "never-print-this"},
			{RuleID: "github-token", Severity: "high", RedactedMatch: "never-print-this"},
			{RuleID: "github-token", Severity: "high", RedactedMatch: "never-print-this"},
		},
	}

	summary := summaryText(report)
	for _, item := range []string{
		"Scanned files: 4",
		"Skipped files: 1",
		"Findings: 3",
		"critical: 1",
		"high: 2",
		"github-token: 2",
		"private-key: 1",
	} {
		if !strings.Contains(summary, item) {
			t.Fatalf("expected summary to contain %q:\n%s", item, summary)
		}
	}
	if strings.Contains(summary, "never-print-this") {
		t.Fatalf("summary should not contain redacted matches:\n%s", summary)
	}
}

func TestFilterRulesBySeverityKeepsRulesAtOrAboveThreshold(t *testing.T) {
	rules := []scanner.RuleMetadata{
		{ID: "assigned-secret", Severity: "medium"},
		{ID: "github-token", Severity: "high"},
		{ID: "private-key", Severity: "critical"},
	}

	filtered, err := filterRulesBySeverity(rules, "high")
	if err != nil {
		t.Fatalf("filter rules: %v", err)
	}

	if len(filtered) != 2 {
		t.Fatalf("expected 2 rules, got %d: %#v", len(filtered), filtered)
	}
	if filtered[0].ID != "github-token" || filtered[1].ID != "private-key" {
		t.Fatalf("unexpected filtered rules: %#v", filtered)
	}
}

func TestFilterRulesBySeverityRejectsUnsupportedLevel(t *testing.T) {
	if _, err := filterRulesBySeverity(nil, "urgent"); err == nil {
		t.Fatal("expected unsupported severity to fail")
	}
}

func TestFilterReportBySeverityKeepsFindingsAtOrAboveThreshold(t *testing.T) {
	report := scanner.Report{
		Findings: []scanner.Finding{
			{RuleID: "assigned-secret", Severity: "medium"},
			{RuleID: "github-token", Severity: "high"},
			{RuleID: "private-key", Severity: "critical"},
		},
	}

	filtered, err := filterReportBySeverity(report, "high")
	if err != nil {
		t.Fatalf("filter report: %v", err)
	}

	if len(filtered.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %#v", len(filtered.Findings), filtered.Findings)
	}
	if filtered.Findings[0].RuleID != "github-token" || filtered.Findings[1].RuleID != "private-key" {
		t.Fatalf("unexpected filtered findings: %#v", filtered.Findings)
	}
}

func TestFilterReportBySeverityRejectsUnsupportedLevel(t *testing.T) {
	if _, err := filterReportBySeverity(scanner.Report{}, "urgent"); err == nil {
		t.Fatal("expected unsupported severity to fail")
	}
}

func TestFilterReportByRulesKeepsMatchingRuleIDs(t *testing.T) {
	report := scanner.Report{
		Findings: []scanner.Finding{
			{RuleID: "assigned-secret", Severity: "medium"},
			{RuleID: "github-token", Severity: "high"},
			{RuleID: "private-key", Severity: "critical"},
		},
	}

	filtered, err := filterReportByRules(report, "github-token, private-key")
	if err != nil {
		t.Fatalf("filter report: %v", err)
	}

	if len(filtered.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %#v", len(filtered.Findings), filtered.Findings)
	}
	if filtered.Findings[0].RuleID != "github-token" || filtered.Findings[1].RuleID != "private-key" {
		t.Fatalf("unexpected filtered findings: %#v", filtered.Findings)
	}
}

func TestFilterReportByRulesRejectsUnknownRuleID(t *testing.T) {
	if _, err := filterReportByRules(scanner.Report{}, "not-a-real-rule"); err == nil {
		t.Fatal("expected unknown rule ID to fail")
	}
}

func TestFilterReportByRulesAllowsEmptyFilter(t *testing.T) {
	report := scanner.Report{
		Findings: []scanner.Finding{
			{RuleID: "github-token", Severity: "high"},
		},
	}

	filtered, err := filterReportByRules(report, "")
	if err != nil {
		t.Fatalf("filter report: %v", err)
	}
	if len(filtered.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %#v", len(filtered.Findings), filtered.Findings)
	}
}
