package main

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/derekFixBug/open-secret-guard/internal/allowlist"
	"github.com/derekFixBug/open-secret-guard/internal/scanner"
)

func TestNormalizeScanArgsAllowsFlagsAfterPaths(t *testing.T) {
	args := normalizeScanArgs([]string{"examples", "-format", "sarif", "-allowlist", ".open-secret-guard.allowlist", "-min-severity", "high", "-fail-on-severity", "critical", "-only-rules", "github-token,private-key", "-provider", "github,generic", "-max-file-bytes", "3145728", "-max-findings", "20", "-expires-on", "2026-12-31", "-exclude-file", ".open-secret-guard.exclude", "-include-hidden"})

	want := []string{"-format", "sarif", "-allowlist", ".open-secret-guard.allowlist", "-min-severity", "high", "-fail-on-severity", "critical", "-only-rules", "github-token,private-key", "-provider", "github,generic", "-max-file-bytes", "3145728", "-max-findings", "20", "-expires-on", "2026-12-31", "-exclude-file", ".open-secret-guard.exclude", "-include-hidden", "examples"}
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

func TestLoadExcludePatternsSkipsCommentsAndEmptyLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "exclude.txt")
	content := "# generated files\n\n*.env\n fixtures \n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write exclude patterns: %v", err)
	}

	patterns, err := loadExcludePatterns(path)
	if err != nil {
		t.Fatalf("load exclude patterns: %v", err)
	}
	if strings.Join(patterns, ",") != "*.env,fixtures" {
		t.Fatalf("unexpected patterns: %#v", patterns)
	}
}

func TestLoadExcludePatternsReturnsNilWhenUnset(t *testing.T) {
	patterns, err := loadExcludePatterns("")
	if err != nil || patterns != nil {
		t.Fatalf("expected no patterns, got %#v, %v", patterns, err)
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

func TestNormalize1PasswordTemplateArgsAllowsFlagsAfterPath(t *testing.T) {
	args := normalize1PasswordTemplateArgs([]string{".env.example", "-vault", "Open Source", "-item", "open-secret-guard", "-output", ".env.1password", "-preserve-references"})
	want := []string{"-vault", "Open Source", "-item", "open-secret-guard", "-output", ".env.1password", "-preserve-references", ".env.example"}
	if len(args) != len(want) {
		t.Fatalf("expected %d args, got %d: %#v", len(want), len(args), args)
	}
	for index := range want {
		if args[index] != want[index] {
			t.Fatalf("arg %d: expected %q, got %q", index, want[index], args[index])
		}
	}
}

func TestRun1PasswordTemplateRequiresVaultAndItem(t *testing.T) {
	if err := run1PasswordTemplate([]string{".env.example", "-item", "project"}); err == nil {
		t.Fatal("expected missing vault to fail")
	}
	if err := run1PasswordTemplate([]string{".env.example", "-vault", "Open Source"}); err == nil {
		t.Fatal("expected missing item to fail")
	}
}

func TestNormalizeInstallHookArgsAllowsFlagsInAnyOrder(t *testing.T) {
	args := normalizeInstallHookArgs([]string{"-allowlist", ".open-secret-guard.allowlist", "-output", ".git/hooks/pre-commit", "-min-severity", "high"})

	want := []string{"-allowlist", ".open-secret-guard.allowlist", "-output", ".git/hooks/pre-commit", "-min-severity", "high"}
	if len(args) != len(want) {
		t.Fatalf("expected %d args, got %d: %#v", len(want), len(args), args)
	}

	for index := range want {
		if args[index] != want[index] {
			t.Fatalf("arg %d: expected %q, got %q", index, want[index], args[index])
		}
	}
}

func TestRunInstallHookRejectsUnsupportedMinimumSeverity(t *testing.T) {
	if err := runInstallHook([]string{"-min-severity", "urgent"}); err == nil {
		t.Fatal("expected unsupported minimum severity to fail")
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

func TestRunGitHubActionRejectsNegativeMaximumFileSize(t *testing.T) {
	if err := runGitHubAction([]string{"-max-file-bytes", "-1"}); err == nil {
		t.Fatal("expected negative maximum file size to fail")
	}
}

func TestRunGitHubActionRejectsNegativeMaximumFindings(t *testing.T) {
	if err := runGitHubAction([]string{"-max-findings", "-1"}); err == nil {
		t.Fatal("expected negative maximum findings to fail")
	}
}

func TestRunGitHubActionRejectsMultipleReportOutputs(t *testing.T) {
	if err := runGitHubAction([]string{"-sarif-output", "results.sarif", "-junit-output", "results.xml"}); err == nil {
		t.Fatal("expected conflicting report outputs to fail")
	}
}

func TestRunGitHubActionRejectsUnsupportedFailureSeverity(t *testing.T) {
	if err := runGitHubAction([]string{"-fail-on-severity", "urgent"}); err == nil {
		t.Fatal("expected unsupported failure severity to fail")
	}
}

func TestRunAllowlistCheckRequiresOnePath(t *testing.T) {
	if err := runAllowlistCheck(nil); err == nil {
		t.Fatal("expected allowlist-check to require a path")
	}
}

func TestNormalizeAllowlistCheckArgsAllowsFlagAfterPath(t *testing.T) {
	args := normalizeAllowlistCheckArgs([]string{".open-secret-guard.allowlist", "-expires-within", "30", "-format", "json"})
	want := []string{"-expires-within", "30", "-format", "json", ".open-secret-guard.allowlist"}
	if len(args) != len(want) {
		t.Fatalf("expected %d args, got %d: %#v", len(want), len(args), args)
	}
	for index := range want {
		if args[index] != want[index] {
			t.Fatalf("arg %d: expected %q, got %q", index, want[index], args[index])
		}
	}
}

func TestRunAllowlistCheckRejectsInvalidExpiryWindow(t *testing.T) {
	if err := runAllowlistCheck([]string{"-expires-within", "-2", ".open-secret-guard.allowlist"}); err == nil {
		t.Fatal("expected invalid expiry window to fail")
	}
}

func TestRunAllowlistCheckRejectsUnsupportedFormat(t *testing.T) {
	if err := runAllowlistCheck([]string{"-format", "yaml", ".open-secret-guard.allowlist"}); err == nil {
		t.Fatal("expected unsupported format to fail")
	}
}

func TestAllowlistCheckReportJSONIncludesOnlyReviewableFields(t *testing.T) {
	expiresAt := time.Date(2026, time.December, 31, 0, 0, 0, 0, time.UTC)
	entry := allowlist.Entry{RuleID: "github-token", PathPattern: "config/example.env", Line: 4, ExpiresAt: expiresAt}
	output, err := allowlistCheckReportJSON(
		[]allowlist.Entry{entry},
		[]allowlist.Entry{entry},
	)
	if err != nil {
		t.Fatalf("build JSON report: %v", err)
	}

	var report allowlistCheckReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("decode JSON report: %v\n%s", err, output)
	}
	if report.Entries != 1 || len(report.Expiring) != 1 || report.Expiring[0].PathPattern != "config/example.env" {
		t.Fatalf("unexpected JSON report: %#v", report)
	}
	if strings.Contains(output, "RedactedMatch") || strings.Contains(output, "super-secret") {
		t.Fatalf("JSON report must not contain secret values: %s", output)
	}
}

func TestAllowlistSuggestionTextIncludesOnlyReviewableFields(t *testing.T) {
	report := scanner.Report{Findings: []scanner.Finding{
		{RuleID: "github-token", Path: "config/.env", Line: 4, RedactedMatch: "should-not-appear"},
		{RuleID: "private-key", Path: "secrets/key.pem", Line: 1, RedactedMatch: "should-not-appear"},
	}}

	suggestions := allowlistSuggestionText(report, "")
	for _, item := range []string{
		"# Review every entry before adding it to an allowlist.",
		"github-token config/.env 4",
		"private-key secrets/key.pem 1",
	} {
		if !strings.Contains(suggestions, item) {
			t.Fatalf("expected suggestions to contain %q:\n%s", item, suggestions)
		}
	}
	if strings.Contains(suggestions, "should-not-appear") {
		t.Fatalf("suggestions should not contain matches:\n%s", suggestions)
	}
}

func TestAllowlistSuggestionTextExplainsNoFindings(t *testing.T) {
	suggestions := allowlistSuggestionText(scanner.Report{}, "")
	if !strings.Contains(suggestions, "# No findings to suggest.") {
		t.Fatalf("expected no-findings message:\n%s", suggestions)
	}
}

func TestAllowlistSuggestionTextAddsRequestedExpiry(t *testing.T) {
	report := scanner.Report{Findings: []scanner.Finding{{RuleID: "github-token", Path: "config/example.env", Line: 4}}}
	suggestions := allowlistSuggestionText(report, "2026-12-31")
	for _, item := range []string{
		"# Suggested entries expire on 2026-12-31.",
		"github-token config/example.env 4 2026-12-31",
	} {
		if !strings.Contains(suggestions, item) {
			t.Fatalf("expected suggestions to contain %q:\n%s", item, suggestions)
		}
	}
}

func TestParseCandidateExpiryRejectsInvalidAndPastDates(t *testing.T) {
	now := time.Date(2026, time.September, 7, 12, 0, 0, 0, time.UTC)
	for _, value := range []string{"2026/12/31", "2026-09-06"} {
		if _, err := parseCandidateExpiry(value, now); err == nil {
			t.Fatalf("expected %q to fail", value)
		}
	}
	if got, err := parseCandidateExpiry("2026-09-07", now); err != nil || got != "2026-09-07" {
		t.Fatalf("expected today to be accepted, got %q, %v", got, err)
	}
}

func TestMarkdownCellEscapesTableContent(t *testing.T) {
	got := markdownCell("first|second\nthird")
	if got != "first\\|second third" {
		t.Fatalf("unexpected markdown cell %q", got)
	}
}

func TestPluralSuffix(t *testing.T) {
	if got := pluralSuffix(1); got != "y" {
		t.Fatalf("expected singular suffix, got %q", got)
	}
	if got := pluralSuffix(2); got != "ies" {
		t.Fatalf("expected plural suffix, got %q", got)
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

func TestMarkdownReportIncludesRuleMetadataWithoutMatches(t *testing.T) {
	report := scanner.Report{Findings: []scanner.Finding{
		{
			RuleID:        "github-token",
			Severity:      "high",
			Path:          "config|example.env",
			Line:          4,
			Message:       "GitHub tokens should be stored in a secret manager, not source files.",
			RedactedMatch: "never-print-this",
		},
	}}

	markdown := markdownReportText(report)
	for _, item := range []string{
		"| Path | Line | Rule | Provider | Severity | Description |",
		"`config\\|example.env`",
		"| 4 | `github-token` | github | high |",
	} {
		if !strings.Contains(markdown, item) {
			t.Fatalf("expected markdown report to contain %q:\n%s", item, markdown)
		}
	}
	if strings.Contains(markdown, "never-print-this") {
		t.Fatalf("markdown report should not contain matches:\n%s", markdown)
	}
}

func TestMarkdownReportExplainsNoFindings(t *testing.T) {
	if got := markdownReportText(scanner.Report{}); got != "No likely secrets found.\n" {
		t.Fatalf("unexpected no-findings report %q", got)
	}
}

func TestCSVReportIncludesMetadataWithoutMatches(t *testing.T) {
	report := scanner.Report{Findings: []scanner.Finding{{
		RuleID:        "github-token",
		Severity:      "high",
		Path:          "config,example.env",
		Line:          4,
		Column:        7,
		Message:       "GitHub tokens should be stored in a secret manager, not source files.",
		RedactedMatch: "never-print-this",
	}}}

	output, err := csvReportText(report)
	if err != nil {
		t.Fatalf("create CSV report: %v", err)
	}
	rows, err := csv.NewReader(strings.NewReader(output)).ReadAll()
	if err != nil {
		t.Fatalf("read CSV report: %v\n%s", err, output)
	}
	if len(rows) != 2 || strings.Join(rows[0], ",") != "path,line,column,rule,provider,severity,description" {
		t.Fatalf("unexpected CSV rows: %#v", rows)
	}
	if strings.Join(rows[1], "|") != "config,example.env|4|7|github-token|github|high|GitHub tokens should be stored in a secret manager, not source files." {
		t.Fatalf("unexpected CSV finding: %#v", rows[1])
	}
	if strings.Contains(output, "never-print-this") {
		t.Fatalf("CSV report must not include matched values: %s", output)
	}
}

func TestCSVRulesIncludesSelectedMetadata(t *testing.T) {
	output, err := csvRulesText([]scanner.RuleMetadata{{
		ID:       "github-token",
		Provider: "github",
		Severity: "high",
		Message:  "GitHub tokens should be stored in a secret manager, not source files.",
	}})
	if err != nil {
		t.Fatalf("create CSV rules: %v", err)
	}
	rows, err := csv.NewReader(strings.NewReader(output)).ReadAll()
	if err != nil {
		t.Fatalf("read CSV rules: %v\n%s", err, output)
	}
	if len(rows) != 2 || strings.Join(rows[0], ",") != "rule,provider,severity,description" {
		t.Fatalf("unexpected CSV rules: %#v", rows)
	}
	if strings.Join(rows[1], "|") != "github-token|github|high|GitHub tokens should be stored in a secret manager, not source files." {
		t.Fatalf("unexpected CSV rule: %#v", rows[1])
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

func TestFilterRulesByProviderKeepsSelectedProviders(t *testing.T) {
	rules := []scanner.RuleMetadata{
		{ID: "github-token", Provider: "github", Severity: "high"},
		{ID: "gitlab-token", Provider: "gitlab", Severity: "high"},
		{ID: "private-key", Provider: "generic", Severity: "critical"},
	}

	filtered, err := filterRulesByProvider(rules, "GitHub, generic")
	if err != nil {
		t.Fatalf("filter rules: %v", err)
	}
	if len(filtered) != 2 || filtered[0].ID != "github-token" || filtered[1].ID != "private-key" {
		t.Fatalf("unexpected filtered rules: %#v", filtered)
	}
}

func TestFilterRulesByProviderRejectsUnknownProvider(t *testing.T) {
	if _, err := filterRulesByProvider(scanner.Rules(), "not-a-provider"); err == nil {
		t.Fatal("expected unknown provider to fail")
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

func TestHasFindingsAtOrAboveUsesFailureThreshold(t *testing.T) {
	report := scanner.Report{Findings: []scanner.Finding{
		{RuleID: "assigned-secret", Severity: "medium"},
		{RuleID: "github-token", Severity: "high"},
	}}
	if !hasFindingsAtOrAbove(report, "high") {
		t.Fatal("expected high finding to meet high threshold")
	}
	if hasFindingsAtOrAbove(report, "critical") {
		t.Fatal("did not expect findings to meet critical threshold")
	}
}

func TestRunScanRejectsUnsupportedFailureSeverity(t *testing.T) {
	if err := runScan([]string{"-fail-on-severity", "urgent"}); err == nil {
		t.Fatal("expected unsupported failure severity to fail")
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

func TestFilterReportByProviderKeepsSelectedProviders(t *testing.T) {
	report := scanner.Report{Findings: []scanner.Finding{
		{RuleID: "github-token", Severity: "high"},
		{RuleID: "gitlab-token", Severity: "high"},
		{RuleID: "private-key", Severity: "critical"},
	}}

	filtered, err := filterReportByProvider(report, "github,generic")
	if err != nil {
		t.Fatalf("filter report: %v", err)
	}
	if len(filtered.Findings) != 2 || filtered.Findings[0].RuleID != "github-token" || filtered.Findings[1].RuleID != "private-key" {
		t.Fatalf("unexpected filtered report: %#v", filtered)
	}
}

func TestFilterReportByProviderRejectsUnknownProvider(t *testing.T) {
	if _, err := filterReportByProvider(scanner.Report{}, "not-a-provider"); err == nil {
		t.Fatal("expected unknown provider to fail")
	}
}

func TestLimitReportFindingsTruncatesSortedFindings(t *testing.T) {
	report := scanner.Report{Findings: []scanner.Finding{
		{RuleID: "github-token", Path: "config/.env", Line: 3},
		{RuleID: "gitlab-token", Path: "config/.env", Line: 7},
		{RuleID: "private-key", Path: "secrets/key.pem", Line: 1},
	}}

	limited, err := limitReportFindings(report, 2)
	if err != nil {
		t.Fatalf("limit report: %v", err)
	}
	if len(limited.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %#v", len(limited.Findings), limited.Findings)
	}
	if limited.Findings[0].RuleID != "github-token" || limited.Findings[1].RuleID != "gitlab-token" {
		t.Fatalf("expected the first findings in sorted order, got %#v", limited.Findings)
	}
}

func TestLimitReportFindingsKeepsAllWhenUnset(t *testing.T) {
	report := scanner.Report{Findings: []scanner.Finding{
		{RuleID: "github-token"},
		{RuleID: "private-key"},
	}}

	limited, err := limitReportFindings(report, 0)
	if err != nil {
		t.Fatalf("limit report: %v", err)
	}
	if len(limited.Findings) != 2 {
		t.Fatalf("expected all findings, got %d", len(limited.Findings))
	}
}

func TestLimitReportFindingsKeepsShorterReports(t *testing.T) {
	report := scanner.Report{Findings: []scanner.Finding{
		{RuleID: "github-token"},
	}}

	limited, err := limitReportFindings(report, 5)
	if err != nil {
		t.Fatalf("limit report: %v", err)
	}
	if len(limited.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(limited.Findings))
	}
}

func TestRunScanRejectsNegativeMaxFindings(t *testing.T) {
	if err := runScan([]string{".", "-max-findings", "-1"}); err == nil {
		t.Fatal("expected negative max-findings to fail")
	}
}

func TestRunAllowlistSuggestRejectsNegativeMaxFindings(t *testing.T) {
	if err := runAllowlistSuggest([]string{".", "-max-findings", "-1"}); err == nil {
		t.Fatal("expected negative max-findings to fail")
	}
}
