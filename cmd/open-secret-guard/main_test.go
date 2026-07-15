package main

import (
	"testing"

	"github.com/derekFixBug/open-secret-guard/internal/scanner"
)

func TestNormalizeScanArgsAllowsFlagsAfterPaths(t *testing.T) {
	args := normalizeScanArgs([]string{"examples", "-format", "sarif", "-allowlist", ".open-secret-guard.allowlist", "-min-severity", "high", "-include-hidden"})

	want := []string{"-format", "sarif", "-allowlist", ".open-secret-guard.allowlist", "-min-severity", "high", "-include-hidden", "examples"}
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
