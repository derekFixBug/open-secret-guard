package sarif

import (
	"testing"

	"github.com/derekFixBug/open-secret-guard/internal/scanner"
)

func TestFromReportBuildsSARIFLog(t *testing.T) {
	log := FromReport(scanner.Report{
		Findings: []scanner.Finding{
			{
				RuleID:        "github-token",
				Severity:      "high",
				Path:          "examples/leaky.env",
				Line:          2,
				Column:        5,
				Message:       "GitHub tokens should be stored in a secret manager, not source files.",
				RedactedMatch: "ghp_********abcd",
			},
		},
	})

	if log.Version != "2.1.0" {
		t.Fatalf("expected SARIF version 2.1.0, got %q", log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected one run, got %d", len(log.Runs))
	}

	run := log.Runs[0]
	if run.Tool.Driver.Name != "open-secret-guard" {
		t.Fatalf("unexpected tool name %q", run.Tool.Driver.Name)
	}
	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("expected one rule, got %d", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 1 {
		t.Fatalf("expected one result, got %d", len(run.Results))
	}

	result := run.Results[0]
	if result.RuleID != "github-token" {
		t.Fatalf("expected github-token result, got %q", result.RuleID)
	}
	if result.Level != "error" {
		t.Fatalf("expected error level, got %q", result.Level)
	}
	if result.Locations[0].PhysicalLocation.ArtifactLocation.URI != "examples/leaky.env" {
		t.Fatalf("unexpected artifact URI %q", result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
}
