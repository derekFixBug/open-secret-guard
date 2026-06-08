package sarif

import (
	"path/filepath"
	"sort"

	"github.com/derekFixBug/open-secret-guard/internal/scanner"
)

const schemaURL = "https://json.schemastore.org/sarif-2.1.0.json"

type Log struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool     `json:"tool"`
	Results []Result `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name"`
	ShortDescription Message         `json:"shortDescription"`
	FullDescription  Message         `json:"fullDescription"`
	DefaultConfig    ReportingConfig `json:"defaultConfiguration"`
}

type ReportingConfig struct {
	Level string `json:"level"`
}

type Message struct {
	Text string `json:"text"`
}

type Result struct {
	RuleID    string     `json:"ruleId"`
	Level     string     `json:"level"`
	Message   Message    `json:"message"`
	Locations []Location `json:"locations"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

func FromReport(report scanner.Report) Log {
	return Log{
		Version: "2.1.0",
		Schema:  schemaURL,
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           "open-secret-guard",
						InformationURI: "https://github.com/derekFixBug/open-secret-guard",
						Rules:          rulesFromFindings(report.Findings),
					},
				},
				Results: resultsFromFindings(report.Findings),
			},
		},
	}
}

func rulesFromFindings(findings []scanner.Finding) []Rule {
	seen := make(map[string]Rule)
	for _, finding := range findings {
		if _, exists := seen[finding.RuleID]; exists {
			continue
		}

		seen[finding.RuleID] = Rule{
			ID:   finding.RuleID,
			Name: finding.RuleID,
			ShortDescription: Message{
				Text: finding.Message,
			},
			FullDescription: Message{
				Text: finding.Message,
			},
			DefaultConfig: ReportingConfig{
				Level: severityToLevel(finding.Severity),
			},
		}
	}

	rules := make([]Rule, 0, len(seen))
	for _, rule := range seen {
		rules = append(rules, rule)
	}

	sort.Slice(rules, func(i, j int) bool {
		return rules[i].ID < rules[j].ID
	})

	return rules
}

func resultsFromFindings(findings []scanner.Finding) []Result {
	results := make([]Result, 0, len(findings))
	for _, finding := range findings {
		results = append(results, Result{
			RuleID: finding.RuleID,
			Level:  severityToLevel(finding.Severity),
			Message: Message{
				Text: finding.Message + " Matched value: " + finding.RedactedMatch,
			},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI: filepath.ToSlash(finding.Path),
						},
						Region: Region{
							StartLine:   finding.Line,
							StartColumn: finding.Column,
						},
					},
				},
			},
		})
	}
	return results
}

func severityToLevel(severity string) string {
	switch severity {
	case "critical", "high":
		return "error"
	case "medium":
		return "warning"
	default:
		return "note"
	}
}
