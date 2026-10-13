package workflow

import (
	"strconv"
	"strings"
)

type GitHubActionsOptions struct {
	AllowlistPath  string
	MinSeverity    string
	FailOnSeverity string
	OnlyRules      string
	Provider       string
	GoVersion      string
	SARIFOutput    string
	JUnitOutput    string
	ScanPaths      string
	Exclude        string
	ExcludeFile    string
	TriggerPaths   string
	Branches       string
	Schedule       string
	ManualTrigger  bool
	MaxFileBytes   int
	MaxFindings    int
}

func GitHubActions(options GitHubActionsOptions) string {
	goVersion := strings.TrimSpace(options.GoVersion)
	if goVersion == "" {
		goVersion = "1.22"
	}

	scanArgs := []string{"go", "run", "./cmd/open-secret-guard", "scan"}
	for _, path := range splitCSV(options.ScanPaths) {
		scanArgs = append(scanArgs, shellQuote(path))
	}
	if len(scanArgs) == 4 {
		scanArgs = append(scanArgs, ".")
	}
	if strings.TrimSpace(options.Exclude) != "" {
		scanArgs = append(scanArgs, "-exclude", shellQuote(options.Exclude))
	}
	if strings.TrimSpace(options.ExcludeFile) != "" {
		scanArgs = append(scanArgs, "-exclude-file", shellQuote(options.ExcludeFile))
	}
	if strings.TrimSpace(options.AllowlistPath) != "" {
		scanArgs = append(scanArgs, "-allowlist", shellQuote(options.AllowlistPath))
	}
	if strings.TrimSpace(options.MinSeverity) != "" {
		scanArgs = append(scanArgs, "-min-severity", shellQuote(options.MinSeverity))
	}
	if strings.TrimSpace(options.OnlyRules) != "" {
		scanArgs = append(scanArgs, "-only-rules", shellQuote(options.OnlyRules))
	}
	if strings.TrimSpace(options.Provider) != "" {
		scanArgs = append(scanArgs, "-provider", shellQuote(options.Provider))
	}
	if options.MaxFileBytes > 0 {
		scanArgs = append(scanArgs, "-max-file-bytes", strconv.Itoa(options.MaxFileBytes))
	}
	if options.MaxFindings > 0 {
		scanArgs = append(scanArgs, "-max-findings", strconv.Itoa(options.MaxFindings))
	}
	if strings.TrimSpace(options.FailOnSeverity) != "" {
		scanArgs = append(scanArgs, "-fail-on-severity", shellQuote(options.FailOnSeverity))
	} else {
		scanArgs = append(scanArgs, "-fail-on-findings")
	}

	workflow := "name: Secret guard\n\n" + workflowTriggers(splitCSV(options.TriggerPaths), splitCSV(options.Branches), options.Schedule, options.ManualTrigger)

	if strings.TrimSpace(options.SARIFOutput) != "" {
		workflow += "permissions:\n" +
			"  contents: read\n" +
			"  security-events: write\n\n"
	}

	workflow += "jobs:\n" +
		"  scan:\n" +
		"    runs-on: ubuntu-latest\n" +
		"    steps:\n" +
		"      - uses: actions/checkout@v4\n" +
		"      - uses: actions/setup-go@v5\n" +
		"        with:\n" +
		"          go-version: " + yamlSingleQuote(goVersion) + "\n"

	if strings.TrimSpace(options.SARIFOutput) == "" && strings.TrimSpace(options.JUnitOutput) == "" {
		return workflow + "      - run: " + strings.Join(scanArgs, " ") + "\n"
	}

	if strings.TrimSpace(options.SARIFOutput) != "" {
		scanArgs = append(scanArgs, "-format", "sarif")
		return workflow +
			"      - run: " + strings.Join(scanArgs, " ") + " > " + shellQuote(options.SARIFOutput) + "\n" +
			"      - uses: github/codeql-action/upload-sarif@v3\n" +
			"        if: always()\n" +
			"        with:\n" +
			"          sarif_file: " + yamlSingleQuote(options.SARIFOutput) + "\n"
	}

	scanArgs = append(scanArgs, "-format", "junit")
	return workflow +
		"      - run: " + strings.Join(scanArgs, " ") + " > " + shellQuote(options.JUnitOutput) + "\n" +
		"      - uses: actions/upload-artifact@v4\n" +
		"        if: always()\n" +
		"        with:\n" +
		"          name: open-secret-guard-junit\n" +
		"          path: " + yamlSingleQuote(options.JUnitOutput) + "\n" +
		"          if-no-files-found: error\n"
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func yamlSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func splitCSV(value string) []string {
	var values []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			values = append(values, item)
		}
	}
	return values
}

func workflowTriggers(paths []string, branches []string, schedule string, manualTrigger bool) string {
	if len(branches) == 0 {
		branches = []string{"main"}
	}

	workflow := "on:\n"
	if schedule = strings.TrimSpace(schedule); schedule != "" {
		workflow += "  schedule:\n    - cron: " + yamlSingleQuote(schedule) + "\n"
	}
	if manualTrigger {
		workflow += "  workflow_dispatch:\n"
	}

	workflow += "  pull_request:\n    branches:\n"
	for _, branch := range branches {
		workflow += "      - " + yamlSingleQuote(branch) + "\n"
	}
	if len(paths) > 0 {
		workflow += "    paths:\n"
		for _, path := range paths {
			workflow += "      - " + yamlSingleQuote(path) + "\n"
		}
	}

	workflow += "  push:\n    branches:\n"
	for _, branch := range branches {
		workflow += "      - " + yamlSingleQuote(branch) + "\n"
	}
	if len(paths) > 0 {
		workflow += "    paths:\n"
		for _, path := range paths {
			workflow += "      - " + yamlSingleQuote(path) + "\n"
		}
	}

	return workflow + "\n"
}
