package workflow

import (
	"strconv"
	"strings"
)

type GitHubActionsOptions struct {
	AllowlistPath string
	MinSeverity   string
	OnlyRules     string
	GoVersion     string
	SARIFOutput   string
	ScanPaths     string
	TriggerPaths  string
	MaxFileBytes  int
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
	if strings.TrimSpace(options.AllowlistPath) != "" {
		scanArgs = append(scanArgs, "-allowlist", shellQuote(options.AllowlistPath))
	}
	if strings.TrimSpace(options.MinSeverity) != "" {
		scanArgs = append(scanArgs, "-min-severity", shellQuote(options.MinSeverity))
	}
	if strings.TrimSpace(options.OnlyRules) != "" {
		scanArgs = append(scanArgs, "-only-rules", shellQuote(options.OnlyRules))
	}
	if options.MaxFileBytes > 0 {
		scanArgs = append(scanArgs, "-max-file-bytes", strconv.Itoa(options.MaxFileBytes))
	}
	scanArgs = append(scanArgs, "-fail-on-findings")

	workflow := "name: Secret guard\n\n" + workflowTriggers(splitCSV(options.TriggerPaths))

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

	if strings.TrimSpace(options.SARIFOutput) == "" {
		return workflow + "      - run: " + strings.Join(scanArgs, " ") + "\n"
	}

	scanArgs = append(scanArgs, "-format", "sarif")
	return workflow +
		"      - run: " + strings.Join(scanArgs, " ") + " > " + shellQuote(options.SARIFOutput) + "\n" +
		"      - uses: github/codeql-action/upload-sarif@v3\n" +
		"        if: always()\n" +
		"        with:\n" +
		"          sarif_file: " + yamlSingleQuote(options.SARIFOutput) + "\n"
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

func workflowTriggers(paths []string) string {
	workflow := "on:\n  pull_request:\n"
	if len(paths) > 0 {
		workflow += "    paths:\n"
		for _, path := range paths {
			workflow += "      - " + yamlSingleQuote(path) + "\n"
		}
	}

	workflow += "  push:\n    branches: [main]\n"
	if len(paths) > 0 {
		workflow += "    paths:\n"
		for _, path := range paths {
			workflow += "      - " + yamlSingleQuote(path) + "\n"
		}
	}

	return workflow + "\n"
}
