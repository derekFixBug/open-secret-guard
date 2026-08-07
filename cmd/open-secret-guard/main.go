package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/derekFixBug/open-secret-guard/internal/allowlist"
	"github.com/derekFixBug/open-secret-guard/internal/envexample"
	"github.com/derekFixBug/open-secret-guard/internal/hook"
	"github.com/derekFixBug/open-secret-guard/internal/sarif"
	"github.com/derekFixBug/open-secret-guard/internal/scanner"
	"github.com/derekFixBug/open-secret-guard/internal/workflow"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "open-secret-guard: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		printUsage()
		return nil
	}

	switch args[0] {
	case "allowlist-check":
		return runAllowlistCheck(args[1:])
	case "allowlist-suggest":
		return runAllowlistSuggest(args[1:])
	case "env-example":
		return runEnvExample(args[1:])
	case "github-action":
		return runGitHubAction(args[1:])
	case "install-hook":
		return runInstallHook(args[1:])
	case "rules":
		return runRules(args[1:])
	case "scan":
		return runScan(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runAllowlistCheck(args []string) error {
	if len(args) != 1 {
		return errors.New("allowlist-check requires exactly one allowlist file")
	}

	entries, err := allowlist.Load(args[0])
	if err != nil {
		return err
	}
	if err := allowlist.Validate(entries, scanner.Rules()); err != nil {
		return err
	}

	fmt.Printf("Allowlist is valid: %d entr%s.\n", len(entries), pluralSuffix(len(entries)))
	return nil
}

func runAllowlistSuggest(args []string) error {
	flags := flag.NewFlagSet("allowlist-suggest", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	includeHidden := flags.Bool("include-hidden", false, "scan hidden files and directories")
	exclude := flags.String("exclude", "", "comma-separated file or directory patterns to skip")
	minSeverity := flags.String("min-severity", "", "minimum severity to include: low, medium, high, or critical")
	onlyRules := flags.String("only-rules", "", "comma-separated rule IDs to include")

	normalizedArgs := normalizeScanArgs(args)
	if err := flags.Parse(normalizedArgs); err != nil {
		return err
	}

	paths := flags.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	report, err := scanner.Scan(scanner.Options{
		Paths:         paths,
		IncludeHidden: *includeHidden,
		Exclude:       splitCSV(*exclude),
	})
	if err != nil {
		return err
	}
	report, err = filterReportByRules(report, *onlyRules)
	if err != nil {
		return err
	}
	report, err = filterReportBySeverity(report, *minSeverity)
	if err != nil {
		return err
	}

	fmt.Print(allowlistSuggestionText(report))
	return nil
}

func runRules(args []string) error {
	flags := flag.NewFlagSet("rules", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	format := flags.String("format", "text", "output format: text, json, or markdown")
	minSeverity := flags.String("min-severity", "", "minimum severity to list: low, medium, high, or critical")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("rules does not accept positional arguments")
	}

	rules := scanner.Rules()
	var err error
	rules, err = filterRulesBySeverity(rules, *minSeverity)
	if err != nil {
		return err
	}
	switch *format {
	case "text":
		for _, rule := range rules {
			fmt.Printf("%s\t%s\t%s\n", rule.ID, rule.Severity, rule.Message)
		}
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(rules)
	case "markdown":
		printMarkdownRules(rules)
	default:
		return fmt.Errorf("unsupported format %q", *format)
	}
	return nil
}

func runGitHubAction(args []string) error {
	flags := flag.NewFlagSet("github-action", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	outputPath := flags.String("output", "", "path to write the generated workflow")
	allowlistPath := flags.String("allowlist", "", "allowlist path used by the scan step")
	minSeverity := flags.String("min-severity", "", "minimum severity used by the scan step")
	onlyRules := flags.String("only-rules", "", "comma-separated rule IDs used by the scan step")
	goVersion := flags.String("go-version", "1.22", "Go version used by the workflow")
	sarifOutput := flags.String("sarif-output", "", "path for optional SARIF output uploaded to GitHub code scanning")
	scanPaths := flags.String("scan-paths", "", "comma-separated paths scanned by the generated workflow")
	triggerPaths := flags.String("trigger-paths", "", "comma-separated paths that trigger the generated workflow")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if flags.NArg() != 0 {
		return errors.New("github-action does not accept positional arguments")
	}

	content := workflow.GitHubActions(workflow.GitHubActionsOptions{
		AllowlistPath: *allowlistPath,
		MinSeverity:   *minSeverity,
		OnlyRules:     *onlyRules,
		GoVersion:     *goVersion,
		SARIFOutput:   *sarifOutput,
		ScanPaths:     *scanPaths,
		TriggerPaths:  *triggerPaths,
	})
	if *outputPath == "" {
		fmt.Print(content)
		return nil
	}

	return os.WriteFile(*outputPath, []byte(content), 0o644)
}

func runInstallHook(args []string) error {
	flags := flag.NewFlagSet("install-hook", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	outputPath := flags.String("output", "", "path to write the generated pre-commit hook")
	command := flags.String("command", "open-secret-guard", "command used inside the generated hook")
	allowlistPath := flags.String("allowlist", "", "allowlist path used inside the generated hook")

	normalizedArgs := normalizeInstallHookArgs(args)
	if err := flags.Parse(normalizedArgs); err != nil {
		return err
	}

	if flags.NArg() != 0 {
		return errors.New("install-hook does not accept positional arguments")
	}

	content := hook.PreCommit(hook.Options{
		Command:       *command,
		AllowlistPath: *allowlistPath,
	})
	if *outputPath == "" {
		fmt.Print(content)
		return nil
	}

	return os.WriteFile(*outputPath, []byte(content), 0o755)
}

func runEnvExample(args []string) error {
	flags := flag.NewFlagSet("env-example", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	outputPath := flags.String("output", "", "path to write the generated .env.example")
	normalizedArgs := normalizeEnvExampleArgs(args)
	if err := flags.Parse(normalizedArgs); err != nil {
		return err
	}

	paths := flags.Args()
	if len(paths) != 1 {
		return errors.New("env-example requires exactly one input file")
	}

	inputPath := paths[0]
	if *outputPath == inputPath {
		return errors.New("output path must be different from input path")
	}

	content, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	generated := envexample.Generate(string(content))
	if *outputPath == "" {
		fmt.Print(generated)
		return nil
	}

	return os.WriteFile(*outputPath, []byte(generated), 0o644)
}

func runScan(args []string) error {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	format := flags.String("format", "text", "output format: text, json, sarif, or summary")
	failOnFindings := flags.Bool("fail-on-findings", false, "exit with a non-zero status when findings are detected")
	includeHidden := flags.Bool("include-hidden", false, "scan hidden files and directories")
	exclude := flags.String("exclude", "", "comma-separated file or directory patterns to skip")
	allowlistPath := flags.String("allowlist", "", "path to an allowlist file")
	minSeverity := flags.String("min-severity", "", "minimum severity to report: low, medium, high, or critical")
	onlyRules := flags.String("only-rules", "", "comma-separated rule IDs to include in the report")

	normalizedArgs := normalizeScanArgs(args)
	if err := flags.Parse(normalizedArgs); err != nil {
		return err
	}

	paths := flags.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	allowlistMatcher, err := loadAllowlist(*allowlistPath)
	if err != nil {
		return err
	}

	report, err := scanner.Scan(scanner.Options{
		Paths:         paths,
		IncludeHidden: *includeHidden,
		Exclude:       splitCSV(*exclude),
		Allowlist:     allowlistMatcher,
	})
	if err != nil {
		return err
	}
	report, err = filterReportByRules(report, *onlyRules)
	if err != nil {
		return err
	}
	report, err = filterReportBySeverity(report, *minSeverity)
	if err != nil {
		return err
	}

	switch *format {
	case "text":
		printTextReport(report)
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			return err
		}
	case "sarif":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(sarif.FromReport(report)); err != nil {
			return err
		}
	case "summary":
		printSummaryReport(report)
	default:
		return fmt.Errorf("unsupported format %q", *format)
	}

	if *failOnFindings && len(report.Findings) > 0 {
		return errors.New("findings detected")
	}

	return nil
}

func normalizeScanArgs(args []string) []string {
	var flagArgs []string
	var pathArgs []string

	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch arg {
		case "-format":
			flagArgs = append(flagArgs, arg)
			if index+1 < len(args) {
				index++
				flagArgs = append(flagArgs, args[index])
			}
		case "-fail-on-findings", "-include-hidden":
			flagArgs = append(flagArgs, arg)
		case "-exclude":
			flagArgs = append(flagArgs, arg)
			if index+1 < len(args) {
				index++
				flagArgs = append(flagArgs, args[index])
			}
		case "-allowlist", "-min-severity", "-only-rules":
			flagArgs = append(flagArgs, arg)
			if index+1 < len(args) {
				index++
				flagArgs = append(flagArgs, args[index])
			}
		default:
			pathArgs = append(pathArgs, arg)
		}
	}

	return append(flagArgs, pathArgs...)
}

func normalizeEnvExampleArgs(args []string) []string {
	var flagArgs []string
	var pathArgs []string

	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch arg {
		case "-output":
			flagArgs = append(flagArgs, arg)
			if index+1 < len(args) {
				index++
				flagArgs = append(flagArgs, args[index])
			}
		default:
			pathArgs = append(pathArgs, arg)
		}
	}

	return append(flagArgs, pathArgs...)
}

func normalizeInstallHookArgs(args []string) []string {
	var flagArgs []string
	var pathArgs []string

	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch arg {
		case "-output", "-command", "-allowlist":
			flagArgs = append(flagArgs, arg)
			if index+1 < len(args) {
				index++
				flagArgs = append(flagArgs, args[index])
			}
		default:
			pathArgs = append(pathArgs, arg)
		}
	}

	return append(flagArgs, pathArgs...)
}

type allowlistMatcher struct {
	entries []allowlist.Entry
}

func loadAllowlist(path string) (scanner.Allowlist, error) {
	if path == "" {
		return nil, nil
	}

	entries, err := allowlist.Load(path)
	if err != nil {
		return nil, err
	}
	if err := allowlist.Validate(entries, scanner.Rules()); err != nil {
		return nil, err
	}
	return &allowlistMatcher{entries: entries}, nil
}

func (matcher *allowlistMatcher) IsAllowed(finding scanner.Finding) bool {
	return allowlist.IsAllowed(finding, matcher.entries)
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

func filterReportBySeverity(report scanner.Report, minSeverity string) (scanner.Report, error) {
	if minSeverity == "" {
		return report, nil
	}

	minRank, ok := severityRank(minSeverity)
	if !ok {
		return report, fmt.Errorf("unsupported minimum severity %q", minSeverity)
	}

	filtered := report.Findings[:0]
	for _, finding := range report.Findings {
		rank, ok := severityRank(finding.Severity)
		if ok && rank >= minRank {
			filtered = append(filtered, finding)
		}
	}
	report.Findings = filtered
	return report, nil
}

func filterReportByRules(report scanner.Report, onlyRules string) (scanner.Report, error) {
	ruleIDs := splitCSV(onlyRules)
	if len(ruleIDs) == 0 {
		return report, nil
	}

	knownRules := make(map[string]bool, len(scanner.Rules()))
	for _, rule := range scanner.Rules() {
		knownRules[rule.ID] = true
	}

	allowedRules := make(map[string]bool, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		if !knownRules[ruleID] {
			return report, fmt.Errorf("unknown rule ID %q", ruleID)
		}
		allowedRules[ruleID] = true
	}

	filtered := report.Findings[:0]
	for _, finding := range report.Findings {
		if allowedRules[finding.RuleID] {
			filtered = append(filtered, finding)
		}
	}
	report.Findings = filtered
	return report, nil
}

func filterRulesBySeverity(rules []scanner.RuleMetadata, minSeverity string) ([]scanner.RuleMetadata, error) {
	if minSeverity == "" {
		return rules, nil
	}

	minRank, ok := severityRank(minSeverity)
	if !ok {
		return rules, fmt.Errorf("unsupported minimum severity %q", minSeverity)
	}

	filtered := rules[:0]
	for _, rule := range rules {
		rank, ok := severityRank(rule.Severity)
		if ok && rank >= minRank {
			filtered = append(filtered, rule)
		}
	}
	return filtered, nil
}

func severityRank(severity string) (int, bool) {
	switch severity {
	case "low":
		return 1, true
	case "medium":
		return 2, true
	case "high":
		return 3, true
	case "critical":
		return 4, true
	default:
		return 0, false
	}
}

func printTextReport(report scanner.Report) {
	if len(report.Findings) == 0 {
		fmt.Println("No likely secrets found.")
		return
	}

	fmt.Printf("Found %d likely secret(s):\n\n", len(report.Findings))
	for _, finding := range report.Findings {
		fmt.Printf("%s:%d:%d [%s] %s\n", finding.Path, finding.Line, finding.Column, finding.Severity, finding.RuleID)
		fmt.Printf("  %s\n", finding.Message)
		fmt.Printf("  matched: %s\n\n", finding.RedactedMatch)
	}
}

func printMarkdownRules(rules []scanner.RuleMetadata) {
	fmt.Println("| Rule ID | Severity | Description |")
	fmt.Println("| --- | --- | --- |")
	for _, rule := range rules {
		fmt.Printf("| `%s` | %s | %s |\n", markdownCell(rule.ID), markdownCell(rule.Severity), markdownCell(rule.Message))
	}
}

func printSummaryReport(report scanner.Report) {
	fmt.Print(summaryText(report))
}

func allowlistSuggestionText(report scanner.Report) string {
	lines := []string{
		"# Review every entry before adding it to an allowlist.",
		"# Format: rule-id path-glob [line]",
	}
	for _, finding := range report.Findings {
		lines = append(lines, fmt.Sprintf("%s %s %d", finding.RuleID, finding.Path, finding.Line))
	}
	if len(report.Findings) == 0 {
		lines = append(lines, "# No findings to suggest.")
	}
	return strings.Join(lines, "\n") + "\n"
}

func summaryText(report scanner.Report) string {
	severityCounts := make(map[string]int)
	ruleCounts := make(map[string]int)
	for _, finding := range report.Findings {
		severityCounts[finding.Severity]++
		ruleCounts[finding.RuleID]++
	}

	lines := []string{
		fmt.Sprintf("Scanned files: %d", report.ScannedFiles),
		fmt.Sprintf("Skipped files: %d", report.SkippedFiles),
		fmt.Sprintf("Findings: %d", len(report.Findings)),
	}

	if len(report.Findings) == 0 {
		return strings.Join(lines, "\n") + "\n"
	}

	lines = append(lines, "", "By severity:")
	for _, severity := range []string{"critical", "high", "medium", "low"} {
		if count := severityCounts[severity]; count > 0 {
			lines = append(lines, fmt.Sprintf("%s: %d", severity, count))
		}
	}

	ruleIDs := make([]string, 0, len(ruleCounts))
	for ruleID := range ruleCounts {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Strings(ruleIDs)

	lines = append(lines, "", "By rule:")
	for _, ruleID := range ruleIDs {
		lines = append(lines, fmt.Sprintf("%s: %d", ruleID, ruleCounts[ruleID]))
	}

	return strings.Join(lines, "\n") + "\n"
}

func markdownCell(value string) string {
	value = strings.ReplaceAll(value, "|", "\\|")
	return strings.ReplaceAll(value, "\n", " ")
}

func pluralSuffix(count int) string {
	if count == 1 {
		return "y"
	}
	return "ies"
}

func printUsage() {
	fmt.Println(`open-secret-guard

Usage:
  open-secret-guard allowlist-check <allowlist-file>
  open-secret-guard allowlist-suggest [path ...] [flags]
  open-secret-guard env-example <env-file> [-output .env.example]
  open-secret-guard github-action [-output .github/workflows/secret-guard.yml] [-sarif-output open-secret-guard.sarif] [-scan-paths cmd,internal] [-trigger-paths cmd/**,internal/**]
  open-secret-guard install-hook [-output .git/hooks/pre-commit]
  open-secret-guard rules [-format text|json|markdown] [-min-severity low|medium|high|critical]
  open-secret-guard scan [path ...] [flags]

Flags:
  -format text|json|sarif|summary Output format
  -fail-on-findings       Exit non-zero when findings are detected
  -min-severity level     Only report findings at or above low|medium|high|critical
  -only-rules ids         Only report findings for the given comma-separated rule IDs
  -include-hidden         Scan hidden files and directories
  -exclude pattern        Comma-separated file or directory patterns to skip
  -allowlist path         Path to an allowlist file`)
}
