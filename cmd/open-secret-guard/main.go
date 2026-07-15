package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/derekFixBug/open-secret-guard/internal/allowlist"
	"github.com/derekFixBug/open-secret-guard/internal/envexample"
	"github.com/derekFixBug/open-secret-guard/internal/hook"
	"github.com/derekFixBug/open-secret-guard/internal/sarif"
	"github.com/derekFixBug/open-secret-guard/internal/scanner"
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
	case "env-example":
		return runEnvExample(args[1:])
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

func runRules(args []string) error {
	flags := flag.NewFlagSet("rules", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	format := flags.String("format", "text", "output format: text or json")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("rules does not accept positional arguments")
	}

	rules := scanner.Rules()
	switch *format {
	case "text":
		for _, rule := range rules {
			fmt.Printf("%s\t%s\t%s\n", rule.ID, rule.Severity, rule.Message)
		}
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(rules)
	default:
		return fmt.Errorf("unsupported format %q", *format)
	}
	return nil
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

	format := flags.String("format", "text", "output format: text, json, or sarif")
	failOnFindings := flags.Bool("fail-on-findings", false, "exit with a non-zero status when findings are detected")
	includeHidden := flags.Bool("include-hidden", false, "scan hidden files and directories")
	exclude := flags.String("exclude", "", "comma-separated file or directory patterns to skip")
	allowlistPath := flags.String("allowlist", "", "path to an allowlist file")
	minSeverity := flags.String("min-severity", "", "minimum severity to report: low, medium, high, or critical")

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
		case "-allowlist", "-min-severity":
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

func printUsage() {
	fmt.Println(`open-secret-guard

Usage:
  open-secret-guard env-example <env-file> [-output .env.example]
  open-secret-guard install-hook [-output .git/hooks/pre-commit]
  open-secret-guard rules [-format text|json]
  open-secret-guard scan [path ...] [flags]

Flags:
  -format text|json|sarif Output format
  -fail-on-findings       Exit non-zero when findings are detected
  -min-severity level     Only report findings at or above low|medium|high|critical
  -include-hidden         Scan hidden files and directories
  -exclude pattern        Comma-separated file or directory patterns to skip
  -allowlist path         Path to an allowlist file`)
}
