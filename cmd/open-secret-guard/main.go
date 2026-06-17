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
	case "scan":
		return runScan(args[1:])
	case "help", "-h", "--help":
		printUsage()
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
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
		case "-allowlist":
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
  open-secret-guard scan [path ...] [flags]

Flags:
  -format text|json|sarif Output format
  -fail-on-findings       Exit non-zero when findings are detected
  -include-hidden         Scan hidden files and directories
  -exclude pattern        Comma-separated file or directory patterns to skip
  -allowlist path         Path to an allowlist file`)
}
