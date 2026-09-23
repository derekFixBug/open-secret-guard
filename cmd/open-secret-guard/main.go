package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/derekFixBug/open-secret-guard/internal/allowlist"
	"github.com/derekFixBug/open-secret-guard/internal/envexample"
	"github.com/derekFixBug/open-secret-guard/internal/hook"
	"github.com/derekFixBug/open-secret-guard/internal/onepassword"
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
	case "1password-template":
		return run1PasswordTemplate(args[1:])
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
	flags := flag.NewFlagSet("allowlist-check", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	format := flags.String("format", "text", "output format: text or json")
	expiresWithin := flags.Int("expires-within", -1, "fail when an allowlist entry expires within this many days")
	normalizedArgs := normalizeAllowlistCheckArgs(args)
	if err := flags.Parse(normalizedArgs); err != nil {
		return err
	}
	if *format != "text" && *format != "json" {
		return fmt.Errorf("unsupported format %q", *format)
	}
	if *expiresWithin < -1 {
		return errors.New("expires-within cannot be less than -1")
	}

	paths := flags.Args()
	if len(paths) != 1 {
		return errors.New("allowlist-check requires exactly one allowlist file")
	}

	entries, err := allowlist.Load(paths[0])
	if err != nil {
		return err
	}
	if err := allowlist.Validate(entries, scanner.Rules()); err != nil {
		return err
	}
	expiring := allowlist.ExpiringWithin(entries, time.Now().UTC(), *expiresWithin)
	switch *format {
	case "text":
		fmt.Printf("Allowlist is valid: %d entr%s.\n", len(entries), pluralSuffix(len(entries)))
	case "json":
		output, err := allowlistCheckReportJSON(entries, expiring)
		if err != nil {
			return err
		}
		fmt.Print(output)
	}
	if len(expiring) > 0 {
		return fmt.Errorf("%d allowlist entr%s expire within %d day(s): %s", len(expiring), pluralSuffix(len(expiring)), *expiresWithin, formatExpiringAllowlistEntries(expiring))
	}

	return nil
}

type allowlistCheckReport struct {
	Entries  int               `json:"entries"`
	Expiring []allowlist.Entry `json:"expiring"`
}

func allowlistCheckReportJSON(entries []allowlist.Entry, expiring []allowlist.Entry) (string, error) {
	if expiring == nil {
		expiring = []allowlist.Entry{}
	}
	output, err := json.MarshalIndent(allowlistCheckReport{
		Entries:  len(entries),
		Expiring: expiring,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	return string(output) + "\n", nil
}

func runAllowlistSuggest(args []string) error {
	flags := flag.NewFlagSet("allowlist-suggest", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	includeHidden := flags.Bool("include-hidden", false, "scan hidden files and directories")
	exclude := flags.String("exclude", "", "comma-separated file or directory patterns to skip")
	excludeFile := flags.String("exclude-file", "", "path to newline-separated file or directory patterns to skip")
	minSeverity := flags.String("min-severity", "", "minimum severity to include: low, medium, high, or critical")
	onlyRules := flags.String("only-rules", "", "comma-separated rule IDs to include")
	provider := flags.String("provider", "", "comma-separated providers to include")
	maxFileBytes := flags.Int("max-file-bytes", 0, "maximum scanned file size in bytes; 0 uses the default")
	maxFindings := flags.Int("max-findings", 0, "maximum number of findings to include; 0 includes all")
	expiresOn := flags.String("expires-on", "", "optional YYYY-MM-DD expiry appended to every suggested entry")

	normalizedArgs := normalizeScanArgs(args)
	if err := flags.Parse(normalizedArgs); err != nil {
		return err
	}
	if *maxFindings < 0 {
		return errors.New("max-findings cannot be negative")
	}
	expiry, err := parseCandidateExpiry(*expiresOn, time.Now().UTC())
	if err != nil {
		return err
	}
	excludePatterns, err := loadExcludePatterns(*excludeFile)
	if err != nil {
		return err
	}

	paths := flags.Args()
	if len(paths) == 0 {
		paths = []string{"."}
	}

	report, err := scanner.Scan(scanner.Options{
		Paths:         paths,
		IncludeHidden: *includeHidden,
		Exclude:       append(splitCSV(*exclude), excludePatterns...),
		MaxFileBytes:  *maxFileBytes,
	})
	if err != nil {
		return err
	}
	report, err = filterReportByRules(report, *onlyRules)
	if err != nil {
		return err
	}
	report, err = filterReportByProvider(report, *provider)
	if err != nil {
		return err
	}
	report, err = filterReportBySeverity(report, *minSeverity)
	if err != nil {
		return err
	}
	report, err = limitReportFindings(report, *maxFindings)
	if err != nil {
		return err
	}

	fmt.Print(allowlistSuggestionText(report, expiry))
	return nil
}

func runRules(args []string) error {
	flags := flag.NewFlagSet("rules", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	format := flags.String("format", "text", "output format: text, json, markdown, or csv")
	minSeverity := flags.String("min-severity", "", "minimum severity to list: low, medium, high, or critical")
	provider := flags.String("provider", "", "comma-separated providers to list")
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
	rules, err = filterRulesByProvider(rules, *provider)
	if err != nil {
		return err
	}
	switch *format {
	case "text":
		for _, rule := range rules {
			fmt.Printf("%s\t%s\t%s\t%s\n", rule.ID, rule.Provider, rule.Severity, rule.Message)
		}
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(rules)
	case "markdown":
		printMarkdownRules(rules)
	case "csv":
		if err := printCSVRules(rules); err != nil {
			return err
		}
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
	provider := flags.String("provider", "", "comma-separated providers used by the scan step")
	goVersion := flags.String("go-version", "1.22", "Go version used by the workflow")
	sarifOutput := flags.String("sarif-output", "", "path for optional SARIF output uploaded to GitHub code scanning")
	scanPaths := flags.String("scan-paths", "", "comma-separated paths scanned by the generated workflow")
	exclude := flags.String("exclude", "", "comma-separated paths excluded by the generated scan")
	triggerPaths := flags.String("trigger-paths", "", "comma-separated paths that trigger the generated workflow")
	branches := flags.String("branches", "", "comma-separated branches that trigger the generated workflow; defaults to main")
	schedule := flags.String("schedule", "", "optional GitHub Actions cron schedule for recurring scans")
	manualTrigger := flags.Bool("manual-trigger", false, "include a GitHub Actions workflow_dispatch trigger")
	maxFileBytes := flags.Int("max-file-bytes", 0, "maximum file size used by the generated scan; 0 uses the default")
	maxFindings := flags.Int("max-findings", 0, "maximum findings reported by the generated scan; 0 reports all")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if flags.NArg() != 0 {
		return errors.New("github-action does not accept positional arguments")
	}
	if *maxFileBytes < 0 {
		return errors.New("max-file-bytes cannot be negative")
	}
	if *maxFindings < 0 {
		return errors.New("max-findings cannot be negative")
	}

	content := workflow.GitHubActions(workflow.GitHubActionsOptions{
		AllowlistPath: *allowlistPath,
		MinSeverity:   *minSeverity,
		OnlyRules:     *onlyRules,
		Provider:      *provider,
		GoVersion:     *goVersion,
		SARIFOutput:   *sarifOutput,
		ScanPaths:     *scanPaths,
		Exclude:       *exclude,
		TriggerPaths:  *triggerPaths,
		Branches:      *branches,
		Schedule:      *schedule,
		ManualTrigger: *manualTrigger,
		MaxFileBytes:  *maxFileBytes,
		MaxFindings:   *maxFindings,
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
	minSeverity := flags.String("min-severity", "", "minimum severity used inside the generated hook")

	normalizedArgs := normalizeInstallHookArgs(args)
	if err := flags.Parse(normalizedArgs); err != nil {
		return err
	}

	if flags.NArg() != 0 {
		return errors.New("install-hook does not accept positional arguments")
	}
	if *minSeverity != "" {
		if _, ok := severityRank(*minSeverity); !ok {
			return fmt.Errorf("unsupported minimum severity %q", *minSeverity)
		}
	}

	content := hook.PreCommit(hook.Options{
		Command:       *command,
		AllowlistPath: *allowlistPath,
		MinSeverity:   *minSeverity,
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

func run1PasswordTemplate(args []string) error {
	flags := flag.NewFlagSet("1password-template", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	vault := flags.String("vault", "", "1Password vault name used by generated references")
	item := flags.String("item", "", "1Password item name used by generated references")
	outputPath := flags.String("output", "", "path to write the generated 1Password environment template")
	preserveReferences := flags.Bool("preserve-references", false, "keep existing op:// references instead of replacing them")
	normalizedArgs := normalize1PasswordTemplateArgs(args)
	if err := flags.Parse(normalizedArgs); err != nil {
		return err
	}
	if strings.TrimSpace(*vault) == "" {
		return errors.New("1password-template requires -vault")
	}
	if strings.TrimSpace(*item) == "" {
		return errors.New("1password-template requires -item")
	}

	paths := flags.Args()
	if len(paths) != 1 {
		return errors.New("1password-template requires exactly one environment template file")
	}
	if *outputPath == paths[0] {
		return errors.New("output path must be different from input path")
	}

	content, err := os.ReadFile(paths[0])
	if err != nil {
		return err
	}

	generated := onepassword.GenerateWithOptions(string(content), strings.TrimSpace(*vault), strings.TrimSpace(*item), onepassword.Options{
		PreserveExistingReferences: *preserveReferences,
	})
	if *outputPath == "" {
		fmt.Print(generated)
		return nil
	}
	return os.WriteFile(*outputPath, []byte(generated), 0o644)
}

func runScan(args []string) error {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)

	format := flags.String("format", "text", "output format: text, json, sarif, summary, markdown, or csv")
	failOnFindings := flags.Bool("fail-on-findings", false, "exit with a non-zero status when findings are detected")
	failOnSeverity := flags.String("fail-on-severity", "", "minimum severity that exits non-zero: low, medium, high, or critical")
	includeHidden := flags.Bool("include-hidden", false, "scan hidden files and directories")
	exclude := flags.String("exclude", "", "comma-separated file or directory patterns to skip")
	excludeFile := flags.String("exclude-file", "", "path to newline-separated file or directory patterns to skip")
	allowlistPath := flags.String("allowlist", "", "path to an allowlist file")
	minSeverity := flags.String("min-severity", "", "minimum severity to report: low, medium, high, or critical")
	onlyRules := flags.String("only-rules", "", "comma-separated rule IDs to include in the report")
	provider := flags.String("provider", "", "comma-separated providers to include in the report")
	maxFileBytes := flags.Int("max-file-bytes", 0, "maximum scanned file size in bytes; 0 uses the default")
	maxFindings := flags.Int("max-findings", 0, "maximum number of findings to report; 0 reports all")

	normalizedArgs := normalizeScanArgs(args)
	if err := flags.Parse(normalizedArgs); err != nil {
		return err
	}
	if *maxFindings < 0 {
		return errors.New("max-findings cannot be negative")
	}
	if *failOnSeverity != "" {
		if _, ok := severityRank(*failOnSeverity); !ok {
			return fmt.Errorf("unsupported failure severity %q", *failOnSeverity)
		}
	}
	excludePatterns, err := loadExcludePatterns(*excludeFile)
	if err != nil {
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
		Exclude:       append(splitCSV(*exclude), excludePatterns...),
		Allowlist:     allowlistMatcher,
		MaxFileBytes:  *maxFileBytes,
	})
	if err != nil {
		return err
	}
	report, err = filterReportByRules(report, *onlyRules)
	if err != nil {
		return err
	}
	report, err = filterReportByProvider(report, *provider)
	if err != nil {
		return err
	}
	report, err = filterReportBySeverity(report, *minSeverity)
	if err != nil {
		return err
	}
	failureReport := report
	report, err = limitReportFindings(report, *maxFindings)
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
	case "markdown":
		printMarkdownReport(report)
	case "csv":
		if err := printCSVReport(report); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported format %q", *format)
	}

	if *failOnFindings && len(report.Findings) > 0 {
		return errors.New("findings detected")
	}
	if *failOnSeverity != "" && hasFindingsAtOrAbove(failureReport, *failOnSeverity) {
		return fmt.Errorf("findings at or above %s severity detected", *failOnSeverity)
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
		case "-exclude", "-exclude-file":
			flagArgs = append(flagArgs, arg)
			if index+1 < len(args) {
				index++
				flagArgs = append(flagArgs, args[index])
			}
		case "-allowlist", "-min-severity", "-fail-on-severity", "-only-rules", "-provider", "-max-file-bytes", "-max-findings", "-expires-on":
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

func normalizeAllowlistCheckArgs(args []string) []string {
	var flagArgs []string
	var pathArgs []string

	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch arg {
		case "-format", "-expires-within":
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

func normalize1PasswordTemplateArgs(args []string) []string {
	var flagArgs []string
	var pathArgs []string

	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch arg {
		case "-vault", "-item", "-output":
			flagArgs = append(flagArgs, arg)
			if index+1 < len(args) {
				index++
				flagArgs = append(flagArgs, args[index])
			}
		case "-preserve-references":
			flagArgs = append(flagArgs, arg)
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
		case "-output", "-command", "-allowlist", "-min-severity":
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

func loadExcludePatterns(path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var patterns []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		pattern := strings.TrimSpace(scanner.Text())
		if pattern == "" || strings.HasPrefix(pattern, "#") {
			continue
		}
		patterns = append(patterns, pattern)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return patterns, nil
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

func hasFindingsAtOrAbove(report scanner.Report, minSeverity string) bool {
	minimumRank, ok := severityRank(minSeverity)
	if !ok {
		return false
	}
	for _, finding := range report.Findings {
		rank, ok := severityRank(finding.Severity)
		if ok && rank >= minimumRank {
			return true
		}
	}
	return false
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

func filterRulesByProvider(rules []scanner.RuleMetadata, providerFilter string) ([]scanner.RuleMetadata, error) {
	selectedProviders, err := selectedProviders(providerFilter)
	if err != nil {
		return rules, err
	}
	if len(selectedProviders) == 0 {
		return rules, nil
	}

	filtered := rules[:0]
	for _, rule := range rules {
		if selectedProviders[strings.ToLower(rule.Provider)] {
			filtered = append(filtered, rule)
		}
	}
	return filtered, nil
}

func limitReportFindings(report scanner.Report, maxFindings int) (scanner.Report, error) {
	if maxFindings < 0 {
		return report, errors.New("max-findings cannot be negative")
	}
	if maxFindings == 0 || len(report.Findings) <= maxFindings {
		return report, nil
	}
	report.Findings = report.Findings[:maxFindings]
	return report, nil
}

func filterReportByProvider(report scanner.Report, providerFilter string) (scanner.Report, error) {
	selectedProviders, err := selectedProviders(providerFilter)
	if err != nil {
		return report, err
	}
	if len(selectedProviders) == 0 {
		return report, nil
	}

	ruleProviders := make(map[string]string, len(scanner.Rules()))
	for _, rule := range scanner.Rules() {
		ruleProviders[rule.ID] = strings.ToLower(rule.Provider)
	}

	filtered := report.Findings[:0]
	for _, finding := range report.Findings {
		if selectedProviders[ruleProviders[finding.RuleID]] {
			filtered = append(filtered, finding)
		}
	}
	report.Findings = filtered
	return report, nil
}

func selectedProviders(providerFilter string) (map[string]bool, error) {
	providers := splitCSV(providerFilter)
	if len(providers) == 0 {
		return nil, nil
	}

	knownProviders := make(map[string]bool, len(scanner.Rules()))
	for _, rule := range scanner.Rules() {
		knownProviders[strings.ToLower(rule.Provider)] = true
	}

	selectedProviders := make(map[string]bool, len(providers))
	for _, provider := range providers {
		provider = strings.ToLower(provider)
		if !knownProviders[provider] {
			return nil, fmt.Errorf("unknown provider %q", provider)
		}
		selectedProviders[provider] = true
	}
	return selectedProviders, nil
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
	fmt.Println("| Rule ID | Provider | Severity | Description |")
	fmt.Println("| --- | --- | --- | --- |")
	for _, rule := range rules {
		fmt.Printf("| `%s` | %s | %s | %s |\n", markdownCell(rule.ID), markdownCell(rule.Provider), markdownCell(rule.Severity), markdownCell(rule.Message))
	}
}

func printCSVRules(rules []scanner.RuleMetadata) error {
	output, err := csvRulesText(rules)
	if err != nil {
		return err
	}
	fmt.Print(output)
	return nil
}

func printSummaryReport(report scanner.Report) {
	fmt.Print(summaryText(report))
}

func printMarkdownReport(report scanner.Report) {
	fmt.Print(markdownReportText(report))
}

func printCSVReport(report scanner.Report) error {
	output, err := csvReportText(report)
	if err != nil {
		return err
	}
	fmt.Print(output)
	return nil
}

func parseCandidateExpiry(value string, now time.Time) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}

	expiresAt, err := time.Parse(time.DateOnly, value)
	if err != nil {
		return "", errors.New("expires-on must be a YYYY-MM-DD date")
	}
	now = now.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	if expiresAt.Before(today) {
		return "", errors.New("expires-on cannot be in the past")
	}
	return expiresAt.Format(time.DateOnly), nil
}

func allowlistSuggestionText(report scanner.Report, expiresOn string) string {
	lines := []string{
		"# Review every entry before adding it to an allowlist.",
		"# Format: rule-id path-glob [line] [expires-on:YYYY-MM-DD]",
	}
	if expiresOn != "" {
		lines = append(lines, fmt.Sprintf("# Suggested entries expire on %s.", expiresOn))
	}
	for _, finding := range report.Findings {
		line := fmt.Sprintf("%s %s %d", finding.RuleID, finding.Path, finding.Line)
		if expiresOn != "" {
			line += " " + expiresOn
		}
		lines = append(lines, line)
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

func markdownReportText(report scanner.Report) string {
	if len(report.Findings) == 0 {
		return "No likely secrets found.\n"
	}

	providers := make(map[string]string, len(scanner.Rules()))
	for _, rule := range scanner.Rules() {
		providers[rule.ID] = rule.Provider
	}

	lines := []string{
		"| Path | Line | Rule | Provider | Severity | Description |",
		"| --- | ---: | --- | --- | --- | --- |",
	}
	for _, finding := range report.Findings {
		lines = append(lines, fmt.Sprintf("| `%s` | %d | `%s` | %s | %s | %s |",
			markdownCell(finding.Path),
			finding.Line,
			markdownCell(finding.RuleID),
			markdownCell(providers[finding.RuleID]),
			markdownCell(finding.Severity),
			markdownCell(finding.Message),
		))
	}
	return strings.Join(lines, "\n") + "\n"
}

func csvReportText(report scanner.Report) (string, error) {
	providers := make(map[string]string, len(scanner.Rules()))
	for _, rule := range scanner.Rules() {
		providers[rule.ID] = rule.Provider
	}

	var builder strings.Builder
	writer := csv.NewWriter(&builder)
	if err := writer.Write([]string{"path", "line", "column", "rule", "provider", "severity", "description"}); err != nil {
		return "", err
	}
	for _, finding := range report.Findings {
		if err := writer.Write([]string{
			finding.Path,
			strconv.Itoa(finding.Line),
			strconv.Itoa(finding.Column),
			finding.RuleID,
			providers[finding.RuleID],
			finding.Severity,
			finding.Message,
		}); err != nil {
			return "", err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", err
	}
	return builder.String(), nil
}

func csvRulesText(rules []scanner.RuleMetadata) (string, error) {
	var builder strings.Builder
	writer := csv.NewWriter(&builder)
	if err := writer.Write([]string{"rule", "provider", "severity", "description"}); err != nil {
		return "", err
	}
	for _, rule := range rules {
		if err := writer.Write([]string{rule.ID, rule.Provider, rule.Severity, rule.Message}); err != nil {
			return "", err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return "", err
	}
	return builder.String(), nil
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

func formatExpiringAllowlistEntries(entries []allowlist.Entry) string {
	formatted := make([]string, 0, len(entries))
	for _, entry := range entries {
		formatted = append(formatted, fmt.Sprintf("%s %s (expires %s)", entry.RuleID, entry.PathPattern, entry.ExpiresAt.Format(time.DateOnly)))
	}
	return strings.Join(formatted, "; ")
}

func printUsage() {
	fmt.Println(`open-secret-guard

Usage:
  open-secret-guard allowlist-check <allowlist-file> [-format text|json] [-expires-within days]
  open-secret-guard allowlist-suggest [path ...] [flags]
  open-secret-guard env-example <env-file> [-output .env.example]
  open-secret-guard 1password-template <env-example-file> -vault <vault> -item <item> [-output .env.1password] [-preserve-references]
  open-secret-guard github-action [-output .github/workflows/secret-guard.yml] [-provider github,gitlab] [-branches main,develop] [-schedule '0 9 * * 1'] [-manual-trigger] [-sarif-output open-secret-guard.sarif] [-scan-paths cmd,internal] [-exclude examples,testdata] [-trigger-paths cmd/**,internal/**] [-max-file-bytes 8388608] [-max-findings 20]
  open-secret-guard install-hook [-output .git/hooks/pre-commit] [-min-severity high]
  open-secret-guard rules [-format text|json|markdown|csv] [-min-severity low|medium|high|critical] [-provider github,gitlab]
  open-secret-guard scan [path ...] [flags]

Flags:
  -format text|json|sarif|summary|markdown Output format
  -fail-on-findings       Exit non-zero when findings are detected
  -fail-on-severity level Exit non-zero for findings at or above low|medium|high|critical
  -min-severity level     Only report findings at or above low|medium|high|critical
  -only-rules ids         Only report findings for the given comma-separated rule IDs
  -provider names         Only report findings for the given comma-separated providers
  -include-hidden         Scan hidden files and directories
  -exclude pattern        Comma-separated file or directory patterns to skip
  -allowlist path         Path to an allowlist file
  -max-file-bytes count   Maximum scanned file size; 0 uses the default
  -max-findings count     Maximum number of findings to report; 0 reports all`)
}
