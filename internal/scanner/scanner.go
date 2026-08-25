package scanner

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const maxFileBytes = 2 * 1024 * 1024

type Options struct {
	Paths         []string  `json:"paths"`
	IncludeHidden bool      `json:"includeHidden"`
	Exclude       []string  `json:"exclude"`
	Allowlist     Allowlist `json:"allowlist"`
	MaxFileBytes  int       `json:"maxFileBytes"`
}

type Report struct {
	ScannedFiles int       `json:"scannedFiles"`
	SkippedFiles int       `json:"skippedFiles"`
	Findings     []Finding `json:"findings"`
}

type Finding struct {
	RuleID        string `json:"ruleId"`
	Severity      string `json:"severity"`
	Path          string `json:"path"`
	Line          int    `json:"line"`
	Column        int    `json:"column"`
	Message       string `json:"message"`
	RedactedMatch string `json:"redactedMatch"`
}

type Allowlist interface {
	IsAllowed(Finding) bool
}

type Rule struct {
	ID       string
	Provider string
	Severity string
	Message  string
	Pattern  *regexp.Regexp
}

type RuleMetadata struct {
	ID       string `json:"id"`
	Provider string `json:"provider"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

var defaultRules = []Rule{
	{
		ID:       "aws-access-key",
		Provider: "aws",
		Severity: "high",
		Message:  "AWS access key identifiers should not be committed.",
		Pattern:  regexp.MustCompile(`\b(AKIA|ASIA)[A-Z0-9]{16}\b`),
	},
	{
		ID:       "github-token",
		Provider: "github",
		Severity: "high",
		Message:  "GitHub tokens should be stored in a secret manager, not source files.",
		Pattern:  regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{20,})\b`),
	},
	{
		ID:       "gitlab-token",
		Provider: "gitlab",
		Severity: "high",
		Message:  "GitLab tokens should be stored in a secret manager, not source files.",
		Pattern:  regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20}\b`),
	},
	{
		ID:       "azure-devops-pat",
		Provider: "azure-devops",
		Severity: "high",
		Message:  "Azure DevOps personal access tokens should not be committed.",
		Pattern:  regexp.MustCompile(`\b[A-Za-z0-9]{75}AZDO[A-Za-z0-9]{5}\b`),
	},
	{
		ID:       "slack-token",
		Provider: "slack",
		Severity: "high",
		Message:  "Slack tokens should be stored in a secret manager, not source files.",
		Pattern:  regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`),
	},
	{
		ID:       "slack-webhook",
		Provider: "slack",
		Severity: "high",
		Message:  "Slack incoming webhook URLs should not be committed.",
		Pattern:  regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+`),
	},
	{
		ID:       "discord-bot-token",
		Provider: "discord",
		Severity: "high",
		Message:  "Discord bot tokens should not be committed.",
		Pattern:  regexp.MustCompile(`\b[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b`),
	},
	{
		ID:       "stripe-live-secret-key",
		Provider: "stripe",
		Severity: "high",
		Message:  "Stripe live secret keys should not be committed.",
		Pattern:  regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{24,}\b`),
	},
	{
		ID:       "sendgrid-api-key",
		Provider: "sendgrid",
		Severity: "high",
		Message:  "SendGrid API keys should not be committed.",
		Pattern:  regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`),
	},
	{
		ID:       "google-api-key",
		Provider: "google",
		Severity: "high",
		Message:  "Google API keys should be stored in a secret manager, not source files.",
		Pattern:  regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
	},
	{
		ID:       "openai-api-key",
		Provider: "openai",
		Severity: "high",
		Message:  "OpenAI or OpenAI-compatible API keys should not be committed.",
		Pattern:  regexp.MustCompile(`\bsk-(proj-[A-Za-z0-9_-]{20,}|[A-Za-z0-9]{32,})\b`),
	},
	{
		ID:       "anthropic-api-key",
		Provider: "anthropic",
		Severity: "high",
		Message:  "Anthropic API keys should not be committed.",
		Pattern:  regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`),
	},
	{
		ID:       "huggingface-token",
		Provider: "huggingface",
		Severity: "high",
		Message:  "Hugging Face access tokens should not be committed.",
		Pattern:  regexp.MustCompile(`\bhf_[A-Za-z0-9]{34,}\b`),
	},
	{
		ID:       "npm-access-token",
		Provider: "npm",
		Severity: "high",
		Message:  "npm access tokens should not be committed.",
		Pattern:  regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
	},
	{
		ID:       "pypi-token",
		Provider: "pypi",
		Severity: "high",
		Message:  "PyPI API tokens should not be committed.",
		Pattern:  regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,}\b`),
	},
	{
		ID:       "digitalocean-token",
		Provider: "digitalocean",
		Severity: "high",
		Message:  "DigitalOcean API tokens should not be committed.",
		Pattern:  regexp.MustCompile(`\bdo[opr]_v1_[a-f0-9]{64}\b`),
	},
	{
		ID:       "shopify-access-token",
		Provider: "shopify",
		Severity: "high",
		Message:  "Shopify access tokens should not be committed.",
		Pattern:  regexp.MustCompile(`\bshp(at|ca|pa|ss)_[a-fA-F0-9]{32}\b`),
	},
	{
		ID:       "terraform-cloud-token",
		Provider: "terraform-cloud",
		Severity: "high",
		Message:  "Terraform Cloud tokens should not be committed.",
		Pattern:  regexp.MustCompile(`\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{67}\b`),
	},
	{
		ID:       "jwt-token",
		Provider: "generic",
		Severity: "high",
		Message:  "JWT bearer tokens should not be committed.",
		Pattern:  regexp.MustCompile(`\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
	},
	{
		ID:       "private-key",
		Provider: "generic",
		Severity: "critical",
		Message:  "Private keys should never be committed to source control.",
		Pattern:  regexp.MustCompile(`-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`),
	},
	{
		ID:       "assigned-secret",
		Provider: "generic",
		Severity: "medium",
		Message:  "This assignment looks like it may contain a secret value.",
		Pattern:  regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)\b\s*[:=]\s*['"]?[^'"\s]{8,}`),
	},
	{
		ID:       "database-url",
		Provider: "generic",
		Severity: "medium",
		Message:  "Database URLs with inline credentials should be kept out of source files.",
		Pattern:  regexp.MustCompile(`(?i)\b(postgres|postgresql|mysql|mongodb|redis)://[^/\s:@]+:[^/\s:@]+@`),
	},
}

func Rules() []RuleMetadata {
	rules := make([]RuleMetadata, 0, len(defaultRules))
	for _, rule := range defaultRules {
		rules = append(rules, RuleMetadata{
			ID:       rule.ID,
			Provider: rule.Provider,
			Severity: rule.Severity,
			Message:  rule.Message,
		})
	}
	return rules
}

var skippedDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	"target":       true,
	".next":        true,
}

func Scan(options Options) (Report, error) {
	if options.MaxFileBytes < 0 {
		return Report{}, errors.New("maximum file size cannot be negative")
	}
	if len(options.Paths) == 0 {
		options.Paths = []string{"."}
	}

	var report Report
	for _, path := range options.Paths {
		if err := scanPath(path, options, &report); err != nil {
			return report, err
		}
	}

	sort.Slice(report.Findings, func(i, j int) bool {
		left := report.Findings[i]
		right := report.Findings[j]
		if left.Path != right.Path {
			return left.Path < right.Path
		}
		if left.Line != right.Line {
			return left.Line < right.Line
		}
		return left.Column < right.Column
	})

	if options.Allowlist != nil {
		report.Findings = filterAllowedFindings(report.Findings, options.Allowlist)
	}

	return report, nil
}

func filterAllowedFindings(findings []Finding, allowlist Allowlist) []Finding {
	filtered := findings[:0]
	for _, finding := range findings {
		if !allowlist.IsAllowed(finding) {
			filtered = append(filtered, finding)
		}
	}
	return filtered
}

func scanPath(path string, options Options, report *Report) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return scanFile(path, report, options.MaxFileBytes)
	}

	return filepath.WalkDir(path, func(current string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if isExcluded(current, options.Exclude) {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			report.SkippedFiles++
			return nil
		}

		name := entry.Name()
		if entry.IsDir() {
			if shouldSkipDir(name, options.IncludeHidden) && current != path {
				return filepath.SkipDir
			}
			return nil
		}

		if !options.IncludeHidden && strings.HasPrefix(name, ".") {
			report.SkippedFiles++
			return nil
		}

		return scanFile(current, report, options.MaxFileBytes)
	})
}

func shouldSkipDir(name string, includeHidden bool) bool {
	if skippedDirs[name] {
		return true
	}
	return !includeHidden && strings.HasPrefix(name, ".")
}

func isExcluded(path string, patterns []string) bool {
	cleanPath := filepath.ToSlash(filepath.Clean(path))
	for _, pattern := range patterns {
		cleanPattern := filepath.ToSlash(filepath.Clean(pattern))
		if cleanPattern == "." {
			continue
		}
		if cleanPath == cleanPattern || strings.HasPrefix(cleanPath, cleanPattern+"/") {
			return true
		}
		matched, err := filepath.Match(cleanPattern, cleanPath)
		if err == nil && matched {
			return true
		}
	}
	return false
}

func scanFile(path string, report *Report, configuredMaxBytes int) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return err
	}
	maxBytes := configuredMaxFileBytes(configuredMaxBytes)
	if stat.Size() > int64(maxBytes) {
		report.SkippedFiles++
		return nil
	}

	content, err := io.ReadAll(file)
	if err != nil {
		return err
	}
	if isBinary(content) {
		report.SkippedFiles++
		return nil
	}

	report.ScannedFiles++
	report.Findings = append(report.Findings, scanContentWithMaxBytes(path, string(content), maxBytes)...)
	return nil
}

func scanContent(path string, content string) []Finding {
	return scanContentWithMaxBytes(path, content, maxFileBytes)
}

func scanContentWithMaxBytes(path string, content string, maxBytes int) []Finding {
	var findings []Finding
	reader := strings.NewReader(content)
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), maxBytes+1)

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		for _, rule := range defaultRules {
			matches := rule.Pattern.FindAllStringIndex(line, -1)
			for _, match := range matches {
				raw := line[match[0]:match[1]]
				findings = append(findings, Finding{
					RuleID:        rule.ID,
					Severity:      rule.Severity,
					Path:          path,
					Line:          lineNumber,
					Column:        match[0] + 1,
					Message:       rule.Message,
					RedactedMatch: redact(raw),
				})
			}
		}
	}

	return findings
}

func configuredMaxFileBytes(configuredMaxBytes int) int {
	if configuredMaxBytes > 0 {
		return configuredMaxBytes
	}
	return maxFileBytes
}

func isBinary(content []byte) bool {
	if len(content) == 0 {
		return false
	}
	if bytesContain(content, 0) {
		return true
	}
	return !utf8.Valid(content)
}

func bytesContain(content []byte, needle byte) bool {
	for _, value := range content {
		if value == needle {
			return true
		}
	}
	return false
}

func redact(value string) string {
	if len(value) <= 10 {
		return strings.Repeat("*", len(value))
	}

	prefix := value[:min(4, len(value))]
	suffix := value[len(value)-min(4, len(value)):]
	return prefix + strings.Repeat("*", 8) + suffix
}

func min(left, right int) int {
	if left < right {
		return left
	}
	return right
}

var ErrFindingsDetected = errors.New("findings detected")
