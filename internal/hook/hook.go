package hook

import (
	"strconv"
	"strings"
)

type Options struct {
	Command        string
	AllowlistPath  string
	Exclude        string
	ExcludeFile    string
	MinSeverity    string
	FailOnSeverity string
	MaxFileBytes   int
}

func PreCommit(options Options) string {
	command := strings.TrimSpace(options.Command)
	if command == "" {
		command = "open-secret-guard"
	}

	args := []string{"scan", "."}
	if strings.TrimSpace(options.AllowlistPath) != "" {
		args = append(args, "-allowlist", shellQuote(options.AllowlistPath))
	}
	if strings.TrimSpace(options.Exclude) != "" {
		args = append(args, "-exclude", shellQuote(options.Exclude))
	}
	if strings.TrimSpace(options.ExcludeFile) != "" {
		args = append(args, "-exclude-file", shellQuote(options.ExcludeFile))
	}
	if strings.TrimSpace(options.MinSeverity) != "" {
		args = append(args, "-min-severity", shellQuote(options.MinSeverity))
	}
	if options.MaxFileBytes > 0 {
		args = append(args, "-max-file-bytes", strconv.Itoa(options.MaxFileBytes))
	}
	if strings.TrimSpace(options.FailOnSeverity) != "" {
		args = append(args, "-fail-on-severity", shellQuote(options.FailOnSeverity))
	} else {
		args = append(args, "-fail-on-findings")
	}

	return "#!/bin/sh\n" +
		"set -eu\n\n" +
		"echo \"open-secret-guard: scanning staged repository before commit\"\n" +
		command + " " + strings.Join(args, " ") + "\n"
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
