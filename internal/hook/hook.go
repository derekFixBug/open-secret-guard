package hook

import (
	"strings"
)

type Options struct {
	Command       string
	AllowlistPath string
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
	args = append(args, "-fail-on-findings")

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
