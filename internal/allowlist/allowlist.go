package allowlist

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/derekFixBug/open-secret-guard/internal/scanner"
)

type Entry struct {
	RuleID      string `json:"ruleId"`
	PathPattern string `json:"pathPattern"`
	Line        int    `json:"line,omitempty"`
}

func Load(path string) ([]Entry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var entries []Entry
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entry, err := parseLine(line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, lineNumber, err)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return entries, nil
}

func IsAllowed(finding scanner.Finding, entries []Entry) bool {
	for _, entry := range entries {
		if entry.RuleID != finding.RuleID {
			continue
		}
		if entry.Line != 0 && entry.Line != finding.Line {
			continue
		}
		if matchPath(entry.PathPattern, finding.Path) {
			return true
		}
	}
	return false
}

func parseLine(line string) (Entry, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 || len(fields) > 3 {
		return Entry{}, fmt.Errorf("expected: rule-id path-glob [line]")
	}

	entry := Entry{
		RuleID:      fields[0],
		PathPattern: filepath.ToSlash(filepath.Clean(fields[1])),
	}
	if entry.RuleID == "" || entry.PathPattern == "" || entry.PathPattern == "." {
		return Entry{}, fmt.Errorf("rule id and path pattern are required")
	}

	if len(fields) == 3 {
		lineNumber, err := strconv.Atoi(fields[2])
		if err != nil || lineNumber <= 0 {
			return Entry{}, fmt.Errorf("line must be a positive integer")
		}
		entry.Line = lineNumber
	}

	return entry, nil
}

func matchPath(pattern string, path string) bool {
	cleanPattern := filepath.ToSlash(filepath.Clean(pattern))
	cleanPath := filepath.ToSlash(filepath.Clean(path))

	if cleanPattern == cleanPath {
		return true
	}

	matched, err := filepath.Match(cleanPattern, cleanPath)
	return err == nil && matched
}
