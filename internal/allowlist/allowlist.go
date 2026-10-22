package allowlist

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/derekFixBug/open-secret-guard/internal/scanner"
)

type Entry struct {
	RuleID      string    `json:"ruleId"`
	PathPattern string    `json:"pathPattern"`
	Line        int       `json:"line,omitempty"`
	ExpiresAt   time.Time `json:"expiresAt,omitempty"`
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
	return IsAllowedAt(finding, entries, time.Now().UTC())
}

func IsAllowedAt(finding scanner.Finding, entries []Entry, now time.Time) bool {
	for _, entry := range entries {
		if !entry.ExpiresAt.IsZero() && !now.Before(entry.ExpiresAt.AddDate(0, 0, 1)) {
			continue
		}
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

func Validate(entries []Entry, rules []scanner.RuleMetadata) error {
	return ValidateAt(entries, rules, time.Now().UTC())
}

func ValidateAt(entries []Entry, rules []scanner.RuleMetadata, now time.Time) error {
	knownRules := make(map[string]bool, len(rules))
	for _, rule := range rules {
		knownRules[rule.ID] = true
	}

	seen := make(map[string]int, len(entries))
	for index, entry := range entries {
		entryNumber := index + 1
		if !knownRules[entry.RuleID] {
			return fmt.Errorf("entry %d uses unknown rule ID %q", entryNumber, entry.RuleID)
		}
		if _, err := filepath.Match(entry.PathPattern, ""); err != nil {
			return fmt.Errorf("entry %d has invalid path glob %q: %w", entryNumber, entry.PathPattern, err)
		}
		if !entry.ExpiresAt.IsZero() && !now.Before(entry.ExpiresAt.AddDate(0, 0, 1)) {
			return fmt.Errorf("entry %d expired on %s", entryNumber, entry.ExpiresAt.Format(time.DateOnly))
		}

		key := fmt.Sprintf("%s\x00%s\x00%d", entry.RuleID, entry.PathPattern, entry.Line)
		if previous, exists := seen[key]; exists {
			return fmt.Errorf("entry %d duplicates entry %d", entryNumber, previous)
		}
		seen[key] = entryNumber
	}

	return nil
}

// ExpiringWithin returns entries whose inclusive expiry date falls between now
// and now plus days. Expired entries are excluded because ValidateAt reports
// those separately.
func ExpiringWithin(entries []Entry, now time.Time, days int) []Entry {
	if days < 0 {
		return nil
	}

	now = now.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	latest := today.AddDate(0, 0, days)

	var expiring []Entry
	for _, entry := range entries {
		if entry.ExpiresAt.IsZero() || entry.ExpiresAt.Before(today) || entry.ExpiresAt.After(latest) {
			continue
		}
		expiring = append(expiring, entry)
	}
	return expiring
}

// ExpiringAfter returns active entries whose inclusive expiry date is later
// than now plus days. Entries without an expiry date are excluded.
func ExpiringAfter(entries []Entry, now time.Time, days int) []Entry {
	if days < 0 {
		return nil
	}

	now = now.UTC()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	latest := today.AddDate(0, 0, days)

	var expiring []Entry
	for _, entry := range entries {
		if entry.ExpiresAt.After(latest) {
			expiring = append(expiring, entry)
		}
	}
	return expiring
}

func parseLine(line string) (Entry, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 || len(fields) > 4 {
		return Entry{}, fmt.Errorf("expected: rule-id path-glob [line] [expires-on]")
	}

	entry := Entry{
		RuleID:      fields[0],
		PathPattern: filepath.ToSlash(filepath.Clean(fields[1])),
	}
	if entry.RuleID == "" || entry.PathPattern == "" || entry.PathPattern == "." {
		return Entry{}, fmt.Errorf("rule id and path pattern are required")
	}

	for _, field := range fields[2:] {
		if lineNumber, err := strconv.Atoi(field); err == nil {
			if lineNumber <= 0 || entry.Line != 0 {
				return Entry{}, fmt.Errorf("line must be a positive integer")
			}
			entry.Line = lineNumber
			continue
		}

		expiresAt, err := time.Parse(time.DateOnly, field)
		if err != nil || !entry.ExpiresAt.IsZero() {
			return Entry{}, fmt.Errorf("expires-on must be a YYYY-MM-DD date")
		}
		entry.ExpiresAt = expiresAt
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
