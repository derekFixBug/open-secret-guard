package onepassword

import (
	"bufio"
	"net/url"
	"strings"
)

// Generate creates an op run-compatible environment template without copying source values.
func Generate(content string, vault string, item string) string {
	var builder strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		builder.WriteString(templateLine(scanner.Text(), vault, item))
		builder.WriteByte('\n')
	}

	if content != "" && !strings.HasSuffix(content, "\n") {
		return strings.TrimSuffix(builder.String(), "\n")
	}
	return builder.String()
}

func templateLine(line string, vault string, item string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return line
	}

	prefix, assignment := splitExportPrefix(line)
	separator := strings.Index(assignment, "=")
	if separator <= 0 {
		return line
	}

	key := strings.TrimSpace(assignment[:separator])
	if !isEnvironmentKey(key) {
		return line
	}

	_, comment := splitValueComment(assignment[separator+1:])
	result := prefix + key + "=op://" + url.PathEscape(vault) + "/" + url.PathEscape(item) + "/" + url.PathEscape(key)
	if comment != "" {
		return result + " " + comment
	}
	return result
}

func splitExportPrefix(line string) (string, string) {
	trimmedLeft := strings.TrimLeft(line, " \t")
	indent := line[:len(line)-len(trimmedLeft)]
	if strings.HasPrefix(trimmedLeft, "export ") {
		return indent + "export ", strings.TrimLeft(strings.TrimPrefix(trimmedLeft, "export "), " \t")
	}
	return indent, trimmedLeft
}

func splitValueComment(value string) (string, string) {
	inSingleQuote := false
	inDoubleQuote := false

	for index, char := range value {
		switch char {
		case '\'':
			if !inDoubleQuote {
				inSingleQuote = !inSingleQuote
			}
		case '"':
			if !inSingleQuote {
				inDoubleQuote = !inDoubleQuote
			}
		case '#':
			if !inSingleQuote && !inDoubleQuote && (index == 0 || isWhitespace(rune(value[index-1]))) {
				return strings.TrimSpace(value[:index]), strings.TrimSpace(value[index:])
			}
		}
	}

	return strings.TrimSpace(value), ""
}

func isEnvironmentKey(value string) bool {
	for index, char := range value {
		isLetter := (char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z')
		isDigit := char >= '0' && char <= '9'
		if !isLetter && char != '_' && (index == 0 || !isDigit) {
			return false
		}
	}
	return value != ""
}

func isWhitespace(char rune) bool {
	return char == ' ' || char == '\t'
}
