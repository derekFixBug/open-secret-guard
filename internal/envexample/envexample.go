package envexample

import (
	"bufio"
	"strings"
)

func Generate(content string) string {
	var builder strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		builder.WriteString(SanitizeLine(scanner.Text()))
		builder.WriteByte('\n')
	}

	if content != "" && !strings.HasSuffix(content, "\n") {
		return strings.TrimSuffix(builder.String(), "\n")
	}
	return builder.String()
}

func SanitizeLine(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return line
	}

	prefix, assignment, ok := splitExportPrefix(line)
	if !ok {
		return line
	}

	separator := strings.Index(assignment, "=")
	if separator <= 0 {
		return line
	}

	key := strings.TrimSpace(assignment[:separator])
	if key == "" {
		return line
	}

	_, comment := splitValueComment(assignment[separator+1:])
	if comment != "" {
		return prefix + key + "= " + comment
	}
	return prefix + key + "="
}

func splitExportPrefix(line string) (string, string, bool) {
	trimmedLeft := strings.TrimLeft(line, " \t")
	indent := line[:len(line)-len(trimmedLeft)]
	if strings.HasPrefix(trimmedLeft, "export ") {
		return indent + "export ", strings.TrimLeft(strings.TrimPrefix(trimmedLeft, "export "), " \t"), true
	}
	return indent, trimmedLeft, true
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
			if inSingleQuote || inDoubleQuote {
				continue
			}
			if index == 0 || isWhitespace(rune(value[index-1])) {
				return strings.TrimSpace(value[:index]), strings.TrimSpace(value[index:])
			}
		}
	}

	return strings.TrimSpace(value), ""
}

func isWhitespace(char rune) bool {
	return char == ' ' || char == '\t'
}
