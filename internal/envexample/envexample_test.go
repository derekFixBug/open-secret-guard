package envexample

import "testing"

func TestGenerateClearsValuesAndKeepsComments(t *testing.T) {
	input := stringsJoin(
		"# app settings",
		"API_"+"KEY=super-secret-value",
		"export DATABASE_"+"URL="+databaseURLFixture()+" # local database",
		"EMPTY=",
		"PLAIN_LINE",
	)

	got := Generate(input)
	want := stringsJoin(
		"# app settings",
		"API_KEY=",
		"export DATABASE_URL= # local database",
		"EMPTY=",
		"PLAIN_LINE",
	)

	if got != want {
		t.Fatalf("unexpected generated env example:\nwant:\n%s\n\ngot:\n%s", want, got)
	}
}

func TestSanitizeLineKeepsHashInsideQuotes(t *testing.T) {
	got := SanitizeLine(`PASSWORD="abc#123" # keep this comment`)
	want := "PASSWORD= # keep this comment"

	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func stringsJoin(lines ...string) string {
	result := ""
	for index, line := range lines {
		if index > 0 {
			result += "\n"
		}
		result += line
	}
	return result
}

func databaseURLFixture() string {
	return "post" + "gres://demo:password@localhost/app"
}
