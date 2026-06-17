package hook

import "testing"

func TestPreCommitUsesDefaultCommand(t *testing.T) {
	got := PreCommit(Options{AllowlistPath: ".open-secret-guard.allowlist"})

	assertContains(t, got, "#!/bin/sh")
	assertContains(t, got, "open-secret-guard scan . -allowlist '.open-secret-guard.allowlist' -fail-on-findings")
}

func TestPreCommitAllowsCustomCommand(t *testing.T) {
	got := PreCommit(Options{Command: "go run ./cmd/open-secret-guard"})

	assertContains(t, got, "go run ./cmd/open-secret-guard scan . -fail-on-findings")
}

func TestPreCommitQuotesAllowlistPath(t *testing.T) {
	got := PreCommit(Options{AllowlistPath: "config/team's allowlist.txt"})

	assertContains(t, got, "-allowlist 'config/team'\"'\"'s allowlist.txt'")
}

func assertContains(t *testing.T, value string, substring string) {
	t.Helper()
	if !stringsContains(value, substring) {
		t.Fatalf("expected %q to contain %q", value, substring)
	}
}

func stringsContains(value string, substring string) bool {
	for index := 0; index+len(substring) <= len(value); index++ {
		if value[index:index+len(substring)] == substring {
			return true
		}
	}
	return false
}
