package main

import "testing"

func TestNormalizeScanArgsAllowsFlagsAfterPaths(t *testing.T) {
	args := normalizeScanArgs([]string{"examples", "-format", "sarif", "-allowlist", ".open-secret-guard.allowlist", "-include-hidden"})

	want := []string{"-format", "sarif", "-allowlist", ".open-secret-guard.allowlist", "-include-hidden", "examples"}
	if len(args) != len(want) {
		t.Fatalf("expected %d args, got %d: %#v", len(want), len(args), args)
	}

	for index := range want {
		if args[index] != want[index] {
			t.Fatalf("arg %d: expected %q, got %q", index, want[index], args[index])
		}
	}
}

func TestLoadAllowlistReturnsNilInterfaceWhenUnset(t *testing.T) {
	matcher, err := loadAllowlist("")
	if err != nil {
		t.Fatalf("load allowlist: %v", err)
	}
	if matcher != nil {
		t.Fatalf("expected nil matcher, got %#v", matcher)
	}
}

func TestNormalizeEnvExampleArgsAllowsOutputAfterPath(t *testing.T) {
	args := normalizeEnvExampleArgs([]string{".env", "-output", ".env.example"})

	want := []string{"-output", ".env.example", ".env"}
	if len(args) != len(want) {
		t.Fatalf("expected %d args, got %d: %#v", len(want), len(args), args)
	}

	for index := range want {
		if args[index] != want[index] {
			t.Fatalf("arg %d: expected %q, got %q", index, want[index], args[index])
		}
	}
}

func TestNormalizeInstallHookArgsAllowsFlagsInAnyOrder(t *testing.T) {
	args := normalizeInstallHookArgs([]string{"-allowlist", ".open-secret-guard.allowlist", "-output", ".git/hooks/pre-commit"})

	want := []string{"-allowlist", ".open-secret-guard.allowlist", "-output", ".git/hooks/pre-commit"}
	if len(args) != len(want) {
		t.Fatalf("expected %d args, got %d: %#v", len(want), len(args), args)
	}

	for index := range want {
		if args[index] != want[index] {
			t.Fatalf("arg %d: expected %q, got %q", index, want[index], args[index])
		}
	}
}
