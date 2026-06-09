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
