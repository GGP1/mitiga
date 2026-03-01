package audit

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/GGP1/mitiga/internal/executor"
)

func TestScanForSecrets_NoSubAgent(t *testing.T) {
	t.Helper()

	dir := t.TempDir()
	exec := executor.New(30 * time.Second)
	a := New(exec, dir)

	// With no sub-agent configured, ScanForSecrets must return nil findings.
	findings, err := a.ScanForSecrets(context.Background())
	if err != nil {
		t.Fatalf("ScanForSecrets returned unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings without sub-agent, got %d", len(findings))
	}
}

func TestScanForSecrets_NoMatches(t *testing.T) {
	t.Helper()

	dir := t.TempDir()
	// Write a file with no secret patterns.
	if err := os.WriteFile(dir+"/clean.go", []byte("package main\n\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	exec := executor.New(30 * time.Second)
	a := New(exec, dir)

	findings, err := a.ScanForSecrets(context.Background())
	if err != nil {
		t.Fatalf("ScanForSecrets returned unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for clean file, got %d", len(findings))
	}
}
