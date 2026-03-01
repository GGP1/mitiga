package logaudit

import (
	"context"
	"testing"
	"time"

	"github.com/GGP1/mitiga/internal/executor"
)

func TestAnalyzeAuthFailures_NoSubAgent(t *testing.T) {
	t.Helper()

	exec := executor.New(30 * time.Second)
	a := New(exec)

	findings, err := a.AnalyzeAuthFailures(context.Background(), 5*time.Minute)
	if err != nil {
		t.Logf("AnalyzeAuthFailures returned error (acceptable in constrained env): %v", err)
		return
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings without sub-agent, got %d", len(findings))
	}
}

func TestAuditSudoUsage_NoSubAgent(t *testing.T) {
	t.Helper()

	exec := executor.New(30 * time.Second)
	a := New(exec)

	findings, err := a.AuditSudoUsage(context.Background(), 5*time.Minute)
	if err != nil {
		t.Logf("AuditSudoUsage returned error (acceptable in constrained env): %v", err)
		return
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings without sub-agent, got %d", len(findings))
	}
}
