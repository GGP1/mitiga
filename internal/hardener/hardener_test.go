package hardener

import (
	"context"
	"testing"
	"time"

	"github.com/GGP1/mitiga/internal/executor"
)

func TestAssessBaseline_NoSubAgent(t *testing.T) {
	t.Helper()

	exec := executor.New(30 * time.Second)
	a := New(exec)

	// With no sub-agent configured, AssessBaseline must return nil findings.
	findings, err := a.AssessBaseline(context.Background())
	if err != nil {
		// sysctl may not be available in all test environments.
		t.Logf("AssessBaseline returned error (acceptable in constrained env): %v", err)
		return
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings without sub-agent, got %d", len(findings))
	}
}

func TestCheckSudoers_NoSubAgent(t *testing.T) {
	t.Helper()

	exec := executor.New(30 * time.Second)
	a := New(exec)

	findings, err := a.CheckSudoers(context.Background())
	if err != nil {
		t.Fatalf("CheckSudoers returned unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings without sub-agent, got %d", len(findings))
	}
}

func TestCheckCronJobs_NoSubAgent(t *testing.T) {
	t.Helper()

	exec := executor.New(30 * time.Second)
	a := New(exec)

	findings, err := a.CheckCronJobs(context.Background())
	if err != nil {
		t.Fatalf("CheckCronJobs returned unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings without sub-agent, got %d", len(findings))
	}
}
