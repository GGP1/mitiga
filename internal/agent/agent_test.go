package agent

import (
	"context"
	"testing"
	"time"

	"github.com/GGP1/mitiga/internal/config"
	"github.com/GGP1/mitiga/pkg/protocol"
)

func TestNew(t *testing.T) {
	cfg := config.Default()
	a := New(cfg)

	if a.State() != protocol.StateInit {
		t.Errorf("initial state: got %q, want %q", a.State(), protocol.StateInit)
	}

	if len(a.Findings()) != 0 {
		t.Errorf("initial findings: got %d, want 0", len(a.Findings()))
	}
}

func TestAddFinding(t *testing.T) {
	cfg := config.Default()
	a := New(cfg)

	a.AddFinding(protocol.Finding{
		ID:       "TEST-001",
		Severity: protocol.SeverityHigh,
		Category: "test",
	})

	findings := a.Findings()
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	if findings[0].ID != "TEST-001" {
		t.Errorf("finding ID: got %q, want %q", findings[0].ID, "TEST-001")
	}

	if findings[0].Timestamp.IsZero() {
		t.Error("finding timestamp should be set by AddFinding")
	}
}

func TestFindings_ReturnsCopy(t *testing.T) {
	cfg := config.Default()
	a := New(cfg)

	a.AddFinding(protocol.Finding{ID: "A"})

	findings := a.Findings()
	findings[0].ID = "MODIFIED"

	// Original should be unchanged.
	if a.Findings()[0].ID != "A" {
		t.Error("Findings() should return a copy, not a reference")
	}
}

func TestClearFindings(t *testing.T) {
	cfg := config.Default()
	a := New(cfg)

	a.AddFinding(protocol.Finding{ID: "A"})
	a.AddFinding(protocol.Finding{ID: "B"})

	if len(a.Findings()) != 2 {
		t.Fatalf("expected 2 findings before clear, got %d", len(a.Findings()))
	}

	a.ClearFindings()

	if len(a.Findings()) != 0 {
		t.Errorf("expected 0 findings after clear, got %d", len(a.Findings()))
	}
}

func TestSetState(t *testing.T) {
	cfg := config.Default()
	a := New(cfg)

	ctx := context.Background()
	a.setState(ctx, protocol.StateMonitor)

	if a.State() != protocol.StateMonitor {
		t.Errorf("state: got %q, want %q", a.State(), protocol.StateMonitor)
	}
}

func TestRun_ShutdownOnCancel(t *testing.T) {
	cfg := config.Default()
	// Use temp dir for reports and logs to avoid permission issues.
	cfg.Report.OutputDir = t.TempDir()
	cfg.Agent.LogFile = t.TempDir() + "/test.log"

	a := New(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// Run should return without error when context is cancelled.
	err := a.Run(ctx)
	if err != nil {
		t.Fatalf("Run should return nil on context cancellation: %v", err)
	}

	// Agent should reach SHUTDOWN state.
	if a.State() != protocol.StateShutdown {
		t.Errorf("final state: got %q, want %q", a.State(), protocol.StateShutdown)
	}
}
