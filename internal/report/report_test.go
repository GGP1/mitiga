package report

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/GGP1/mitiga/pkg/protocol"
)

func TestNew(t *testing.T) {
	r := New("test-001", "agent-abc", "testhost", "scan")

	if r.ID != "test-001" {
		t.Errorf("ID: got %q, want %q", r.ID, "test-001")
	}
	if r.AgentID != "agent-abc" {
		t.Errorf("AgentID: got %q, want %q", r.AgentID, "agent-abc")
	}
	if r.Hostname != "testhost" {
		t.Errorf("Hostname: got %q, want %q", r.Hostname, "testhost")
	}
	if r.Type != "scan" {
		t.Errorf("Type: got %q, want %q", r.Type, "scan")
	}
	if len(r.Findings) != 0 {
		t.Errorf("Findings: got %d, want 0", len(r.Findings))
	}
}

func TestAddFindings_SortsBySeverity(t *testing.T) {
	r := New("test-002", "agent-abc", "testhost", "scan")

	r.AddFindings([]protocol.Finding{
		{ID: "low-1", Severity: protocol.SeverityLow},
		{ID: "crit-1", Severity: protocol.SeverityCritical},
		{ID: "med-1", Severity: protocol.SeverityMedium},
		{ID: "high-1", Severity: protocol.SeverityHigh},
		{ID: "info-1", Severity: protocol.SeverityInfo},
	})

	if len(r.Findings) != 5 {
		t.Fatalf("expected 5 findings, got %d", len(r.Findings))
	}

	expectedOrder := []protocol.Severity{
		protocol.SeverityCritical,
		protocol.SeverityHigh,
		protocol.SeverityMedium,
		protocol.SeverityLow,
		protocol.SeverityInfo,
	}

	for i, expected := range expectedOrder {
		if r.Findings[i].Severity != expected {
			t.Errorf("findings[%d].Severity: got %q, want %q", i, r.Findings[i].Severity, expected)
		}
	}
}

func TestGenerateSummary_NoFindings(t *testing.T) {
	r := New("test", "agent", "host", "scan")
	r.GenerateSummary()

	if r.Summary == "" {
		t.Error("summary should not be empty")
	}
}

func TestGenerateSummary_WithFindings(t *testing.T) {
	r := New("test", "agent", "host", "scan")
	r.AddFindings([]protocol.Finding{
		{ID: "f1", Severity: protocol.SeverityCritical},
		{ID: "f2", Severity: protocol.SeverityHigh},
		{ID: "f3", Severity: protocol.SeverityHigh},
	})
	r.GenerateSummary()

	if r.Summary == "" {
		t.Error("summary should not be empty")
	}
}

func TestAddAction(t *testing.T) {
	r := New("test", "agent", "host", "scan")
	r.AddAction("blocked IP 10.0.0.5", "success")

	if len(r.Actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(r.Actions))
	}
	if r.Actions[0].Description != "blocked IP 10.0.0.5" {
		t.Errorf("action desc: got %q", r.Actions[0].Description)
	}
	if r.Actions[0].Outcome != "success" {
		t.Errorf("action outcome: got %q", r.Actions[0].Outcome)
	}
	if r.Actions[0].Timestamp.IsZero() {
		t.Error("action timestamp should not be zero")
	}
}

func TestWriteJSON(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	r := New("test-json", "agent-1", "testhost", "scan")
	r.Timestamp = time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	r.AddFindings([]protocol.Finding{
		{ID: "PORT-8080", Severity: protocol.SeverityMedium, Category: "open-port"},
	})
	r.GenerateSummary()

	path, err := r.WriteJSON(ctx, dir)
	if err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	if filepath.Dir(path) != dir {
		t.Errorf("output dir: got %q, want %q", filepath.Dir(path), dir)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	var parsed Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if parsed.ID != "test-json" {
		t.Errorf("parsed ID: got %q, want %q", parsed.ID, "test-json")
	}
	if len(parsed.Findings) != 1 {
		t.Errorf("parsed findings: got %d, want 1", len(parsed.Findings))
	}
}

func TestWriteMarkdown(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	r := New("test-md", "agent-2", "testhost", "audit")
	r.Timestamp = time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	r.AddFindings([]protocol.Finding{
		{ID: "UID0-backdoor", Severity: protocol.SeverityCritical, Category: "unauthorized-user"},
	})
	r.GenerateSummary()

	path, err := r.WriteMarkdown(ctx, dir)
	if err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if len(string(data)) < 50 {
		t.Errorf("markdown too short: %d bytes", len(data))
	}
}
