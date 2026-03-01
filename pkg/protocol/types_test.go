package protocol

import (
	"testing"
	"time"
)

func TestSentinelErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		msg  string
	}{
		{"unauthorized", ErrUnauthorized, "unauthorized"},
		{"command denied", ErrCommandDenied, "command denied"},
		{"timeout", ErrTimeout, "timeout"},
		{"unverifiable", ErrUnverifiable, "tool unverifiable"},
		{"hash mismatch", ErrHashMismatch, "hash mismatch"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Error() != tc.msg {
				t.Errorf("error message: got %q, want %q", tc.err.Error(), tc.msg)
			}
		})
	}
}

func TestSeverityValues(t *testing.T) {
	tests := []struct {
		severity Severity
		want     string
	}{
		{SeverityCritical, "CRITICAL"},
		{SeverityHigh, "HIGH"},
		{SeverityMedium, "MEDIUM"},
		{SeverityLow, "LOW"},
		{SeverityInfo, "INFO"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if string(tc.severity) != tc.want {
				t.Errorf("severity: got %q, want %q", tc.severity, tc.want)
			}
		})
	}
}

func TestAgentStateValues(t *testing.T) {
	tests := []struct {
		state AgentState
		want  string
	}{
		{StateInit, "INIT"},
		{StateMonitor, "MONITOR"},
		{StateShutdown, "SHUTDOWN"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if string(tc.state) != tc.want {
				t.Errorf("state: got %q, want %q", tc.state, tc.want)
			}
		})
	}
}

func TestEventTypeValues(t *testing.T) {
	tests := []struct {
		eventType EventType
		want      string
	}{
		{EventTypeStartup, "startup"},
		{EventTypeScheduledScan, "scheduled_scan"},
		{EventTypeFilesystemChange, "filesystem_change"},
		{EventTypeHeartbeat, "heartbeat"},
	}

	for _, tc := range tests {
		t.Run(tc.want, func(t *testing.T) {
			if string(tc.eventType) != tc.want {
				t.Errorf("event type: got %q, want %q", tc.eventType, tc.want)
			}
		})
	}
}

func TestEvent_Fields(t *testing.T) {
	now := time.Now().UTC()
	ev := Event{
		ID:        "evt-001",
		Type:      EventTypeScheduledScan,
		Source:    "timer:scan",
		Payload:   map[string]string{"key": "value"},
		Timestamp: now,
	}

	if ev.ID != "evt-001" {
		t.Errorf("ID: got %q, want %q", ev.ID, "evt-001")
	}
	if ev.Type != EventTypeScheduledScan {
		t.Errorf("Type: got %q, want %q", ev.Type, EventTypeScheduledScan)
	}
	if ev.Source != "timer:scan" {
		t.Errorf("Source: got %q, want %q", ev.Source, "timer:scan")
	}
	if ev.Payload["key"] != "value" {
		t.Errorf("Payload[key]: got %q, want %q", ev.Payload["key"], "value")
	}
	if !ev.Timestamp.Equal(now) {
		t.Errorf("Timestamp: got %v, want %v", ev.Timestamp, now)
	}
}
