// Package protocol defines shared types used across Mitiga packages.
package protocol

import (
	"errors"
	"time"
)

// Sentinel errors per §8.
var (
	// ErrUnauthorized indicates an authentication or authorization failure.
	ErrUnauthorized = errors.New("unauthorized")
	// ErrCommandDenied indicates a command was rejected by the allowlist.
	ErrCommandDenied = errors.New("command denied")
	// ErrTimeout indicates an operation exceeded its deadline.
	ErrTimeout = errors.New("timeout")
	// ErrUnverifiable indicates a tool binary could not be verified.
	ErrUnverifiable = errors.New("tool unverifiable")
	// ErrHashMismatch indicates a checksum validation failure.
	ErrHashMismatch = errors.New("hash mismatch")
)

// Severity represents a threat or finding severity level per §4.4.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding represents a single security finding in a report per §10.1.
type Finding struct {
	// ID is a unique identifier for this finding.
	ID string `json:"id"`
	// Severity indicates the impact level.
	Severity Severity `json:"severity"`
	// Category classifies the finding (e.g., open-port, unauthorized-user).
	Category string `json:"category"`
	// Description explains what was found.
	Description string `json:"description"`
	// Evidence contains supporting data (log entries, scan results, paths).
	Evidence []string `json:"evidence"`
	// Impact describes the potential consequence if unaddressed.
	Impact string `json:"impact"`
	// Recommendation provides specific remediation steps.
	Recommendation string `json:"recommendation"`
	// Timestamp is when the finding was detected.
	Timestamp time.Time `json:"timestamp"`
}

// AgentState represents the agent's lifecycle state per §11.
type AgentState string

const (
	StateInit     AgentState = "INIT"
	StateMonitor  AgentState = "MONITOR"
	StateShutdown AgentState = "SHUTDOWN"
)

// EventType classifies the trigger that produced an Event.
type EventType string

const (
	// EventTypeStartup fires once when the agent enters the monitor phase.
	EventTypeStartup EventType = "startup"
	// EventTypeScheduledScan fires on each periodic scan ticker.
	EventTypeScheduledScan EventType = "scheduled_scan"
	// EventTypeFilesystemChange fires when a watched path is modified.
	EventTypeFilesystemChange EventType = "filesystem_change"
	// EventTypeHeartbeat fires on the heartbeat ticker.
	EventTypeHeartbeat EventType = "heartbeat"
)

// Event is a discrete, immutable trigger that drives the agent's processing
// loop.  Producers (timers, filesystem watchers) emit events; the single
// consumer loop dispatches each one to the appropriate handler.
type Event struct {
	// ID is a unique identifier for this event instance.
	ID string `json:"id"`
	// Type classifies the trigger.
	Type EventType `json:"type"`
	// Source identifies the producer (e.g., "timer:scan", "fs:/etc/passwd").
	Source string `json:"source"`
	// Payload holds optional key/value data supplied by the producer.
	Payload map[string]string `json:"payload,omitempty"`
	// Timestamp is when the event was produced (UTC).
	Timestamp time.Time `json:"timestamp"`
}
