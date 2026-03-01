// Package state manages the persistent agent snapshot that survives restarts.
//
// The Snapshot captures the agent's meaningful runtime state — recent
// findings, LLM insights, and event statistics.  It is written to disk as
// JSON after every processing cycle so the next run has full context of what
// was observed before.
//
// Writes use an atomic rename strategy (write to a temp file, then rename)
// to prevent a partial write from corrupting the stored state.  Logs are
// append-only; the state file is the only piece of mutable persistent data
// managed by this package.
package state

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/GGP1/mitiga/internal/logger"
	"github.com/GGP1/mitiga/pkg/protocol"
)

// Snapshot is the serializable representation of agent state persisted across
// process restarts.
type Snapshot struct {
	// AgentID is the identifier of the agent that produced this snapshot.
	AgentID string `json:"agent_id"`
	// UpdatedAt is the UTC timestamp of the last write.
	UpdatedAt time.Time `json:"updated_at"`
	// Findings is the set of security findings accumulated since the last
	// report was generated.
	Findings []protocol.Finding `json:"findings"`
	// LLMInsights holds summary text and recommendations returned by the
	// local LLM advisory endpoint.
	LLMInsights []string `json:"llm_insights"`
	// EventCounts tracks how many events of each type have been processed
	// in the current run, for diagnostic and reporting purposes.
	EventCounts map[string]int64 `json:"event_counts"`
}

// Store reads and writes the agent Snapshot to a file on disk.
//
// Every Save atomically updates the current-state file AND appends a record to
// an append-only JSONL history file so that all prior states are available for
// auditing.  The history file path is derived from the state file path by
// replacing the extension with ".history.jsonl".
type Store struct {
	path        string
	historyPath string
}

// NewStore creates a Store that persists state at the given file path.
// The history log is placed alongside the state file with a ".history.jsonl"
// extension.
func NewStore(path string) *Store {
	ext := filepath.Ext(path)
	history := strings.TrimSuffix(path, ext) + ".history.jsonl"
	return &Store{path: path, historyPath: history}
}

// HistoryPath returns the path of the append-only history log.
func (s *Store) HistoryPath() string {
	return s.historyPath
}

// Load reads the Snapshot from disk.  If the file does not exist a fresh,
// empty Snapshot is returned without error.
func (s *Store) Load(ctx context.Context, agentID string) (*Snapshot, error) {
	ctx = logger.WithComponent(ctx, "state")

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			logger.Info(ctx, "no prior state file found, starting fresh",
				"path", s.path,
			)
			return s.empty(agentID), nil
		}
		return nil, fmt.Errorf("state: read %s: %w", s.path, err)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		// A corrupt state file is a recoverable error: log and start fresh
		// rather than aborting the agent.
		logger.Warn(ctx, "state file corrupt, starting fresh",
			"path", s.path,
			"error", err.Error(),
		)
		return s.empty(agentID), nil
	}

	logger.Info(ctx, "prior state restored",
		"path", s.path,
		"findings", len(snap.Findings),
		"llm_insights", len(snap.LLMInsights),
		"updated_at", snap.UpdatedAt,
	)

	return &snap, nil
}

// Save atomically writes the Snapshot to disk.  It creates the parent
// directory if it does not exist, writes to a temp file, then renames to
// the target path to avoid partial writes.
func (s *Store) Save(ctx context.Context, snap *Snapshot) error {
	ctx = logger.WithComponent(ctx, "state")

	snap.UpdatedAt = time.Now().UTC()

	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("state: marshal snapshot: %w", err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("state: create directory %s: %w", dir, err)
	}

	// Write to a sibling temp file then rename for atomicity.
	tmp := s.path + ".tmp"
	//nolint:gosec — 0o600 is intentionally restrictive for state files.
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("state: write temp file %s: %w", tmp, err)
	}

	if err := os.Rename(tmp, s.path); err != nil {
		// Best-effort cleanup of the temp file.
		_ = os.Remove(tmp)
		return fmt.Errorf("state: rename %s → %s: %w", tmp, s.path, err)
	}

	logger.Debug(ctx, "state persisted",
		"path", s.path,
		"findings", len(snap.Findings),
		"llm_insights", len(snap.LLMInsights),
	)

	// Append to the audit history log after the atomic rename succeeds.
	s.appendHistory(ctx, snap)

	return nil
}

// appendHistory appends the snapshot as a single JSON line to the append-only
// history log.  Failures are logged as warnings — a missing history entry is
// recoverable, but a corrupted current-state file is not.
func (s *Store) appendHistory(ctx context.Context, snap *Snapshot) {
	dir := filepath.Dir(s.historyPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		logger.Warn(ctx, "failed to create history directory",
			"path", s.historyPath,
			"error", err.Error(),
		)
		return
	}

	//nolint:gosec — 0o600 is intentionally restrictive.
	f, err := os.OpenFile(s.historyPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		logger.Warn(ctx, "failed to open history file",
			"path", s.historyPath,
			"error", err.Error(),
		)
		return
	}
	defer f.Close()

	data, err := json.Marshal(snap)
	if err != nil {
		logger.Warn(ctx, "failed to marshal snapshot for history",
			"error", err.Error(),
		)
		return
	}

	if _, err := fmt.Fprintf(f, "%s\n", data); err != nil {
		logger.Warn(ctx, "failed to write history entry",
			"path", s.historyPath,
			"error", err.Error(),
		)
	}
}

// LoadHistory reads all historical snapshots from the append-only JSONL log in
// chronological order (oldest first).  Corrupt lines are skipped with a
// warning so a single bad entry does not prevent access to other records.
// Returns an empty slice when no history file exists yet.
func (s *Store) LoadHistory(ctx context.Context) ([]Snapshot, error) {
	ctx = logger.WithComponent(ctx, "state")

	f, err := os.Open(s.historyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []Snapshot{}, nil
		}
		return nil, fmt.Errorf("state: open history %s: %w", s.historyPath, err)
	}
	defer f.Close()

	// Use a 1 MiB per-line buffer to accommodate snapshots with many findings.
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)

	var snapshots []Snapshot
	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var snap Snapshot
		if err := json.Unmarshal(line, &snap); err != nil {
			logger.Warn(ctx, "history entry corrupt, skipping",
				"history_file", s.historyPath,
				"line", lineNum,
				"error", err.Error(),
			)
			continue
		}
		snapshots = append(snapshots, snap)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("state: scan history %s: %w", s.historyPath, err)
	}

	logger.Info(ctx, "history loaded",
		"path", s.historyPath,
		"entries", len(snapshots),
	)
	return snapshots, nil
}

// empty returns a zero-value Snapshot for the given agent.
func (s *Store) empty(agentID string) *Snapshot {
	return &Snapshot{
		AgentID:     agentID,
		UpdatedAt:   time.Now().UTC(),
		Findings:    make([]protocol.Finding, 0),
		LLMInsights: make([]string, 0),
		EventCounts: make(map[string]int64),
	}
}
