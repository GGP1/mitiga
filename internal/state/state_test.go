package state

import (
"context"
"os"
"path/filepath"
"testing"
"time"

"github.com/GGP1/mitiga/pkg/protocol"
)

func TestLoad_FreshStart(t *testing.T) {
t.Helper()
dir := t.TempDir()
s := NewStore(filepath.Join(dir, "state.json"))

snap, err := s.Load(context.Background(), "agent-1")
if err != nil {
t.Fatalf("unexpected error: %v", err)
}
if snap.AgentID != "agent-1" {
t.Errorf("AgentID: got %q, want %q", snap.AgentID, "agent-1")
}
if len(snap.Findings) != 0 {
t.Errorf("Findings: got %d, want 0", len(snap.Findings))
}
if len(snap.LLMInsights) != 0 {
t.Errorf("LLMInsights: got %d, want 0", len(snap.LLMInsights))
}
}

func TestSave_And_Load_RoundTrip(t *testing.T) {
t.Helper()
dir := t.TempDir()
s := NewStore(filepath.Join(dir, "state.json"))

original := &Snapshot{
AgentID: "agent-42",
Findings: []protocol.Finding{
{
ID:        "F-001",
Severity:  protocol.SeverityHigh,
Category:  "open-port",
Timestamp: time.Now().UTC().Truncate(time.Second),
},
},
LLMInsights: []string{"patch immediately"},
EventCounts: map[string]int64{"scheduled_scan": 3},
}

if err := s.Save(context.Background(), original); err != nil {
t.Fatalf("Save: unexpected error: %v", err)
}

loaded, err := s.Load(context.Background(), "agent-42")
if err != nil {
t.Fatalf("Load: unexpected error: %v", err)
}
if loaded.AgentID != original.AgentID {
t.Errorf("AgentID: got %q, want %q", loaded.AgentID, original.AgentID)
}
if len(loaded.Findings) != 1 {
t.Fatalf("Findings count: got %d, want 1", len(loaded.Findings))
}
if loaded.Findings[0].ID != "F-001" {
t.Errorf("Finding ID: got %q, want F-001", loaded.Findings[0].ID)
}
if loaded.LLMInsights[0] != "patch immediately" {
t.Errorf("LLMInsight: got %q, want %q", loaded.LLMInsights[0], "patch immediately")
}
if loaded.EventCounts["scheduled_scan"] != 3 {
t.Errorf("EventCount[scheduled_scan]: got %d, want 3", loaded.EventCounts["scheduled_scan"])
}
if loaded.UpdatedAt.IsZero() {
t.Error("UpdatedAt must be set by Save")
}
}

func TestLoad_CorruptFile_ReturnsFresh(t *testing.T) {
t.Helper()
dir := t.TempDir()
path := filepath.Join(dir, "state.json")
if err := os.WriteFile(path, []byte("not valid json {{{{"), 0o600); err != nil {
t.Fatal(err)
}

s := NewStore(path)
snap, err := s.Load(context.Background(), "agent-x")
if err != nil {
t.Fatalf("unexpected error for corrupt file: %v", err)
}
if len(snap.Findings) != 0 {
t.Errorf("expected empty findings for fresh state, got %d", len(snap.Findings))
}
}

func TestSave_CreatesParentDirectory(t *testing.T) {
t.Helper()
dir := t.TempDir()
path := filepath.Join(dir, "deep", "nested", "state.json")
s := NewStore(path)

if err := s.Save(context.Background(), s.empty("agent-y")); err != nil {
t.Fatalf("Save with missing parent dir: %v", err)
}
if _, err := os.Stat(path); err != nil {
t.Errorf("state file not created: %v", err)
}
}

func TestHistoryPath_DerivedFromStatePath(t *testing.T) {
s := NewStore("/var/lib/mitiga/state.json")
want := "/var/lib/mitiga/state.history.jsonl"
if s.HistoryPath() != want {
t.Errorf("HistoryPath: got %q, want %q", s.HistoryPath(), want)
}
}

func TestSave_AppendsToHistory(t *testing.T) {
t.Helper()
dir := t.TempDir()
s := NewStore(filepath.Join(dir, "state.json"))
ctx := context.Background()

// Save twice — history must accumulate both records.
for i := range 2 {
snap := &Snapshot{
AgentID:     "agent-h",
Findings:    []protocol.Finding{{ID: "F-" + string(rune('A'+i))}},
LLMInsights: make([]string, 0),
EventCounts: make(map[string]int64),
}
if err := s.Save(ctx, snap); err != nil {
t.Fatalf("Save %d: %v", i, err)
}
}

if _, err := os.Stat(s.HistoryPath()); err != nil {
t.Fatalf("history file not created: %v", err)
}

history, err := s.LoadHistory(ctx)
if err != nil {
t.Fatalf("LoadHistory: %v", err)
}
if len(history) != 2 {
t.Errorf("history entries: got %d, want 2", len(history))
}
}

func TestLoadHistory_Empty(t *testing.T) {
t.Helper()
dir := t.TempDir()
s := NewStore(filepath.Join(dir, "state.json"))

history, err := s.LoadHistory(context.Background())
if err != nil {
t.Fatalf("unexpected error: %v", err)
}
if len(history) != 0 {
t.Errorf("expected empty history, got %d entries", len(history))
}
}

func TestLoadHistory_MultipleEntries_Ordered(t *testing.T) {
t.Helper()
dir := t.TempDir()
s := NewStore(filepath.Join(dir, "state.json"))
ctx := context.Background()

ids := []string{"F-001", "F-002", "F-003"}
for _, id := range ids {
snap := &Snapshot{
AgentID:     "agent-ord",
Findings:    []protocol.Finding{{ID: id, Timestamp: time.Now().UTC()}},
LLMInsights: make([]string, 0),
EventCounts: make(map[string]int64),
}
if err := s.Save(ctx, snap); err != nil {
t.Fatalf("Save %s: %v", id, err)
}
}

history, err := s.LoadHistory(ctx)
if err != nil {
t.Fatalf("LoadHistory: %v", err)
}
if len(history) != 3 {
t.Fatalf("entries: got %d, want 3", len(history))
}
for i, id := range ids {
if history[i].Findings[0].ID != id {
t.Errorf("entry %d finding ID: got %q, want %q", i, history[i].Findings[0].ID, id)
}
}
}

func TestLoadHistory_CorruptEntry_IsSkipped(t *testing.T) {
t.Helper()
dir := t.TempDir()
s := NewStore(filepath.Join(dir, "state.json"))
ctx := context.Background()

// Write one valid entry, then a corrupt line, then another valid entry.
valid := &Snapshot{
AgentID:     "agent-c",
Findings:    make([]protocol.Finding, 0),
LLMInsights: make([]string, 0),
EventCounts: make(map[string]int64),
}
if err := s.Save(ctx, valid); err != nil {
t.Fatal(err)
}

// Manually corrupt: append a bad JSON line directly to the history file.
f, err := os.OpenFile(s.HistoryPath(), os.O_APPEND|os.O_WRONLY, 0o600)
if err != nil {
t.Fatal(err)
}
_, _ = f.WriteString("not json at all\n")
f.Close()

if err := s.Save(ctx, valid); err != nil {
t.Fatal(err)
}

history, err := s.LoadHistory(ctx)
if err != nil {
t.Fatalf("LoadHistory: %v", err)
}
// The two valid entries should load; the corrupt line should be skipped.
if len(history) != 2 {
t.Errorf("entries: got %d, want 2 (corrupt line must be skipped)", len(history))
}
}
