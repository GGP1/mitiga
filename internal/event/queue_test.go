package event

import (
"context"
"testing"
"time"

"github.com/GGP1/mitiga/pkg/protocol"
)

func TestNewQueue_DefaultCapacity(t *testing.T) {
q := NewQueue(0)
if q.capacity != 64 {
t.Errorf("default capacity: got %d, want 64", q.capacity)
}
}

func TestNewQueue_CustomCapacity(t *testing.T) {
q := NewQueue(128)
if q.capacity != 128 {
t.Errorf("capacity: got %d, want 128", q.capacity)
}
}

func TestEnqueue_And_Chan(t *testing.T) {
ctx := context.Background()
q := NewQueue(4)

ev := NewEvent(protocol.EventTypeScheduledScan, "test", nil)
q.Enqueue(ctx, ev)

if q.Len() != 1 {
t.Fatalf("Len after enqueue: got %d, want 1", q.Len())
}

received := <-q.Chan()
if received.ID != ev.ID {
t.Errorf("received event ID: got %q, want %q", received.ID, ev.ID)
}
}

func TestEnqueue_DropsWhenFull(t *testing.T) {
ctx := context.Background()
q := NewQueue(2)

for i := range 3 {
_ = i
q.Enqueue(ctx, NewEvent(protocol.EventTypeHeartbeat, "test", nil))
}

// Only 2 should be buffered (the third was dropped).
if q.Len() != 2 {
t.Errorf("Len after overfill: got %d, want 2", q.Len())
}
}

func TestNewEvent_Fields(t *testing.T) {
before := time.Now().UTC()
ev := NewEvent(protocol.EventTypeFilesystemChange, "fs:/etc", map[string]string{"path": "/etc"})
after := time.Now().UTC()

if ev.Type != protocol.EventTypeFilesystemChange {
t.Errorf("Type: got %q, want %q", ev.Type, protocol.EventTypeFilesystemChange)
}
if ev.Source != "fs:/etc" {
t.Errorf("Source: got %q, want %q", ev.Source, "fs:/etc")
}
if ev.Payload["path"] != "/etc" {
t.Errorf("Payload[path]: got %q, want /etc", ev.Payload["path"])
}
if ev.Timestamp.Before(before) || ev.Timestamp.After(after) {
t.Errorf("Timestamp %v not in expected range [%v, %v]", ev.Timestamp, before, after)
}
if ev.ID == "" {
t.Error("ID must not be empty")
}
}

func TestQueue_Close(t *testing.T) {
ctx := context.Background()
q := NewQueue(4)

q.Enqueue(ctx, NewEvent(protocol.EventTypeStartup, "agent", nil))
q.Close()

count := 0
for range q.Chan() {
count++
}
if count != 1 {
t.Errorf("drained %d events after Close, want 1", count)
}
}
