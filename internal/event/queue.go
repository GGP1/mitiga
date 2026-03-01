// Package event provides the event queue that drives the agent's processing
// loop.
//
// Producers (timer tickers, filesystem watchers) enqueue events without
// blocking.  The single consumer reads from the channel and dispatches each
// event to the appropriate handler, maintaining consistent in-order
// processing.
package event

import (
	"context"
	"fmt"
	"time"

	"github.com/GGP1/mitiga/internal/logger"
	"github.com/GGP1/mitiga/pkg/protocol"
)

// Queue is a bounded, channel-backed event queue.  It is safe for concurrent
// use by multiple producers and a single consumer.
type Queue struct {
	ch       chan protocol.Event
	capacity int
}

// NewQueue creates a Queue with the given buffer capacity.
// A capacity ≤ 0 defaults to 64.
func NewQueue(capacity int) *Queue {
	if capacity <= 0 {
		capacity = 64
	}
	return &Queue{
		ch:       make(chan protocol.Event, capacity),
		capacity: capacity,
	}
}

// Enqueue adds an event to the queue.  If the queue is full the event is
// dropped and a warning is logged — the agent must never block a producer
// goroutine indefinitely.
func (q *Queue) Enqueue(ctx context.Context, ev protocol.Event) {
	select {
	case q.ch <- ev:
		logger.Debug(ctx, "event enqueued",
			"event_id", ev.ID,
			"event_type", string(ev.Type),
			"source", ev.Source,
		)
	default:
		logger.Warn(ctx, "event queue full, dropping event",
			"event_id", ev.ID,
			"event_type", string(ev.Type),
			"source", ev.Source,
			"capacity", q.capacity,
		)
	}
}

// Chan returns the read-only channel that the consumer reads from.
func (q *Queue) Chan() <-chan protocol.Event {
	return q.ch
}

// Close signals that no more events will be produced.  The consumer should
// drain the channel after Close returns.
func (q *Queue) Close() {
	close(q.ch)
}

// Len returns the number of events currently buffered in the queue.
func (q *Queue) Len() int {
	return len(q.ch)
}

// NewEvent constructs a new Event with a unique ID and the current UTC
// timestamp, ready to be enqueued.
func NewEvent(eventType protocol.EventType, source string, payload map[string]string) protocol.Event {
	return protocol.Event{
		ID:        fmt.Sprintf("%s-%d", string(eventType), time.Now().UnixNano()),
		Type:      eventType,
		Source:    source,
		Payload:   payload,
		Timestamp: time.Now().UTC(),
	}
}
