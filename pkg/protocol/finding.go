package protocol

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// FindingSpec describes input fields for creating a normalized finding.
type FindingSpec struct {
	Severity       Severity
	Category       string
	Description    string
	Impact         string
	Recommendation string
	Evidence       map[string]any
	Timestamp      time.Time
}

// NewFinding creates a finding with a random non-repeatable ID and normalized evidence.
func NewFinding(spec FindingSpec) Finding {
	timestamp := spec.Timestamp
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}

	return Finding{
		ID:             NewFindingID(),
		Severity:       spec.Severity,
		Category:       spec.Category,
		Description:    spec.Description,
		Evidence:       normalizeEvidence(spec.Evidence),
		Impact:         spec.Impact,
		Recommendation: spec.Recommendation,
		Timestamp:      timestamp,
	}
}

// NewFindingID generates a cryptographically random finding ID.
func NewFindingID() string {
	raw := make([]byte, 10)
	if _, err := rand.Read(raw); err != nil {
		return fmt.Sprintf("fnd-fallback-%d", time.Now().UTC().UnixNano())
	}
	return "fnd-" + hex.EncodeToString(raw)
}

func normalizeEvidence(input map[string]any) []string {
	if len(input) == 0 {
		return nil
	}

	keys := make([]string, 0, len(input))
	for key := range input {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	lines := make([]string, 0, len(keys))
	for _, key := range keys {
		value := input[key]
		lines = append(lines, fmt.Sprintf("%s: %s", key, stringifyEvidenceValue(value)))
	}

	return lines
}

func stringifyEvidenceValue(value any) string {
	switch typedValue := value.(type) {
	case string:
		return typedValue
	case []string:
		return strings.Join(typedValue, ", ")
	default:
		return fmt.Sprint(typedValue)
	}
}
