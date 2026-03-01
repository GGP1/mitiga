package protocol

import (
	"strings"
	"testing"
	"time"
)

func TestNewFindingID(t *testing.T) {
	// Generate multiple IDs and verify they are unique and well-formed
	ids := make(map[string]bool)
	count := 100

	for range count {
		id := NewFindingID()

		// Check format: fnd-<20 hex chars>
		if !strings.HasPrefix(id, "fnd-") {
			t.Errorf("ID should start with 'fnd-', got: %s", id)
		}

		parts := strings.Split(id, "-")
		if len(parts) != 2 {
			t.Errorf("ID should have format fnd-<hex>, got: %s", id)
		}

		hexPart := parts[1]
		if len(hexPart) != 20 {
			t.Errorf("hex part should be 20 chars (10 bytes), got %d: %s", len(hexPart), id)
		}

		// Verify it's valid hex
		for _, c := range hexPart {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("hex part contains invalid char %c in ID: %s", c, id)
			}
		}

		// Check uniqueness
		if ids[id] {
			t.Errorf("duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}

func TestNewFinding(t *testing.T) {
	tests := []struct {
		name          string
		spec          FindingSpec
		checkEvidence bool
	}{
		{
			name: "basic finding with map evidence",
			spec: FindingSpec{
				Severity:    SeverityHigh,
				Category:    "test-category",
				Description: "Test description",
				Evidence: map[string]any{
					"key1": "value1",
					"key2": 42,
				},
				Impact:         "Test impact",
				Recommendation: "Test recommendation",
				Timestamp:      time.Now().UTC(),
			},
			checkEvidence: true,
		},
		{
			name: "finding with nil evidence",
			spec: FindingSpec{
				Severity:       SeverityCritical,
				Category:       "test-category",
				Description:    "Test description",
				Evidence:       nil,
				Impact:         "Test impact",
				Recommendation: "Test recommendation",
				Timestamp:      time.Now().UTC(),
			},
			checkEvidence: false,
		},
		{
			name: "finding with empty evidence map",
			spec: FindingSpec{
				Severity:       SeverityMedium,
				Category:       "test-category",
				Description:    "Test description",
				Evidence:       map[string]any{},
				Impact:         "Test impact",
				Recommendation: "Test recommendation",
				Timestamp:      time.Now().UTC(),
			},
			checkEvidence: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			finding := NewFinding(tt.spec)

			// Verify ID is generated
			if finding.ID == "" {
				t.Error("ID should not be empty")
			}
			if !strings.HasPrefix(finding.ID, "fnd-") {
				t.Errorf("ID should start with fnd-, got: %s", finding.ID)
			}

			// Verify fields are copied correctly
			if finding.Severity != tt.spec.Severity {
				t.Errorf("Severity = %v, want %v", finding.Severity, tt.spec.Severity)
			}
			if finding.Category != tt.spec.Category {
				t.Errorf("Category = %v, want %v", finding.Category, tt.spec.Category)
			}
			if finding.Description != tt.spec.Description {
				t.Errorf("Description = %v, want %v", finding.Description, tt.spec.Description)
			}

			// Verify evidence is formatted
			if tt.checkEvidence {
				if len(finding.Evidence) == 0 {
					t.Error("Evidence should not be empty")
				}
			}
		})
	}
}

func TestNewFinding_Uniqueness(t *testing.T) {
	// Verify that identical specs produce unique findings due to random IDs
	spec := FindingSpec{
		Severity:       SeverityHigh,
		Category:       "test",
		Description:    "test",
		Evidence:       map[string]any{"key": "value"},
		Impact:         "test",
		Recommendation: "test",
		Timestamp:      time.Now().UTC(),
	}

	f1 := NewFinding(spec)
	f2 := NewFinding(spec)

	if f1.ID == f2.ID {
		t.Errorf("identical specs should produce different IDs, got %s for both", f1.ID)
	}
}

func TestNewFinding_EvidenceSorting(t *testing.T) {
	// Evidence with map should produce sorted, readable output
	spec := FindingSpec{
		Severity:    SeverityHigh,
		Category:    "test",
		Description: "test",
		Evidence: map[string]any{
			"zebra":  "last",
			"apple":  "first",
			"middle": 42,
		},
		Impact:         "test",
		Recommendation: "test",
		Timestamp:      time.Now().UTC(),
	}

	finding := NewFinding(spec)

	// Should have 3 lines
	if len(finding.Evidence) != 3 {
		t.Errorf("expected 3 evidence lines, got %d", len(finding.Evidence))
	}

	// Should be sorted alphabetically by key
	expectedOrder := []string{"apple", "middle", "zebra"}
	for i, line := range finding.Evidence {
		if !strings.HasPrefix(line, expectedOrder[i]+":") {
			t.Errorf("evidence line %d should start with %q, got: %s", i, expectedOrder[i], line)
		}
	}
}

func TestNewFinding_ZeroTimestamp(t *testing.T) {
	// When timestamp is zero, it should be set to now
	spec := FindingSpec{
		Severity:       SeverityHigh,
		Category:       "test",
		Description:    "test",
		Evidence:       map[string]any{"key": "value"},
		Impact:         "test",
		Recommendation: "test",
		// Timestamp is zero value
	}

	before := time.Now().UTC()
	finding := NewFinding(spec)
	after := time.Now().UTC()

	if finding.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}

	if finding.Timestamp.Before(before) || finding.Timestamp.After(after) {
		t.Errorf("timestamp %v should be between %v and %v", finding.Timestamp, before, after)
	}
}
