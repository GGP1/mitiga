package executor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/GGP1/mitiga/pkg/protocol"
)

func TestIsAllowed(t *testing.T) {
	tests := []struct {
		command string
		allowed bool
	}{
		{"ps", true},
		{"ss", true},
		{"nmap", true},
		{"stat", true},
		{"getent", true},
		{"rm", false},
		{"curl", false},
		{"wget", false},
		{"bash", false},
		{"sh", false},
		{"python", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.command, func(t *testing.T) {
			if got := IsAllowed(tc.command); got != tc.allowed {
				t.Errorf("IsAllowed(%q) = %v, want %v", tc.command, got, tc.allowed)
			}
		})
	}
}

func TestRun_DeniedCommand(t *testing.T) {
	exec := New(5 * time.Second)
	ctx := context.Background()

	result := exec.Run(ctx, "rm", "-rf", "/")

	if result.Err == nil {
		t.Fatal("expected error for denied command")
	}

	if !errors.Is(result.Err, protocol.ErrCommandDenied) {
		t.Errorf("expected ErrCommandDenied, got: %v", result.Err)
	}

	if result.ExitCode != -1 {
		t.Errorf("exit code: got %d, want -1", result.ExitCode)
	}
}

func TestRun_AllowedCommand(t *testing.T) {
	exec := New(5 * time.Second)
	ctx := context.Background()

	result := exec.Run(ctx, "uname", "-s")

	if result.Err != nil {
		t.Fatalf("unexpected error: %v", result.Err)
	}

	if result.ExitCode != 0 {
		t.Errorf("exit code: got %d, want 0", result.ExitCode)
	}

	if result.Stdout == "" {
		t.Error("expected non-empty stdout from uname")
	}

	if result.Duration <= 0 {
		t.Error("expected positive duration")
	}
}

func TestRun_CapturesStderr(t *testing.T) {
	exec := New(5 * time.Second)
	ctx := context.Background()

	result := exec.Run(ctx, "stat", "/nonexistent_file_for_test_12345")

	if result.Err == nil {
		t.Fatal("expected error for stat on non-existent file")
	}

	if result.Stderr == "" {
		t.Error("expected non-empty stderr for stat on non-existent file")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		maxLen int
		want   string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"truncated", "hello world", 5, "hello...(truncated)"},
		{"empty", "", 5, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := truncate(tc.input, tc.maxLen)
			if got != tc.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tc.input, tc.maxLen, got, tc.want)
			}
		})
	}
}
