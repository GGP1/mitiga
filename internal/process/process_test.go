package process

import (
	"testing"
)

func TestParsePSOutput(t *testing.T) {
	output := "  1     0 root      0.0  0.1  169456 11264 /sbin/init\n 42     1 root      0.0  0.0   5968  3712 /usr/lib/systemd/systemd-journald\n1234     1 postgres  1.2  3.4 567890 45678 /usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main\n5678  1234 www-data  0.5  0.2 123456  7890 nginx: worker process\n9999     1 root     95.0  2.0 890123 56789 /tmp/suspicious (deleted)\n"

	procs, err := parsePSOutput(output)
	if err != nil {
		t.Fatalf("parsePSOutput: %v", err)
	}

	if len(procs) != 5 {
		t.Fatalf("expected 5 processes, got %d", len(procs))
	}

	if procs[0].PID != 1 {
		t.Errorf("first PID: got %d, want 1", procs[0].PID)
	}
	if procs[0].PPID != 0 {
		t.Errorf("first PPID: got %d, want 0", procs[0].PPID)
	}
	if procs[0].User != "root" {
		t.Errorf("first user: got %q, want %q", procs[0].User, "root")
	}

	if procs[2].PID != 1234 {
		t.Errorf("postgres PID: got %d, want 1234", procs[2].PID)
	}
	if procs[4].CPU != 95.0 {
		t.Errorf("suspicious CPU: got %f, want 95.0", procs[4].CPU)
	}
}

func TestParsePSOutput_Empty(t *testing.T) {
	procs, err := parsePSOutput("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(procs) != 0 {
		t.Errorf("expected 0 processes, got %d", len(procs))
	}
}

func TestParsePSOutput_ShortLines(t *testing.T) {
	output := "1 0 root 0.0\n42 1 root\n"
	procs, err := parsePSOutput(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(procs) != 0 {
		t.Errorf("expected 0 processes from short lines, got %d", len(procs))
	}
}

func FuzzParsePSOutput(f *testing.F) {
	f.Add("  1     0 root      0.0  0.1  169456 11264 /sbin/init\n")
	f.Add("")
	f.Add("not a valid line\n")

	f.Fuzz(func(t *testing.T, data string) {
		_, _ = parsePSOutput(data)
	})
}
