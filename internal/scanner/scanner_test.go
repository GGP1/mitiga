package scanner

import (
	"testing"
)

func TestParseSSOutput(t *testing.T) {
	output := "Netid State  Recv-Q Send-Q  Local Address:Port   Peer Address:Port Process\ntcp   LISTEN 0      128     0.0.0.0:22          0.0.0.0:*     users:((\"sshd\",pid=1234,fd=3))\ntcp   LISTEN 0      128     127.0.0.1:5432      0.0.0.0:*     users:((\"postgres\",pid=5678,fd=5))\nudp   UNCONN 0      0       0.0.0.0:68          0.0.0.0:*     users:((\"dhclient\",pid=345,fd=7))\ntcp   LISTEN 0      128     [::]:22             [::]:*         users:((\"sshd\",pid=1234,fd=4))\n"

	ports, err := parseSSOutput(output)
	if err != nil {
		t.Fatalf("parseSSOutput: %v", err)
	}

	if len(ports) < 3 {
		t.Fatalf("expected at least 3 ports, got %d", len(ports))
	}

	// Check SSH on IPv4.
	found := false
	for _, p := range ports {
		if p.Port == 22 && p.Protocol == "tcp" && p.Address == "0.0.0.0" {
			found = true
			if p.Process != "sshd" {
				t.Errorf("expected process sshd, got %q", p.Process)
			}
			if p.PID != 1234 {
				t.Errorf("expected PID 1234, got %d", p.PID)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find sshd on port 22 (IPv4)")
	}

	// Check PostgreSQL.
	found = false
	for _, p := range ports {
		if p.Port == 5432 {
			found = true
			if p.Process != "postgres" {
				t.Errorf("expected process postgres, got %q", p.Process)
			}
			break
		}
	}
	if !found {
		t.Error("expected to find postgres on port 5432")
	}
}

func TestParseSSOutput_Empty(t *testing.T) {
	ports, err := parseSSOutput("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 0 {
		t.Errorf("expected 0 ports, got %d", len(ports))
	}
}

func TestParseSSOutput_HeaderOnly(t *testing.T) {
	output := "Netid State  Recv-Q Send-Q  Local Address:Port   Peer Address:Port Process\n"
	ports, err := parseSSOutput(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ports) != 0 {
		t.Errorf("expected 0 ports from header-only output, got %d", len(ports))
	}
}

func TestParseAddress_IPv4(t *testing.T) {
	tests := []struct {
		input    string
		wantAddr string
		wantPort int
		wantErr  bool
	}{
		{"0.0.0.0:22", "0.0.0.0", 22, false},
		{"127.0.0.1:5432", "127.0.0.1", 5432, false},
		{"*:8080", "*", 8080, false},
		{"0.0.0.0:*", "0.0.0.0", 0, false},
		{"invalid", "", 0, true},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			addr, port, err := parseAddress(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if addr != tc.wantAddr {
				t.Errorf("address: got %q, want %q", addr, tc.wantAddr)
			}
			if port != tc.wantPort {
				t.Errorf("port: got %d, want %d", port, tc.wantPort)
			}
		})
	}
}

func TestParseAddress_IPv6(t *testing.T) {
	addr, port, err := parseAddress("[::]:22")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "::" {
		t.Errorf("address: got %q, want %q", addr, "::")
	}
	if port != 22 {
		t.Errorf("port: got %d, want 22", port)
	}
}

func TestParseProcessInfo(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantName string
		wantPID  int
	}{
		{"standard format", "users:((\"sshd\",pid=1234,fd=3))", "sshd", 1234},
		{"nginx", "users:((\"nginx\",pid=9012,fd=6))", "nginx", 9012},
		{"empty", "", "", 0},
		{"no process info", "users:()", "", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name, pid := parseProcessInfo(tc.input)
			if name != tc.wantName {
				t.Errorf("name: got %q, want %q", name, tc.wantName)
			}
			if pid != tc.wantPID {
				t.Errorf("pid: got %d, want %d", pid, tc.wantPID)
			}
		})
	}
}

func FuzzParseSSOutput(f *testing.F) {
	f.Add("Netid State  Recv-Q Send-Q  Local Address:Port   Peer Address:Port\ntcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\n")
	f.Add("")
	f.Add("garbage\nmore garbage\n")

	f.Fuzz(func(t *testing.T, data string) {
		_, _ = parseSSOutput(data)
	})
}

func FuzzParseAddress(f *testing.F) {
	f.Add("0.0.0.0:22")
	f.Add("[::]:8080")
	f.Add("*:*")
	f.Add("")
	f.Add("invalid")

	f.Fuzz(func(t *testing.T, data string) {
		_, _, _ = parseAddress(data)
	})
}
