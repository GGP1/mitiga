package system

import (
	"testing"
)

func TestParsePasswdOutput(t *testing.T) {
	output := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\ntestuser:x:1000:1000:Test User:/home/testuser:/bin/bash\n"

	users := parsePasswdOutput(output)

	if len(users) != 4 {
		t.Fatalf("expected 4 users, got %d", len(users))
	}

	if users[0].Name != "root" {
		t.Errorf("first user name: got %q, want %q", users[0].Name, "root")
	}
	if users[0].UID != 0 {
		t.Errorf("root UID: got %d, want 0", users[0].UID)
	}
	if users[0].Shell != "/bin/bash" {
		t.Errorf("root shell: got %q, want %q", users[0].Shell, "/bin/bash")
	}
	if users[2].UID != 65534 {
		t.Errorf("nobody UID: got %d, want 65534", users[2].UID)
	}
	if users[3].Comment != "Test User" {
		t.Errorf("testuser comment: got %q, want %q", users[3].Comment, "Test User")
	}
}

func TestParsePasswdOutput_Empty(t *testing.T) {
	users := parsePasswdOutput("")
	if len(users) != 0 {
		t.Errorf("expected 0 users, got %d", len(users))
	}
}

func TestParsePasswdOutput_ShortLines(t *testing.T) {
	output := "root:x:0:0\nshort\n"
	users := parsePasswdOutput(output)
	if len(users) != 0 {
		t.Errorf("expected 0 users from short lines, got %d", len(users))
	}
}

func TestIsPermsTooWide(t *testing.T) {
	tests := []struct {
		name    string
		actual  string
		max     string
		tooWide bool
	}{
		{"exact match", "644", "644", false},
		{"more restrictive", "600", "644", false},
		{"too wide world read", "666", "644", true},
		{"too wide world exec", "755", "644", true},
		{"shadow ok", "640", "640", false},
		{"shadow too wide", "644", "640", true},
		{"invalid actual", "xyz", "644", false},
		{"invalid max", "644", "abc", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isPermsTooWide(tc.actual, tc.max)
			if got != tc.tooWide {
				t.Errorf("isPermsTooWide(%q, %q) = %v, want %v", tc.actual, tc.max, got, tc.tooWide)
			}
		})
	}
}

func FuzzParsePasswdOutput(f *testing.F) {
	f.Add("root:x:0:0:root:/root:/bin/bash\n")
	f.Add("")
	f.Add("short:x\n")
	f.Add("a:b:c:d:e:f:g\n")

	f.Fuzz(func(t *testing.T, data string) {
		_ = parsePasswdOutput(data)
	})
}
