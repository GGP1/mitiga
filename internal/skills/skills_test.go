package skills

import (
	"testing"
)

func TestNewRegistry(t *testing.T) {
	reg, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() error: %v", err)
	}
	if len(reg.skills) == 0 {
		t.Fatal("expected at least one skill in registry")
	}
}

func TestGet(t *testing.T) {
	reg, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() error: %v", err)
	}

	tests := []struct {
		name    string
		wantOk  bool
		wantCat string
	}{
		{name: "ss", wantOk: true, wantCat: "Network Reconnaissance"},
		{name: "ps", wantOk: true, wantCat: "Process Management"},
		{name: "sysctl", wantOk: true, wantCat: "System Hardening"},
		{name: "getent", wantOk: true, wantCat: "User & Group Management"},
		{name: "journalctl", wantOk: true, wantCat: "Log Analysis"},
		{name: "govulncheck", wantOk: true, wantCat: "Vulnerability Scanning"},
		{name: "nonexistent", wantOk: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			skill, ok := reg.Get(tc.name)
			if ok != tc.wantOk {
				t.Fatalf("Get(%q) ok = %v, want %v", tc.name, ok, tc.wantOk)
			}
			if !tc.wantOk {
				return
			}
			if skill.Category != tc.wantCat {
				t.Errorf("Get(%q).Category = %q, want %q", tc.name, skill.Category, tc.wantCat)
			}
			if skill.Purpose == "" {
				t.Errorf("Get(%q).Purpose is empty", tc.name)
			}
			if skill.Title == "" {
				t.Errorf("Get(%q).Title is empty", tc.name)
			}
		})
	}
}

func TestByCategory(t *testing.T) {
	reg, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() error: %v", err)
	}

	netRecon := reg.ByCategory("Network Reconnaissance")
	if len(netRecon) == 0 {
		t.Error("expected at least one skill in Network Reconnaissance")
	}
	for _, s := range netRecon {
		if s.Category != "Network Reconnaissance" {
			t.Errorf("ByCategory returned skill %q with category %q", s.Name, s.Category)
		}
	}
}

func TestFormatForPrompt(t *testing.T) {
	reg, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() error: %v", err)
	}

	prompt := reg.FormatForPrompt("ss", "ps")
	if prompt == "" {
		t.Fatal("FormatForPrompt returned empty string")
	}

	// Should contain both tool references.
	for _, want := range []string{"ss", "ps", "AVAILABLE TOOL REFERENCE"} {
		if !contains(prompt, want) {
			t.Errorf("FormatForPrompt missing %q", want)
		}
	}
}

func TestFormatForPromptUnknownTool(t *testing.T) {
	reg, err := NewRegistry()
	if err != nil {
		t.Fatalf("NewRegistry() error: %v", err)
	}

	prompt := reg.FormatForPrompt("nonexistent")
	if prompt == "" {
		t.Fatal("FormatForPrompt returned empty for unknown tool")
	}
	// Should just have the header, no tool content.
	if contains(prompt, "---") {
		t.Error("expected no tool entries for unknown tool")
	}
}

func TestParseSkillMD(t *testing.T) {
	md := `# testtool — Test Tool

## Category
Testing

## License
MIT

## Source
https://example.com

## Purpose
A tool for testing the parser.

## Use Cases
- Test parsing logic
- Verify extraction works

## Examples
` + "```bash\ntesttool --check\ntesttool --scan /path\n```" + `

## Safety Notes
- Read-only operation — safe to run at any time.
- Requires root for some options.
`

	skill, err := parseSkillMD("testtool", md)
	if err != nil {
		t.Fatalf("parseSkillMD() error: %v", err)
	}
	if skill.Name != "testtool" {
		t.Errorf("Name = %q, want %q", skill.Name, "testtool")
	}
	if skill.Title != "testtool — Test Tool" {
		t.Errorf("Title = %q, want %q", skill.Title, "testtool — Test Tool")
	}
	if skill.Category != "Testing" {
		t.Errorf("Category = %q, want %q", skill.Category, "Testing")
	}
	if skill.Purpose != "A tool for testing the parser." {
		t.Errorf("Purpose = %q", skill.Purpose)
	}
	if len(skill.UseCases) != 2 {
		t.Errorf("UseCases len = %d, want 2", len(skill.UseCases))
	}
	if skill.Examples == "" {
		t.Error("Examples is empty")
	}
	if len(skill.SafetyNotes) != 2 {
		t.Errorf("SafetyNotes len = %d, want 2", len(skill.SafetyNotes))
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
