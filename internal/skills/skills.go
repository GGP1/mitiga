// Package skills provides a compile-time registry of CLI tool documentation
// from the .github/skills/ catalog. SKILL.md files are embedded into the
// binary via go:embed and parsed into structured [Skill] values.
//
// The registry serves two purposes:
//
//  1. Sub-agent prompt enrichment — when building an LLM sub-agent, the
//     system prompt can be augmented with the relevant skills so the LLM
//     understands the tools, their safety constraints, and what to look for.
//
//  2. Discoverability — modules can query the registry to discover available
//     tools per category.
package skills

import (
	"embed"
	"fmt"
	"strings"
)

//go:embed catalog/*/*.md
var skillFS embed.FS

// Skill holds the parsed metadata from a single SKILL.md file.
type Skill struct {
	// Name is the tool name (directory name, e.g. "ss", "nmap").
	Name string
	// Title is the full heading (e.g. "ss — Socket Statistics").
	Title string
	// Category is the skill category (e.g. "Network Reconnaissance").
	Category string
	// Purpose is a short description of what the tool does.
	Purpose string
	// UseCases lists security-relevant use cases.
	UseCases []string
	// Examples contains the raw example code block.
	Examples string
	// SafetyNotes lists safety-relevant notes.
	SafetyNotes []string
}

// Registry maps tool names to their parsed skill definitions.
type Registry struct {
	skills map[string]Skill
}

// NewRegistry parses all embedded SKILL.md files and returns a populated
// registry. It is safe to call from init or main.
func NewRegistry() (*Registry, error) {
	entries, err := skillFS.ReadDir("catalog")
	if err != nil {
		return nil, fmt.Errorf("skills: read catalog: %w", err)
	}

	reg := &Registry{skills: make(map[string]Skill, len(entries))}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		data, err := skillFS.ReadFile(fmt.Sprintf("catalog/%s/SKILL.md", name))
		if err != nil {
			continue // directory without SKILL.md — skip silently
		}
		skill, err := parseSkillMD(name, string(data))
		if err != nil {
			return nil, fmt.Errorf("skills: parse %s: %w", name, err)
		}
		reg.skills[name] = skill
	}
	return reg, nil
}

// Get returns the skill for the given tool name.
func (r *Registry) Get(name string) (Skill, bool) {
	s, ok := r.skills[name]
	return s, ok
}

// ByCategory returns all skills matching the given category (case-insensitive).
func (r *Registry) ByCategory(category string) []Skill {
	cat := strings.ToLower(category)
	var result []Skill
	for _, s := range r.skills {
		if strings.ToLower(s.Category) == cat {
			result = append(result, s)
		}
	}
	return result
}

// All returns every skill in the registry.
func (r *Registry) All() []Skill {
	result := make([]Skill, 0, len(r.skills))
	for _, s := range r.skills {
		result = append(result, s)
	}
	return result
}

// Names returns the list of registered tool names.
func (r *Registry) Names() []string {
	names := make([]string, 0, len(r.skills))
	for n := range r.skills {
		names = append(names, n)
	}
	return names
}

// FormatForPrompt returns a textual summary of the given tools suitable for
// inclusion in an LLM sub-agent system prompt. It includes purpose, use
// cases, example commands, and safety notes for each tool.
func (r *Registry) FormatForPrompt(toolNames ...string) string {
	var sb strings.Builder
	sb.WriteString("=== AVAILABLE TOOL REFERENCE ===\n\n")
	for _, name := range toolNames {
		s, ok := r.skills[name]
		if !ok {
			continue
		}
		fmt.Fprintf(&sb, "--- %s ---\n", s.Title)
		fmt.Fprintf(&sb, "Category: %s\n", s.Category)
		fmt.Fprintf(&sb, "Purpose: %s\n", s.Purpose)
		if len(s.UseCases) > 0 {
			sb.WriteString("Use Cases:\n")
			for _, uc := range s.UseCases {
				fmt.Fprintf(&sb, "  - %s\n", uc)
			}
		}
		if s.Examples != "" {
			sb.WriteString("Examples:\n")
			sb.WriteString(s.Examples)
			sb.WriteString("\n")
		}
		if len(s.SafetyNotes) > 0 {
			sb.WriteString("Safety:\n")
			for _, sn := range s.SafetyNotes {
				fmt.Fprintf(&sb, "  - %s\n", sn)
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// parseSkillMD extracts structured fields from a SKILL.md file.
func parseSkillMD(name, content string) (Skill, error) {
	s := Skill{Name: name}

	s.Title = extractTitle(content)
	s.Category = extractSection(content, "Category")
	s.Purpose = extractSection(content, "Purpose")
	s.UseCases = extractList(content, "Use Cases")
	if len(s.UseCases) == 0 {
		// coreutils uses "Tools" instead of "Use Cases"
		s.UseCases = extractList(content, "Tools")
	}
	s.Examples = extractCodeBlock(content, "Examples")
	s.SafetyNotes = extractList(content, "Safety Notes")

	if s.Title == "" {
		s.Title = name
	}

	return s, nil
}

// extractTitle returns the text after "# " on the first heading line.
func extractTitle(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "# ") && !strings.HasPrefix(line, "## ") {
			return strings.TrimPrefix(line, "# ")
		}
	}
	return ""
}

// extractSection returns the first paragraph of text under "## <heading>".
func extractSection(content, heading string) string {
	marker := "## " + heading
	idx := strings.Index(content, marker)
	if idx < 0 {
		return ""
	}
	rest := content[idx+len(marker):]
	lines := strings.SplitN(rest, "\n", 20)
	var result []string
	started := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !started {
			if trimmed == "" {
				continue
			}
			started = true
		}
		if started && trimmed == "" {
			break
		}
		if strings.HasPrefix(trimmed, "## ") || strings.HasPrefix(trimmed, "# ") {
			break
		}
		result = append(result, trimmed)
	}
	return strings.Join(result, " ")
}

// extractList returns bullet-point items under "## <heading>".
func extractList(content, heading string) []string {
	marker := "## " + heading
	idx := strings.Index(content, marker)
	if idx < 0 {
		return nil
	}
	rest := content[idx+len(marker):]
	lines := strings.Split(rest, "\n")
	var items []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "## ") || strings.HasPrefix(trimmed, "# ") {
			break
		}
		if strings.HasPrefix(trimmed, "- ") {
			items = append(items, strings.TrimPrefix(trimmed, "- "))
		}
	}
	return items
}

// extractCodeBlock returns the content of the first fenced code block
// under "## <heading>".
func extractCodeBlock(content, heading string) string {
	marker := "## " + heading
	idx := strings.Index(content, marker)
	if idx < 0 {
		return ""
	}
	rest := content[idx+len(marker):]

	fenceStart := strings.Index(rest, "```")
	if fenceStart < 0 {
		return ""
	}
	afterFence := rest[fenceStart+3:]
	// Skip the language tag on the same line.
	nlIdx := strings.Index(afterFence, "\n")
	if nlIdx < 0 {
		return ""
	}
	afterFence = afterFence[nlIdx+1:]

	fenceEnd := strings.Index(afterFence, "```")
	if fenceEnd < 0 {
		return afterFence
	}
	return strings.TrimRight(afterFence[:fenceEnd], "\n")
}
