// Package report generates structured security reports per §10.
//
// Reports are the primary interface between Mitiga and the system manager.
// They must be clear, actionable, and complete. Output formats: JSON (primary),
// Markdown (human-readable), HTML (styled, from Markdown).
package report

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/GGP1/mitiga/internal/logger"
	"github.com/GGP1/mitiga/pkg/protocol"
)

// Report is a complete security report per §10.1.
type Report struct {
	// Header
	ID        string    `json:"id"`
	AgentID   string    `json:"agent_id"`
	Hostname  string    `json:"hostname"`
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`

	// Executive Summary
	Summary string `json:"summary"`

	// Findings ordered by severity (CRITICAL first)
	Findings []protocol.Finding `json:"findings"`

	// Actions taken by the agent
	Actions []Action `json:"actions"`

	// LLMInsights captures advisory recommendations returned by the local LLM.
	LLMInsights []string `json:"llm_insights,omitempty"`

}

// Action records an automated action the agent performed.
type Action struct {
	Timestamp   time.Time `json:"timestamp"`
	Description string    `json:"description"`
	Outcome     string    `json:"outcome"`
}

// severityOrder defines the sort order for findings (CRITICAL first).
var severityOrder = map[protocol.Severity]int{
	protocol.SeverityCritical: 0,
	protocol.SeverityHigh:     1,
	protocol.SeverityMedium:   2,
	protocol.SeverityLow:      3,
	protocol.SeverityInfo:     4,
}

// New creates a new report with the given metadata.
func New(id, agentID, hostname, reportType string) *Report {
	return &Report{
		ID:        id,
		AgentID:   agentID,
		Hostname:  hostname,
		Timestamp: time.Now().UTC(),
		Type:      reportType,
		Findings:  make([]protocol.Finding, 0),
		Actions:   make([]Action, 0),
		LLMInsights: make([]string, 0),
	}
}

// AddFindings adds findings to the report and sorts them by severity.
func (r *Report) AddFindings(findings []protocol.Finding) {
	r.Findings = append(r.Findings, findings...)
	sort.Slice(r.Findings, func(i, j int) bool {
		return severityOrder[r.Findings[i].Severity] < severityOrder[r.Findings[j].Severity]
	})
}

// AddAction records an action taken during this report period.
func (r *Report) AddAction(description, outcome string) {
	r.Actions = append(r.Actions, Action{
		Timestamp:   time.Now().UTC(),
		Description: description,
		Outcome:     outcome,
	})
}

// AddLLMInsights appends advisory LLM recommendations to the report.
func (r *Report) AddLLMInsights(insights []string) {
	r.LLMInsights = append(r.LLMInsights, insights...)
}

// GenerateSummary builds the executive summary from findings.
func (r *Report) GenerateSummary() {
	counts := make(map[protocol.Severity]int)
	for _, f := range r.Findings {
		counts[f.Severity]++
	}

	if len(r.Findings) == 0 {
		r.Summary = fmt.Sprintf(
			"Security scan completed on %s at %s. No findings to report. System posture is clean.",
			r.Hostname, r.Timestamp.Format(time.RFC3339),
		)
		return
	}

	parts := make([]string, 0, 5)
	for _, sev := range []protocol.Severity{
		protocol.SeverityCritical, protocol.SeverityHigh,
		protocol.SeverityMedium, protocol.SeverityLow, protocol.SeverityInfo,
	} {
		if c := counts[sev]; c > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c, sev))
		}
	}

	r.Summary = fmt.Sprintf(
		"Security scan completed on %s at %s. %d finding(s) detected: %s. Immediate attention required for any CRITICAL or HIGH severity items.",
		r.Hostname, r.Timestamp.Format(time.RFC3339),
		len(r.Findings), strings.Join(parts, ", "),
	)
}

// WriteJSON writes the report as JSON to the given directory.
func (r *Report) WriteJSON(ctx context.Context, outputDir string) (string, error) {
	ctx = logger.WithComponent(ctx, "report")

	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return "", fmt.Errorf("report: create output directory: %w", err)
	}

	filename := fmt.Sprintf("%s_%s.json", r.Type, r.Timestamp.Format("20060102T150405Z"))
	path := filepath.Join(outputDir, filename)

	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", fmt.Errorf("report: marshal JSON: %w", err)
	}

	if err := os.WriteFile(path, data, 0o640); err != nil {
		return "", fmt.Errorf("report: write file %q: %w", path, err)
	}

	logger.Info(ctx, "report written",
		"format", "json",
		"path", path,
		"findings_count", len(r.Findings),
	)

	return path, nil
}

// WriteMarkdown writes the report as Markdown to the given directory.
func (r *Report) WriteMarkdown(ctx context.Context, outputDir string) (string, error) {
	ctx = logger.WithComponent(ctx, "report")

	if err := os.MkdirAll(outputDir, 0o750); err != nil {
		return "", fmt.Errorf("report: create output directory: %w", err)
	}

	filename := fmt.Sprintf("%s_%s.md", r.Type, r.Timestamp.Format("20060102T150405Z"))
	path := filepath.Join(outputDir, filename)

	var sb strings.Builder
	fmt.Fprintf(&sb, "# Mitiga Security Report: %s\n\n", r.Type)
	fmt.Fprintf(&sb, "- **Report ID:** %s\n", r.ID)
	fmt.Fprintf(&sb, "- **Agent ID:** %s\n", r.AgentID)
	fmt.Fprintf(&sb, "- **Hostname:** %s\n", r.Hostname)
	fmt.Fprintf(&sb, "- **Timestamp:** %s\n", r.Timestamp.Format(time.RFC3339))
	sb.WriteString("\n---\n\n")

	sb.WriteString("## Executive Summary\n\n")
	sb.WriteString(r.Summary)
	sb.WriteString("\n\n---\n\n")

	sb.WriteString("## Findings\n\n")
	if len(r.Findings) == 0 {
		sb.WriteString("No findings.\n\n")
	} else {
		for i, f := range r.Findings {
			fmt.Fprintf(&sb, "### %d. [%s] %s\n\n", i+1, f.Severity, f.Description)
			fmt.Fprintf(&sb, "- **Finding ID:** %s\n", f.ID)
			fmt.Fprintf(&sb, "- **Category:** %s\n", f.Category)
			fmt.Fprintf(&sb, "- **Impact:** %s\n", f.Impact)
			fmt.Fprintf(&sb, "- **Recommendation:** %s\n", f.Recommendation)
			if len(f.Evidence) > 0 {
				sb.WriteString("- **Evidence:**\n")
				for _, e := range f.Evidence {
					fmt.Fprintf(&sb, "  - `%s`\n", e)
				}
			}
			sb.WriteString("\n")
		}
	}

	sb.WriteString("---\n\n")
	sb.WriteString("## Actions Taken\n\n")
	if len(r.Actions) == 0 {
		sb.WriteString("No automated actions were taken.\n\n")
	} else {
		for _, a := range r.Actions {
			fmt.Fprintf(&sb, "- **%s:** %s — *%s*\n",
				a.Timestamp.Format(time.RFC3339), a.Description, a.Outcome)
		}
		sb.WriteString("\n")
	}

	if len(r.LLMInsights) > 0 {
		sb.WriteString("---\n\n")
		sb.WriteString("## LLM Advisory Insights\n\n")
		for _, insight := range r.LLMInsights {
			fmt.Fprintf(&sb, "- %s\n", insight)
		}
		sb.WriteString("\n")
	}

	if err := os.WriteFile(path, []byte(sb.String()), 0o640); err != nil {
		return "", fmt.Errorf("report: write file %q: %w", path, err)
	}

	logger.Info(ctx, "report written",
		"format", "markdown",
		"path", path,
		"findings_count", len(r.Findings),
	)

	return path, nil
}
