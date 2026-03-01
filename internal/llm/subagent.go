package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/GGP1/mitiga/internal/config"
	"github.com/GGP1/mitiga/internal/logger"
	"github.com/GGP1/mitiga/pkg/protocol"
)

// SubAgentTask identifies the security domain a sub-agent covers.
// Used as the key in config.LLMConfig.SubAgents.
type SubAgentTask string

// Sub agent tasks.
const (
	TaskScanner  SubAgentTask = "scanner"
	TaskProcess  SubAgentTask = "process"
	TaskSystem   SubAgentTask = "system"
	TaskHardener SubAgentTask = "hardener"
	TaskLogAudit SubAgentTask = "logaudit"
	TaskAudit    SubAgentTask = "audit"
	TaskAdvisory SubAgentTask = "advisory"
)

// SubAgent wraps an LLM endpoint with a task-specific system prompt.
// Each security module has its own sub-agent so the prompt can be tailored
// and, optionally, a different model can be used for different tasks.
type SubAgent struct {
	task       SubAgentTask
	prompt     string
	endpoint   string
	model      string
	apiKey     string
	httpClient *http.Client
}

// SubAgentOption configures a SubAgent.
type SubAgentOption func(*SubAgent)

// WithModel overrides the model name for this sub-agent.
func WithModel(model string) SubAgentOption {
	return func(sa *SubAgent) { sa.model = model }
}

// WithEndpoint overrides the LLM endpoint for this sub-agent.
func WithEndpoint(endpoint string) SubAgentOption {
	return func(sa *SubAgent) { sa.endpoint = endpoint }
}

// WithTimeout overrides the HTTP timeout for this sub-agent.
func WithTimeout(d time.Duration) SubAgentOption {
	return func(sa *SubAgent) { sa.httpClient.Timeout = d }
}

// WithAPIKey overrides the API key (Authorization: Bearer) for this sub-agent.
func WithAPIKey(key string) SubAgentOption {
	return func(sa *SubAgent) { sa.apiKey = key }
}

// WithSkillContext appends tool reference documentation to the sub-agent's
// system prompt.  The LLM receives the tool's purpose, use cases, examples,
// and safety notes so it can produce better-informed findings.
func WithSkillContext(skillContext string) SubAgentOption {
	return func(sa *SubAgent) {
		if skillContext != "" {
			sa.prompt = sa.prompt + "\n\n" + skillContext
		}
	}
}

// NewSubAgent creates a sub-agent for the given task using parentCfg.FindingsModel.
// For the advisory task, use NewAdvisorySubAgent instead.
func NewSubAgent(parentCfg config.LLMConfig, task SubAgentTask, systemPrompt string, opts ...SubAgentOption) *SubAgent {
	sa := &SubAgent{
		task:     task,
		prompt:   systemPrompt,
		endpoint: parentCfg.Endpoint,
		model:    parentCfg.FindingsModel,
		apiKey:   parentCfg.APIKey,
		httpClient: &http.Client{
			Timeout: parentCfg.Timeout,
		},
	}
	for _, opt := range opts {
		opt(sa)
	}
	return sa
}

// NewAdvisorySubAgent creates the post-scan advisory sub-agent using
// parentCfg.AdvisoryModel.
func NewAdvisorySubAgent(parentCfg config.LLMConfig, opts ...SubAgentOption) *SubAgent {
	sa := &SubAgent{
		task:     TaskAdvisory,
		prompt:   PromptAdvisory,
		endpoint: parentCfg.Endpoint,
		model:    parentCfg.AdvisoryModel,
		apiKey:   parentCfg.APIKey,
		httpClient: &http.Client{
			Timeout: parentCfg.Timeout,
		},
	}
	for _, opt := range opts {
		opt(sa)
	}
	return sa
}

// AnalysisRequest is the payload sent to the local LLM endpoint when a
// sub-agent requests analysis.
type AnalysisRequest struct {
	Task         string `json:"task"`
	SystemPrompt string `json:"system_prompt"`
	UserMessage  string `json:"user_message"`
	Model        string `json:"model,omitempty"`
}

// AnalysisResult is the structured response expected from the LLM.
// The LLM must return an array of findings and optional free-text insights.
type AnalysisResult struct {
	Findings []FindingLLM `json:"findings"`
	Insights []string     `json:"insights,omitempty"`
}

// FindingLLM is the JSON shape the LLM must produce for each finding.
// The agent maps this to protocol.Finding after validation.
type FindingLLM struct {
	Severity       string            `json:"severity"`
	Category       string            `json:"category"`
	Description    string            `json:"description"`
	Impact         string            `json:"impact"`
	Recommendation string            `json:"recommendation"`
	Evidence       map[string]string `json:"evidence,omitempty"`
}

// Analyze sends raw command output to the LLM sub-agent and returns the LLM's
// findings.  The caller passes the raw stdout/stderr from a system tool (e.g.
// `ss -tulnp`, `ps axo ...`, contents of /proc/modules).
//
// Pipeline:
//  1. Prompt injection defense — invisible characters are stripped and known
//     injection phrases are redacted.  Any detected attempt is logged at HIGH.
//  2. Sensitive-value tokenization — IPs, credentials, emails, etc. are
//     replaced with stable opaque tokens (e.g. <IP_1>).  Tokens remain in the
//     returned findings permanently; they are NEVER restored to real values
//     here because findings continue to the advisory LLM.  Call
//     sanitizer.RestoreFindings on the final report only when displaying output
//     to a human operator.
//  3. Data-section wrapping — tokenized output is enclosed in <data> tags so
//     the LLM's trust boundary is structurally enforced.
//
// If the LLM is unreachable, returns an empty slice and a non-nil error so the
// caller can fall back to deterministic parsing.
func (sa *SubAgent) Analyze(ctx context.Context, rawOutput string) ([]protocol.Finding, []string, error) {
	ctx = logger.WithComponent(ctx, "llm-subagent")

	// 1. Defend against prompt injection attacks embedded in tool output.
	defended, injections := DefendPromptInjection(rawOutput)
	for _, m := range injections {
		logger.Warn(ctx, "prompt injection attempt detected in tool output",
			"task", string(sa.task),
			"pattern", m.Label,
			"excerpt", m.Excerpt,
		)
	}

	// 2. Tokenize sensitive values — tokens stay in findings permanently.
	sanitizer := NewSanitizer()
	sanitizedOutput := sanitizer.Sanitize(defended)
	if sanitizer.HasSubstitutions() {
		logger.Info(ctx, "sensitive values tokenized before LLM prompt",
			"task", string(sa.task),
			"substitutions", sanitizer.SubstitutionCount(),
		)
	}

	// 3. Wrap the data section and prepend the trust-boundary preamble.
	reqPayload := AnalysisRequest{
		Task:         string(sa.task),
		SystemPrompt: PromptInjectionPreamble + sa.prompt,
		UserMessage:  WrapDataSection(sanitizedOutput),
		Model:        sa.model,
	}

	body, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, nil, fmt.Errorf("llm subagent %s: marshal request: %w", sa.task, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sa.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("llm subagent %s: build request: %w", sa.task, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if sa.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+sa.apiKey)
	}

	resp, err := sa.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("llm subagent %s: request: %w", sa.task, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("llm subagent %s: status %d", sa.task, resp.StatusCode)
	}

	var result AnalysisResult
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil, fmt.Errorf("llm subagent %s: decode response: %w", sa.task, err)
	}

	findings := mapLLMFindings(result.Findings)

	logger.Info(ctx, "sub-agent analysis complete",
		"task", string(sa.task),
		"findings", len(findings),
		"insights", len(result.Insights),
	)

	return findings, result.Insights, nil
}

// mapLLMFindings converts the LLM's JSON findings into protocol.Finding values.
// Invalid severities are clamped to INFO; missing fields default to empty strings.
func mapLLMFindings(llmFindings []FindingLLM) []protocol.Finding {
	findings := make([]protocol.Finding, 0, len(llmFindings))
	for _, lf := range llmFindings {
		sev := parseSeverity(lf.Severity)
		evidence := make(map[string]any, len(lf.Evidence))
		for k, v := range lf.Evidence {
			evidence[k] = v
		}
		findings = append(findings, protocol.NewFinding(protocol.FindingSpec{
			Severity:       sev,
			Category:       lf.Category,
			Description:    lf.Description,
			Impact:         lf.Impact,
			Recommendation: lf.Recommendation,
			Evidence:       evidence,
			Timestamp:      time.Now().UTC(),
		}))
	}
	return findings
}

// parseSeverity maps a string to protocol.Severity, defaulting to INFO for
// unrecognised values to avoid panics on malformed LLM output.
func parseSeverity(s string) protocol.Severity {
	switch protocol.Severity(s) {
	case protocol.SeverityCritical:
		return protocol.SeverityCritical
	case protocol.SeverityHigh:
		return protocol.SeverityHigh
	case protocol.SeverityMedium:
		return protocol.SeverityMedium
	case protocol.SeverityLow:
		return protocol.SeverityLow
	case protocol.SeverityInfo:
		return protocol.SeverityInfo
	default:
		return protocol.SeverityInfo
	}
}
