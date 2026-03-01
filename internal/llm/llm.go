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

// Recommendation is a single advisory recommendation returned by the LLM.
type Recommendation struct {
	Title      string   `json:"title"`
	Rationale  string   `json:"rationale"`
	Actions    []string `json:"actions"`
	Confidence string   `json:"confidence"`
}

// AnalysisResponse is the structured LLM response envelope.
type AnalysisResponse struct {
	Summary         string           `json:"summary"`
	Recommendations []Recommendation `json:"recommendations"`
}

// Client is an LLM advisory client. It supports both local inference servers
// (e.g. Ollama) and external API providers (e.g. OpenRouter).
type Client struct {
	cfg        config.LLMConfig
	httpClient *http.Client
}

// New creates an LLM client from config.
func New(cfg config.LLMConfig) *Client {
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
		},
	}
}

// AnalyzeFindings sends findings to the configured LLM endpoint for recommendations.
func (c *Client) AnalyzeFindings(ctx context.Context, agentID string, findings []protocol.Finding) (*AnalysisResponse, error) {
	ctx = logger.WithComponent(ctx, "llm")

	reqPayload := map[string]any{
		"agent_id":      agentID,
		"timestamp":     time.Now().UTC(),
		"advisory_only": c.cfg.AdvisoryOnly,
		"model":         c.cfg.AdvisoryModel,
		"findings":      findings,
	}

	body, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, fmt.Errorf("llm: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("llm: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("llm: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("llm: endpoint returned status %d", resp.StatusCode)
	}

	var analysis AnalysisResponse
	if err := json.NewDecoder(resp.Body).Decode(&analysis); err != nil {
		return nil, fmt.Errorf("llm: decode response: %w", err)
	}

	logger.Info(ctx, "llm analysis completed",
		"recommendations", len(analysis.Recommendations),
	)

	return &analysis, nil
}
