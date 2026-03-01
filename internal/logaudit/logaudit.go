package logaudit

import (
	"context"
	"fmt"
	"time"

	"github.com/GGP1/mitiga/internal/executor"
	"github.com/GGP1/mitiga/internal/llm"
	"github.com/GGP1/mitiga/internal/logger"
	"github.com/GGP1/mitiga/pkg/protocol"
)

// Analyzer scans auth logs for suspicious authentication behavior.
type Analyzer struct {
	exec     *executor.Executor
	subAgent *llm.SubAgent
}

// New creates a log anomaly Analyzer.
func New(exec *executor.Executor) *Analyzer {
	return &Analyzer{exec: exec}
}

// SetSubAgent attaches an LLM sub-agent for AI-driven analysis.
func (a *Analyzer) SetSubAgent(sa *llm.SubAgent) {
	a.subAgent = sa
}

// AnalyzeAuthFailures analyzes recent SSH auth log entries using the LLM sub-agent.
func (a *Analyzer) AnalyzeAuthFailures(ctx context.Context, since time.Duration) ([]protocol.Finding, error) {
	ctx = logger.WithComponent(ctx, "logaudit")
	sinceArg := fmt.Sprintf("%d seconds ago", int(since.Seconds()))

	result := a.exec.Run(ctx, "journalctl", "-u", "sshd", "--since", sinceArg, "--no-pager")
	if result.Err != nil {
		return nil, fmt.Errorf("logaudit: journalctl sshd: %w", result.Err)
	}

	if a.subAgent == nil {
		return nil, nil
	}

	findings, _, err := a.subAgent.Analyze(ctx, result.Stdout)
	if err != nil {
		return nil, fmt.Errorf("logaudit: auth failures sub-agent: %w", err)
	}
	return findings, nil
}

// AuditSudoUsage analyzes recent sudo journal entries using the LLM sub-agent.
func (a *Analyzer) AuditSudoUsage(ctx context.Context, since time.Duration) ([]protocol.Finding, error) {
	ctx = logger.WithComponent(ctx, "logaudit")
	sinceArg := fmt.Sprintf("%d seconds ago", int(since.Seconds()))

	result := a.exec.Run(ctx, "journalctl", "_COMM=sudo", "--since", sinceArg, "--no-pager")
	if result.Err != nil {
		return nil, fmt.Errorf("logaudit: journalctl sudo: %w", result.Err)
	}

	if a.subAgent == nil {
		return nil, nil
	}

	findings, _, err := a.subAgent.Analyze(ctx, result.Stdout)
	if err != nil {
		return nil, fmt.Errorf("logaudit: sudo audit sub-agent: %w", err)
	}
	return findings, nil
}
