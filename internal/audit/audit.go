package audit

import (
	"context"
	"fmt"
	"strings"

	"github.com/GGP1/mitiga/internal/executor"
	"github.com/GGP1/mitiga/internal/llm"
	"github.com/GGP1/mitiga/internal/logger"
	"github.com/GGP1/mitiga/pkg/protocol"
)

const secretPattern = `(AKIA[0-9A-Z]{16}|-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----|password[[:space:]]*=[[:space:]]*["'][^"']+["'])`

// Auditor performs conservative source code security checks.
type Auditor struct {
	exec     *executor.Executor
	rootDir  string
	subAgent *llm.SubAgent
}

// New creates an Auditor for a repository root directory.
func New(exec *executor.Executor, rootDir string) *Auditor {
	return &Auditor{exec: exec, rootDir: rootDir}
}

// SetSubAgent attaches an LLM sub-agent for AI-driven analysis.
func (a *Auditor) SetSubAgent(sa *llm.SubAgent) {
	a.subAgent = sa
}

// ScanForSecrets scans repository files for likely hardcoded secrets using
// the LLM sub-agent.
func (a *Auditor) ScanForSecrets(ctx context.Context) ([]protocol.Finding, error) {
	ctx = logger.WithComponent(ctx, "audit")

	result := a.exec.Run(ctx, "grep", "-RInE", secretPattern, "--exclude-dir=.git", "--exclude-dir=vendor", a.rootDir)
	if result.Err != nil && result.ExitCode == 1 && strings.TrimSpace(result.Stderr) == "" {
		return nil, nil
	}
	if result.Err != nil {
		return nil, fmt.Errorf("audit: grep secret patterns: %w", result.Err)
	}

	if a.subAgent == nil {
		return nil, nil
	}

	findings, _, err := a.subAgent.Analyze(ctx, result.Stdout)
	if err != nil {
		return nil, fmt.Errorf("audit: secrets analysis sub-agent: %w", err)
	}
	return findings, nil
}
