package hardener

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/GGP1/mitiga/internal/executor"
	"github.com/GGP1/mitiga/internal/llm"
	"github.com/GGP1/mitiga/internal/logger"
	"github.com/GGP1/mitiga/pkg/protocol"
)

// Assessor performs read-only baseline hardening checks.
type Assessor struct {
	exec     *executor.Executor
	subAgent *llm.SubAgent
}

// New creates a hardening baseline Assessor.
func New(exec *executor.Executor) *Assessor {
	return &Assessor{exec: exec}
}

// SetSubAgent attaches an LLM sub-agent for AI-driven analysis.
func (a *Assessor) SetSubAgent(sa *llm.SubAgent) {
	a.subAgent = sa
}

// AssessBaseline runs sysctl -a and delegates analysis to the LLM sub-agent.
func (a *Assessor) AssessBaseline(ctx context.Context) ([]protocol.Finding, error) {
	ctx = logger.WithComponent(ctx, "hardener")

	result := a.exec.Run(ctx, "sysctl", "-a")
	if result.Err != nil {
		return nil, fmt.Errorf("hardener: sysctl -a: %w", result.Err)
	}

	if a.subAgent == nil {
		return nil, nil
	}

	findings, _, err := a.subAgent.Analyze(ctx, result.Stdout)
	if err != nil {
		return nil, fmt.Errorf("hardener: baseline assessment sub-agent: %w", err)
	}
	return findings, nil
}

// CheckSudoers reads sudoers files and delegates analysis to the LLM sub-agent.
func (a *Assessor) CheckSudoers(ctx context.Context) ([]protocol.Finding, error) {
	ctx = logger.WithComponent(ctx, "hardener")

	files := []string{"/etc/sudoers"}
	entries, err := os.ReadDir("/etc/sudoers.d")
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("hardener: read /etc/sudoers.d: %w", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			files = append(files, filepath.Join("/etc/sudoers.d", e.Name()))
		}
	}

	if a.subAgent == nil {
		return nil, nil
	}

	var combined strings.Builder
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		fmt.Fprintf(&combined, "=== %s ===\\n%s\\n", path, string(data))
	}

	if combined.Len() == 0 {
		return nil, nil
	}

	findings, _, err := a.subAgent.Analyze(ctx, combined.String())
	if err != nil {
		return nil, fmt.Errorf("hardener: sudoers sub-agent: %w", err)
	}
	return findings, nil
}

// CheckCronJobs reads all system crontab files and delegates analysis to the
// LLM sub-agent.
func (a *Assessor) CheckCronJobs(ctx context.Context) ([]protocol.Finding, error) {
	ctx = logger.WithComponent(ctx, "hardener")

	cronFiles := []string{"/etc/crontab"}
	for _, dir := range []string{"/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				cronFiles = append(cronFiles, filepath.Join(dir, e.Name()))
			}
		}
	}

	if a.subAgent == nil {
		return nil, nil
	}

	var combined strings.Builder
	for _, path := range cronFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		fmt.Fprintf(&combined, "=== %s ===\\n%s\\n", path, string(data))
	}

	if combined.Len() == 0 {
		return nil, nil
	}

	findings, _, err := a.subAgent.Analyze(ctx, combined.String())
	if err != nil {
		return nil, fmt.Errorf("hardener: cron jobs sub-agent: %w", err)
	}
	return findings, nil
}
