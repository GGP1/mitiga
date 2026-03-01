package hardener

import (
	"context"
	"fmt"
	"io"
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

	// Scope all reads to /etc to prevent directory traversal.
	etcRoot, err := os.OpenRoot("/etc")
	if err != nil {
		return nil, fmt.Errorf("hardener: open /etc: %w", err)
	}
	defer etcRoot.Close()

	if a.subAgent == nil {
		return nil, nil
	}

	var combined strings.Builder

	// Read /etc/sudoers.
	if f, ferr := etcRoot.Open("sudoers"); ferr == nil {
		if data, rerr := io.ReadAll(f); rerr == nil {
			fmt.Fprintf(&combined, "=== /etc/sudoers ===\\n%s\\n", string(data))
		}
		f.Close()
	}

	// Read /etc/sudoers.d/*.
	if dir, derr := etcRoot.Open("sudoers.d"); derr == nil {
		entries, _ := dir.ReadDir(-1)
		dir.Close()
		for _, e := range entries {
			if !e.IsDir() {
				rel := filepath.Join("sudoers.d", e.Name())
				if f, ferr := etcRoot.Open(rel); ferr == nil {
					if data, rerr := io.ReadAll(f); rerr == nil {
						fmt.Fprintf(&combined, "=== /etc/%s ===\\n%s\\n", rel, string(data))
					}
					f.Close()
				}
			}
		}
	} else if !os.IsNotExist(derr) {
		if os.IsPermission(derr) {
			logger.Warn(ctx, "skipping /etc/sudoers.d: permission denied")
		} else {
			return nil, fmt.Errorf("hardener: open /etc/sudoers.d: %w", derr)
		}
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

	// Scope all reads to /etc to prevent directory traversal.
	etcRoot, err := os.OpenRoot("/etc")
	if err != nil {
		return nil, fmt.Errorf("hardener: open /etc: %w", err)
	}
	defer etcRoot.Close()

	if a.subAgent == nil {
		return nil, nil
	}

	var combined strings.Builder

	// Read /etc/crontab.
	if f, ferr := etcRoot.Open("crontab"); ferr == nil {
		if data, rerr := io.ReadAll(f); rerr == nil {
			fmt.Fprintf(&combined, "=== /etc/crontab ===\\n%s\\n", string(data))
		}
		f.Close()
	}

	// Read per-directory cron files.
	for _, dir := range []string{"cron.d", "cron.hourly", "cron.daily", "cron.weekly", "cron.monthly"} {
		d, derr := etcRoot.Open(dir)
		if derr != nil {
			continue
		}
		entries, _ := d.ReadDir(-1)
		d.Close()
		for _, e := range entries {
			if !e.IsDir() {
				rel := filepath.Join(dir, e.Name())
				if f, ferr := etcRoot.Open(rel); ferr == nil {
					if data, rerr := io.ReadAll(f); rerr == nil {
						fmt.Fprintf(&combined, "=== /etc/%s ===\\n%s\\n", rel, string(data))
					}
					f.Close()
				}
			}
		}
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
