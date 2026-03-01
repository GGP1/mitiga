// Package process provides process listing, monitoring, and anomaly detection.
//
// Per §4.3: List running processes, detect suspicious processes (unexpected
// parents, unusual resource usage, hidden PIDs), and signal processes when authorized.
package process

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/GGP1/mitiga/internal/executor"
	"github.com/GGP1/mitiga/internal/llm"
	"github.com/GGP1/mitiga/internal/logger"
	"github.com/GGP1/mitiga/pkg/protocol"
)

// Info describes a running process.
type Info struct {
	PID     int     `json:"pid"`
	PPID    int     `json:"ppid"`
	User    string  `json:"user"`
	CPU     float64 `json:"cpu"`
	MEM     float64 `json:"mem"`
	VSZ     int64   `json:"vsz"`
	RSS     int64   `json:"rss"`
	Command string  `json:"command"`
}

// Monitor audits running processes for anomalies.
type Monitor struct {
	executor *executor.Executor
	subAgent *llm.SubAgent
}

// New creates a new process Monitor with the given command executor.
func New(executor *executor.Executor) *Monitor {
	return &Monitor{executor: executor}
}

// SetSubAgent attaches an LLM sub-agent for AI-driven analysis.
func (m *Monitor) SetSubAgent(sa *llm.SubAgent) {
	m.subAgent = sa
}

// List returns all running processes.
func (m *Monitor) List(ctx context.Context) ([]Info, error) {
	ctx = logger.WithComponent(ctx, "process")
	logger.Info(ctx, "listing processes", "tool", "ps")

	// ps with explicit output format for reliable parsing.
	result := m.executor.Run(ctx, "ps", "axo", "pid,ppid,user,%cpu,%mem,vsz,rss,args", "--no-headers")
	if result.Err != nil {
		return nil, fmt.Errorf("process: list: %w", result.Err)
	}

	procs, err := parsePSOutput(result.Stdout)
	if err != nil {
		return nil, fmt.Errorf("process: parse ps output: %w", err)
	}

	logger.Info(ctx, "process listing complete",
		"count", len(procs),
		"outcome", "success",
	)

	return procs, nil
}

// parsePSOutput parses ps output into structured process info.
func parsePSOutput(output string) ([]Info, error) {
	var procs []Info

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 8 {
			continue
		}

		pid, _ := strconv.Atoi(fields[0])
		ppid, _ := strconv.Atoi(fields[1])
		cpu, _ := strconv.ParseFloat(fields[3], 64)
		mem, _ := strconv.ParseFloat(fields[4], 64)
		vsz, _ := strconv.ParseInt(fields[5], 10, 64)
		rss, _ := strconv.ParseInt(fields[6], 10, 64)
		cmd := strings.Join(fields[7:], " ")

		procs = append(procs, Info{
			PID:     pid,
			PPID:    ppid,
			User:    fields[2],
			CPU:     cpu,
			MEM:     mem,
			VSZ:     vsz,
			RSS:     rss,
			Command: cmd,
		})
	}

	return procs, scanner.Err()
}

// DetectAnomalies checks for suspicious processes and returns findings.
func (m *Monitor) DetectAnomalies(ctx context.Context) ([]protocol.Finding, error) {
	ctx = logger.WithComponent(ctx, "process")

	result := m.executor.Run(ctx, "ps", "axo", "pid,ppid,user,%cpu,%mem,vsz,rss,args", "--no-headers")
	if result.Err != nil {
		return nil, fmt.Errorf("process: list processes: %w", result.Err)
	}

	if m.subAgent == nil {
		return nil, nil
	}

	findings, _, err := m.subAgent.Analyze(ctx, result.Stdout)
	if err != nil {
		return nil, fmt.Errorf("process: anomaly detection sub-agent: %w", err)
	}
	return findings, nil
}

// DetectRootkitModules reads /proc/modules and delegates analysis to the LLM
// sub-agent to detect known and novel kernel-level rootkits.
func (m *Monitor) DetectRootkitModules(ctx context.Context) ([]protocol.Finding, error) {
	ctx = logger.WithComponent(ctx, "process")

	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return nil, fmt.Errorf("process: read /proc/modules: %w", err)
	}

	if m.subAgent == nil {
		return nil, nil
	}

	findings, _, err := m.subAgent.Analyze(ctx, string(data))
	if err != nil {
		return nil, fmt.Errorf("process: rootkit detection sub-agent: %w", err)
	}
	return findings, nil
}
