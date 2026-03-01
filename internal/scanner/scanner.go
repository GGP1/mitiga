// Package scanner provides TCP/UDP port scanning and network reconnaissance.
//
// Per §4.3: Detect open ports, identify services, flag unexpected listeners.
// Uses system tools (ss, nmap) through the safe command executor.
package scanner

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/GGP1/mitiga/internal/executor"
	"github.com/GGP1/mitiga/internal/llm"
	"github.com/GGP1/mitiga/internal/logger"
	"github.com/GGP1/mitiga/pkg/protocol"
)

// OpenPort describes a listening port found on the system.
type OpenPort struct {
	Protocol string `json:"protocol"` // tcp, udp
	Address  string `json:"address"`  // listen address
	Port     int    `json:"port"`     // port number
	Process  string `json:"process"`  // process name (if available)
	PID      int    `json:"pid"`      // process ID (if available)
	State    string `json:"state"`    // LISTEN, ESTABLISHED, etc.
}

// Scanner audits open ports and network listeners.
type Scanner struct {
	executor *executor.Executor
	subAgent *llm.SubAgent
}

// New creates a new Scanner with the given command executor.
func New(executor *executor.Executor) *Scanner {
	return &Scanner{executor: executor}
}

// SetSubAgent attaches an LLM sub-agent for AI-driven analysis.
func (s *Scanner) SetSubAgent(sa *llm.SubAgent) {
	s.subAgent = sa
}

// ListOpenPorts discovers all listening TCP and UDP ports on the local host
// using the `ss` command.
func (s *Scanner) ListOpenPorts(ctx context.Context) ([]OpenPort, error) {
	ctx = logger.WithComponent(ctx, "scanner")
	logger.Info(ctx, "scanning open ports", "tool", "ss")

	// ss -tulnp: TCP/UDP, listening, numeric, show process
	result := s.executor.Run(ctx, "ss", "-tulnp")
	if result.Err != nil {
		return nil, fmt.Errorf("scanner: list open ports: %w", result.Err)
	}

	ports, err := parseSSOutput(result.Stdout)
	if err != nil {
		return nil, fmt.Errorf("scanner: parse ss output: %w", err)
	}

	logger.Info(ctx, "port scan complete",
		"open_ports", len(ports),
		"outcome", "success",
	)

	return ports, nil
}

// parseSSOutput parses the output of `ss -tulnp` into structured OpenPort entries.
func parseSSOutput(output string) ([]OpenPort, error) {
	var ports []OpenPort

	scanner := bufio.NewScanner(strings.NewReader(output))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip header line.
		if lineNum == 1 {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		proto := strings.ToLower(fields[0])
		state := fields[1]
		localAddr := fields[4]

		// Parse address:port.
		addr, portNum, err := parseAddress(localAddr)
		if err != nil {
			continue // Skip unparseable lines.
		}

		port := OpenPort{
			Protocol: proto,
			Address:  addr,
			Port:     portNum,
			State:    state,
		}

		// Parse process info if available (last field, format: users:(("name",pid=N,...)))
		if len(fields) >= 7 {
			port.Process, port.PID = parseProcessInfo(fields[6])
		}

		ports = append(ports, port)
	}

	return ports, scanner.Err()
}

// parseAddress splits "addr:port" or "[addr]:port" into components.
func parseAddress(addr string) (string, int, error) {
	// Handle IPv6: [::1]:8080
	if strings.HasPrefix(addr, "[") {
		idx := strings.LastIndex(addr, "]:")
		if idx == -1 {
			return "", 0, fmt.Errorf("invalid IPv6 address format: %s", addr)
		}
		host := addr[1:idx]
		portStr := addr[idx+2:]
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return "", 0, fmt.Errorf("invalid port in %s: %w", addr, err)
		}
		return host, port, nil
	}

	// Handle IPv4: 0.0.0.0:8080 or *:8080
	idx := strings.LastIndex(addr, ":")
	if idx == -1 {
		return "", 0, fmt.Errorf("no port separator in %s", addr)
	}

	host := addr[:idx]
	portStr := addr[idx+1:]

	if portStr == "*" {
		return host, 0, nil
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port in %s: %w", addr, err)
	}

	return host, port, nil
}

// parseProcessInfo extracts process name and PID from ss process info.
func parseProcessInfo(info string) (string, int) {
	// Format: users:(("sshd",pid=1234,fd=3))
	name := ""
	pid := 0

	if start := strings.Index(info, "((\""); start != -1 {
		end := strings.Index(info[start+3:], "\"")
		if end != -1 {
			name = info[start+3 : start+3+end]
		}
	}

	if _, after, ok := strings.Cut(info, "pid="); ok {
		pidStr := after
		if end := strings.IndexAny(pidStr, ",)"); end != -1 {
			pidStr = pidStr[:end]
		}
		pid, _ = strconv.Atoi(pidStr)
	}

	return name, pid
}

// FindUnexpectedListeners discovers network listeners and delegates analysis
// to the LLM sub-agent.
func (s *Scanner) FindUnexpectedListeners(ctx context.Context, expected map[int]string) ([]protocol.Finding, error) {
	ctx = logger.WithComponent(ctx, "scanner")

	result := s.executor.Run(ctx, "ss", "-tulnp")
	if result.Err != nil {
		return nil, fmt.Errorf("scanner: list open ports: %w", result.Err)
	}

	if s.subAgent == nil {
		return nil, nil
	}

	findings, _, err := s.subAgent.Analyze(ctx, result.Stdout)
	if err != nil {
		return nil, fmt.Errorf("scanner: listener analysis sub-agent: %w", err)
	}
	return findings, nil
}

// FindSuspiciousConnections examines active ESTABLISHED TCP connections and
// delegates analysis to the LLM sub-agent.
func (s *Scanner) FindSuspiciousConnections(ctx context.Context) ([]protocol.Finding, error) {
	ctx = logger.WithComponent(ctx, "scanner")

	result := s.executor.Run(ctx, "ss", "-tnp", "state", "established")
	if result.Err != nil {
		return nil, fmt.Errorf("scanner: ss established: %w", result.Err)
	}

	if s.subAgent == nil {
		return nil, nil
	}

	findings, _, err := s.subAgent.Analyze(ctx, result.Stdout)
	if err != nil {
		return nil, fmt.Errorf("scanner: connection analysis sub-agent: %w", err)
	}
	return findings, nil
}
