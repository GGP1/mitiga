// Package agent provides the core agent lifecycle, orchestration, and
// safe command execution for Mitiga.
//
// The command executor is the most security-critical component. Every command
// must pass through the allowlist, execute with a timeout, and have its
// output fully captured and logged per §4.1.
package agent

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/GGP1/mitiga/internal/logger"
	"github.com/GGP1/mitiga/pkg/protocol"
)

// CommandResult holds the outcome of an executed command.
type CommandResult struct {
	// Command is the executable name.
	Command string
	// Args are the arguments passed.
	Args []string
	// Stdout contains captured standard output.
	Stdout string
	// Stderr contains captured standard error.
	Stderr string
	// ExitCode is the process exit code.
	ExitCode int
	// Duration is how long the command took.
	Duration time.Duration
	// Err is any error that occurred during execution.
	Err error
}

// allowedCommands is the static allowlist of commands the agent may execute.
// Per §4.1: "Allowlist, don't blocklist." Only commands on this list are permitted.
// This list corresponds to the tools defined in .github/skills/README.md.
var allowedCommands = map[string]bool{
	// Network Reconnaissance
	"nmap": true, "ss": true, "ip": true,
	// Vulnerability Scanning
	"trivy": true, "grype": true, "govulncheck": true,
	// Code Auditing
	"semgrep": true, "gosec": true, "gitleaks": true,
	// Malware & Rootkit Detection
	"clamscan": true, "freshclam": true, "chkrootkit": true, "rkhunter": true,
	// File Integrity & Verification
	"sha256sum": true, "gpg": true, "aide": true,
	// File System
	"find": true, "stat": true,
	// Log Analysis
	"journalctl": true, "ausearch": true, "aureport": true,
	"auditctl": true, "last": true,
	// Process Management
	"ps": true, "lsof": true, "pgrep": true, "pkill": true, "top": true,
	// User & Group Management
	"id": true, "who": true, "getent": true, "chage": true,
	"passwd": true, "useradd": true, "usermod": true, "userdel": true,
	"groupadd": true, "groupmod": true, "groupdel": true,
	// System Hardening
	"lynis": true, "iptables": true, "ufw": true, "sysctl": true,
	"systemctl": true, "chmod": true, "chown": true,
	"aa-status": true, "aa-enforce": true, "aa-complain": true,
	"getenforce": true, "sestatus": true,
	// TLS & Certificates
	"openssl": true,
	// Network Traffic Analysis
	"tcpdump": true,
	// General System Utilities (coreutils)
	"cat": true, "head": true, "tail": true, "grep": true,
	"awk": true, "sed": true, "wc": true, "diff": true,
	"sort": true, "uniq": true, "cut": true, "file": true,
	"ldd": true, "uname": true, "hostname": true, "date": true,
	"uptime": true, "free": true, "df": true, "du": true, "mount": true,
}

// Executor runs system commands safely per §4.1.
type Executor struct {
	maxTimeout time.Duration
}

// NewExecutor creates a command executor with the given maximum timeout.
func NewExecutor(maxTimeout time.Duration) *Executor {
	return &Executor{maxTimeout: maxTimeout}
}

// Run executes a command with safety checks, timeout, and full logging.
//
// Per §4.1:
//   - Commands must be on the allowlist
//   - No shell interpolation (exec.Command with explicit args)
//   - Timeout enforced via context
//   - All output captured and logged
func (e *Executor) Run(ctx context.Context, command string, args ...string) CommandResult {
	start := time.Now()

	// Check allowlist.
	if !allowedCommands[command] {
		logger.Warn(ctx, "command denied: not on allowlist",
			"command", command,
			"args", strings.Join(args, " "),
			"outcome", "denied",
		)
		return CommandResult{
			Command:  command,
			Args:     args,
			ExitCode: -1,
			Duration: time.Since(start),
			Err:      fmt.Errorf("execute %q: %w", command, protocol.ErrCommandDenied),
		}
	}

	// Apply timeout. Use the smaller of the provided context deadline
	// and the configured maximum.
	execCtx, cancel := context.WithTimeout(ctx, e.maxTimeout)
	defer cancel()

	logger.Info(ctx, "executing command",
		"command", command,
		"args", strings.Join(args, " "),
		"timeout", e.maxTimeout.String(),
	)

	// Build command with explicit argument list — no shell interpolation.
	cmd := exec.CommandContext(execCtx, command, args...) // #nosec G204 -- command validated against skills allowlist; explicit args, no shell

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start)

	result := CommandResult{
		Command:  command,
		Args:     args,
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		Duration: duration,
		Err:      err,
	}

	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}

	// Check for timeout.
	if execCtx.Err() == context.DeadlineExceeded {
		result.Err = fmt.Errorf("execute %q: %w (after %s)", command, protocol.ErrTimeout, duration)
		logger.Warn(ctx, "command timed out",
			"command", command,
			"args", strings.Join(args, " "),
			"duration", duration.String(),
			"outcome", "timeout",
		)
		return result
	}

	if err != nil {
		logger.Warn(ctx, "command failed",
			"command", command,
			"args", strings.Join(args, " "),
			"exit_code", result.ExitCode,
			"stderr", truncate(result.Stderr, 500),
			"duration", duration.String(),
			"outcome", "error",
		)
	} else {
		logger.Info(ctx, "command completed",
			"command", command,
			"args", strings.Join(args, " "),
			"exit_code", result.ExitCode,
			"duration", duration.String(),
			"outcome", "success",
		)
	}

	return result
}

// IsAllowed checks whether a command is on the allowlist.
func IsAllowed(command string) bool {
	return allowedCommands[command]
}

// truncate limits a string to maxLen characters for safe logging.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...(truncated)"
}
