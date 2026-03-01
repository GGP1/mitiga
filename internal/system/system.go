// Package system provides user, group, and file permission auditing.
//
// Per §4.3: Audit user accounts, detect unauthorized users, verify group
// memberships, enforce password policies. Create or modify users/groups
// only with explicit system manager permission.
package system

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/GGP1/mitiga/internal/executor"
	"github.com/GGP1/mitiga/internal/llm"
	"github.com/GGP1/mitiga/internal/logger"
	"github.com/GGP1/mitiga/pkg/protocol"
)

// UserInfo describes a system user account.
type UserInfo struct {
	Name    string `json:"name"`
	UID     int    `json:"uid"`
	GID     int    `json:"gid"`
	Home    string `json:"home"`
	Shell   string `json:"shell"`
	Comment string `json:"comment"`
}

// Auditor checks users, groups, and file permissions.
type Auditor struct {
	executor *executor.Executor
	subAgent *llm.SubAgent
}

// New creates a new system Auditor with the given command executor.
func New(exec *executor.Executor) *Auditor {
	return &Auditor{executor: exec}
}

// SetSubAgent attaches an LLM sub-agent for AI-driven analysis.
func (a *Auditor) SetSubAgent(sa *llm.SubAgent) {
	a.subAgent = sa
}

// ListUsers returns all system user accounts using getent.
func (a *Auditor) ListUsers(ctx context.Context) ([]UserInfo, error) {
	ctx = logger.WithComponent(ctx, "system")
	logger.Info(ctx, "listing system users", "tool", "getent")

	result := a.executor.Run(ctx, "getent", "passwd")
	if result.Err != nil {
		return nil, fmt.Errorf("system: list users: %w", result.Err)
	}

	users := parsePasswdOutput(result.Stdout)

	logger.Info(ctx, "user listing complete",
		"count", len(users),
		"outcome", "success",
	)

	return users, nil
}

// parsePasswdOutput parses /etc/passwd format output.
func parsePasswdOutput(output string) []UserInfo {
	var users []UserInfo

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}

		uid, _ := strconv.Atoi(fields[2])
		gid, _ := strconv.Atoi(fields[3])

		users = append(users, UserInfo{
			Name:    fields[0],
			UID:     uid,
			GID:     gid,
			Comment: fields[4],
			Home:    fields[5],
			Shell:   fields[6],
		})
	}

	return users
}

// AuditUsers checks user accounts for security issues using the LLM sub-agent.
func (a *Auditor) AuditUsers(ctx context.Context) ([]protocol.Finding, error) {
	ctx = logger.WithComponent(ctx, "system")

	passwdResult := a.executor.Run(ctx, "getent", "passwd")
	if passwdResult.Err != nil {
		return nil, fmt.Errorf("system: list users: %w", passwdResult.Err)
	}

	if a.subAgent == nil {
		return nil, nil
	}

	shadowResult := a.executor.Run(ctx, "getent", "shadow")
	rawData := "=== passwd ===\n" + passwdResult.Stdout
	if shadowResult.Err == nil {
		rawData += "\n=== shadow ===\n" + shadowResult.Stdout
	}

	findings, _, err := a.subAgent.Analyze(ctx, rawData)
	if err != nil {
		return nil, fmt.Errorf("system: user audit sub-agent: %w", err)
	}
	return findings, nil
}

// CheckFilePermissions verifies permissions on critical system files.
func (a *Auditor) CheckFilePermissions(ctx context.Context) ([]protocol.Finding, error) {
	ctx = logger.WithComponent(ctx, "system")

	criticalFiles := []struct {
		path     string
		maxPerms string
		desc     string
	}{
		{"/etc/shadow", "640", "password hashes"},
		{"/etc/gshadow", "640", "group password hashes"},
		{"/etc/ssh/sshd_config", "600", "SSH server configuration"},
		{"/etc/passwd", "644", "user account database"},
		{"/etc/group", "644", "group database"},
	}

	var findings []protocol.Finding

	for _, cf := range criticalFiles {
		result := a.executor.Run(ctx, "stat", "-c", "%a %U %G", cf.path)
		if result.Err != nil {
			continue
		}

		output := strings.TrimSpace(result.Stdout)
		fields := strings.Fields(output)
		if len(fields) < 3 {
			continue
		}

		perms := fields[0]
		owner := fields[1]
		group := fields[2]

		if isPermsTooWide(perms, cf.maxPerms) {
			findings = append(findings, protocol.NewFinding(protocol.FindingSpec{
				Severity:    protocol.SeverityHigh,
				Category:    "file-permissions",
				Description: fmt.Sprintf("File %s (%s) has permissions %s (expected max %s)", cf.path, cf.desc, perms, cf.maxPerms),
				Evidence: map[string]any{
					"path":           cf.path,
					"owner":          owner,
					"group":          group,
					"actual_perms":   perms,
					"expected_perms": cf.maxPerms,
				},
				Impact:         fmt.Sprintf("Overly permissive access to %s may allow unauthorized reading or modification.", cf.path),
				Recommendation: fmt.Sprintf("Restrict permissions: chmod %s %s", cf.maxPerms, cf.path),
				Timestamp:      time.Now().UTC(),
			}))
		}

		if owner != "root" {
			findings = append(findings, protocol.NewFinding(protocol.FindingSpec{
				Severity:    protocol.SeverityHigh,
				Category:    "file-ownership",
				Description: fmt.Sprintf("File %s owned by %s (expected root)", cf.path, owner),
				Evidence: map[string]any{
					"path":           cf.path,
					"owner":          owner,
					"group":          group,
					"expected_owner": "root",
				},
				Impact:         fmt.Sprintf("Non-root ownership of %s could allow unauthorized modification.", cf.path),
				Recommendation: fmt.Sprintf("Restore ownership: chown root %s", cf.path),
				Timestamp:      time.Now().UTC(),
			}))
		}
	}

	return findings, nil
}

// isPermsTooWide checks if actual permissions exceed the maximum allowed.
func isPermsTooWide(actual, maxAllowed string) bool {
	a, err1 := strconv.ParseUint(actual, 8, 32)
	m, err2 := strconv.ParseUint(maxAllowed, 8, 32)
	if err1 != nil || err2 != nil {
		return false
	}
	return (a & ^m) != 0
}

// CheckAuthorizedKeys reads authorized_keys for all users and delegates
// analysis to the LLM sub-agent.
func (a *Auditor) CheckAuthorizedKeys(ctx context.Context) ([]protocol.Finding, error) {
	ctx = logger.WithComponent(ctx, "system")

	users, err := a.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("system: list users for authorized_keys check: %w", err)
	}

	if a.subAgent == nil {
		return nil, nil
	}

	var combined strings.Builder
	for _, u := range users {
		if u.Home == "" || u.Home == "/" {
			continue
		}
		// Use os.OpenRoot to scope file access to the user's home directory,
		// preventing directory traversal via a malicious home path.
		homeRoot, oerr := os.OpenRoot(u.Home)
		if oerr != nil {
			continue
		}
		f, ferr := homeRoot.Open(".ssh/authorized_keys")
		homeRoot.Close()
		if ferr != nil {
			continue
		}
		data, rerr := io.ReadAll(f)
		f.Close()
		if rerr != nil {
			continue
		}
		displayPath := filepath.Join(u.Home, ".ssh", "authorized_keys")
		fmt.Fprintf(&combined, "=== user=%s uid=%d file=%s ===\n%s\n", u.Name, u.UID, displayPath, string(data))
	}

	if combined.Len() == 0 {
		return nil, nil
	}

	findings, _, err := a.subAgent.Analyze(ctx, combined.String())
	if err != nil {
		return nil, fmt.Errorf("system: authorized_keys sub-agent: %w", err)
	}
	return findings, nil
}

// CheckSUIDFiles walks common binary directories and delegates SUID/SGID
// analysis to the LLM sub-agent.
func (a *Auditor) CheckSUIDFiles(ctx context.Context) ([]protocol.Finding, error) {
	ctx = logger.WithComponent(ctx, "system")
	logger.Debug(ctx, "scanning for unexpected SUID/SGID binaries")

	if a.subAgent == nil {
		return nil, nil
	}

	scanDirs := []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/local/bin", "/usr/local/sbin"}

	var sb strings.Builder
	for _, dir := range scanDirs {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			mode := info.Mode()
			hasSUID := mode&os.ModeSetuid != 0
			hasSGID := mode&os.ModeSetgid != 0
			if !hasSUID && !hasSGID {
				return nil
			}
			bits := make([]string, 0, 2)
			if hasSUID {
				bits = append(bits, "SUID")
			}
			if hasSGID {
				bits = append(bits, "SGID")
			}
			fmt.Fprintf(&sb, "%s  %s  %s\n", path, mode, strings.Join(bits, "+"))
			return nil
		})
	}

	if sb.Len() == 0 {
		return nil, nil
	}

	findings, _, err := a.subAgent.Analyze(ctx, sb.String())
	if err != nil {
		return nil, fmt.Errorf("system: SUID/SGID analysis sub-agent: %w", err)
	}
	return findings, nil
}
