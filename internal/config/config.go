// Package config provides layered configuration loading for Mitiga.
//
// Configuration is loaded in order of increasing precedence:
//  1. Hardcoded safe defaults (most restrictive)
//  2. TOML configuration file (config/mitiga.toml)
//  3. Environment variables (prefixed with MITIGA_)
//  4. CLI flags (highest precedence)
package config

import (
	"fmt"
	"os"
	"time"
)

// Config holds all Mitiga agent configuration.
type Config struct {
	Agent    AgentConfig    `toml:"agent"`
	Security SecurityConfig `toml:"security"`
	Runtime  RuntimeConfig  `toml:"runtime"`
	LLM      LLMConfig      `toml:"llm"`
	Scan     ScanConfig     `toml:"scan"`
	Report   ReportConfig   `toml:"report"`
}

// AgentConfig holds agent identity and logging settings.
type AgentConfig struct {
	// ID is the unique agent identifier, derived from the certificate
	// fingerprint if left empty.
	ID string `toml:"id"`
	// LogLevel controls the minimum severity for log output.
	// Valid values: debug, info, warn, error.
	LogLevel string `toml:"log_level"`
	// LogOutput controls the console log destination.
	// Valid values: stdout, stderr, none.
	LogOutput string `toml:"log_output"`
	// LogFile is the mandatory file path for the authoritative audit trail.
	LogFile string `toml:"log_file"`
}

// SecurityConfig controls the agent's operational safety posture.
type SecurityConfig struct {
	// AutoRemediate allows automatic remediation of MEDIUM and LOW findings
	// when explicitly enabled by the system manager.
	AutoRemediate bool `toml:"auto_remediate"`
	// MaxCommandTimeout is the maximum duration for any executed command.
	MaxCommandTimeout time.Duration `toml:"max_command_timeout"`
	// RequireManagerApproval requires system manager confirmation for
	// impactful actions.
	RequireManagerApproval bool `toml:"require_manager_approval"`
}

// RuntimeConfig controls daemon scheduling and event polling.
type RuntimeConfig struct {
	// ScanInterval is the periodic full scan interval.
	ScanInterval time.Duration `toml:"scan_interval"`
	// EventPollInterval is the filesystem/event polling interval.
	EventPollInterval time.Duration `toml:"event_poll_interval"`
	// HeartbeatInterval is the daemon liveness heartbeat interval.
	HeartbeatInterval time.Duration `toml:"heartbeat_interval"`
	// WatchPaths are paths that trigger scan cycles on metadata changes.
	WatchPaths []string `toml:"watch_paths"`
	// StateFile is the path where the agent persists its snapshot across
	// restarts.  Must be on a local filesystem; the directory is created
	// automatically if it does not exist.
	StateFile string `toml:"state_file"`
	// EventQueueSize is the buffer capacity of the internal event queue.
	// Producers drop events when the queue is full rather than blocking.
	EventQueueSize int `toml:"event_queue_size"`
}

// LLMConfig controls LLM advisory integration.
type LLMConfig struct {
	// Endpoint is the HTTP endpoint for LLM inference.
	// Can be a local server (e.g. Ollama) or an external API (e.g. OpenRouter).
	Endpoint string `toml:"endpoint"`
	// APIKey is the bearer token sent in the Authorization header.
	// Required for external providers such as OpenRouter. Leave empty for
	// unauthenticated local endpoints.
	APIKey string `toml:"api_key"`
	// FindingsModel is the model used by all security module sub-agents
	// (scanner, process, system, hardener, logaudit, audit) to produce findings
	// from raw command output.
	FindingsModel string `toml:"findings_model"`
	// AdvisoryModel is the model used for the post-scan holistic advisory that
	// analyses the aggregated set of findings.
	AdvisoryModel string `toml:"advisory_model"`
	// Timeout is the LLM request timeout.
	Timeout time.Duration `toml:"timeout"`
	// AdvisoryOnly ensures LLM output is non-executing recommendation text.
	AdvisoryOnly bool `toml:"advisory_only"`
}

// ScanConfig controls scanning behavior.
type ScanConfig struct {
	// DefaultPortRange is the TCP port range to scan.
	DefaultPortRange string `toml:"default_port_range"`
	// ScanTimeout is the maximum duration for a single scan operation.
	ScanTimeout time.Duration `toml:"scan_timeout"`
	// MaxConcurrentScans limits the number of scans running in parallel.
	MaxConcurrentScans int `toml:"max_concurrent_scans"`
}

// ReportConfig controls report generation.
type ReportConfig struct {
	// OutputDir is the directory where reports are stored.
	OutputDir string `toml:"output_dir"`
	// Format is the default report format: json, markdown, html.
	Format string `toml:"format"`
	// RetentionDays is how long reports are kept before cleanup.
	RetentionDays int `toml:"retention_days"`
}

// Default returns a Config with hardcoded safe defaults.
// These are the most restrictive settings — the secure baseline.
func Default() Config {
	return Config{
		Agent: AgentConfig{
			ID:        "",
			LogLevel:  "info",
			LogOutput: "stdout",
			LogFile:   "/var/log/mitiga/mitiga.log",
		},
		Security: SecurityConfig{
			AutoRemediate:          false,
			MaxCommandTimeout:      60 * time.Second,
			RequireManagerApproval: true,
		},
		Runtime: RuntimeConfig{
			ScanInterval:      30 * time.Second,
			EventPollInterval: 5 * time.Second,
			HeartbeatInterval: 60 * time.Second,
			WatchPaths:        []string{"/etc", "/usr/local/bin", "/var/lib/mitiga"},
			StateFile:         "/var/lib/mitiga/state.json",
			EventQueueSize:    64,
		},
		LLM: LLMConfig{
			Endpoint:     "http://127.0.0.1:11434/api/mitiga/analyze",
			Timeout:      10 * time.Second,
			AdvisoryOnly: true,
		},
		Scan: ScanConfig{
			DefaultPortRange:   "1-65535",
			ScanTimeout:        120 * time.Second,
			MaxConcurrentScans: 4,
		},
		Report: ReportConfig{
			OutputDir:     "/var/lib/mitiga/reports",
			Format:        "json",
			RetentionDays: 90,
		},
	}
}

// ApplyEnvironment overlays environment variables onto the config.
// Environment variables use the MITIGA_ prefix and override file settings.
func (c *Config) ApplyEnvironment() {
	if v := os.Getenv("MITIGA_LOG_LEVEL"); v != "" {
		c.Agent.LogLevel = v
	}
	if v := os.Getenv("MITIGA_LOG_OUTPUT"); v != "" {
		c.Agent.LogOutput = v
	}
	if v := os.Getenv("MITIGA_LOG_FILE"); v != "" {
		c.Agent.LogFile = v
	}
	if v := os.Getenv("MITIGA_AGENT_ID"); v != "" {
		c.Agent.ID = v
	}
	if v := os.Getenv("MITIGA_AUTO_REMEDIATE"); v != "" {
		c.Security.AutoRemediate = v == "true" || v == "1"
	}
	if v := os.Getenv("MITIGA_MAX_COMMAND_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Security.MaxCommandTimeout = d
		}
	}
	if v := os.Getenv("MITIGA_REPORT_DIR"); v != "" {
		c.Report.OutputDir = v
	}
	if v := os.Getenv("MITIGA_REPORT_FORMAT"); v != "" {
		c.Report.Format = v
	}
	if v := os.Getenv("MITIGA_SCAN_PORT_RANGE"); v != "" {
		c.Scan.DefaultPortRange = v
	}
	if v := os.Getenv("MITIGA_SCAN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Scan.ScanTimeout = d
		}
	}
	if v := os.Getenv("MITIGA_RUNTIME_SCAN_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Runtime.ScanInterval = d
		}
	}
	if v := os.Getenv("MITIGA_RUNTIME_EVENT_POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Runtime.EventPollInterval = d
		}
	}
	if v := os.Getenv("MITIGA_RUNTIME_HEARTBEAT_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Runtime.HeartbeatInterval = d
		}
	}
	if v := os.Getenv("MITIGA_RUNTIME_STATE_FILE"); v != "" {
		c.Runtime.StateFile = v
	}
	if v := os.Getenv("MITIGA_RUNTIME_EVENT_QUEUE_SIZE"); v != "" {
		if n, err := fmt.Sscanf(v, "%d", &c.Runtime.EventQueueSize); n != 1 || err != nil {
			// Ignore malformed value; validation will catch zero/negative.
		}
	}
	if v := os.Getenv("MITIGA_LLM_ENDPOINT"); v != "" {
		c.LLM.Endpoint = v
	}
	if v := os.Getenv("MITIGA_LLM_API_KEY"); v != "" {
		c.LLM.APIKey = v
	}
	if v := os.Getenv("MITIGA_LLM_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.LLM.Timeout = d
		}
	}
}

// Validate checks that the configuration is internally consistent and safe.
func (c *Config) Validate() error {
	if c.Agent.LogFile == "" {
		return fmt.Errorf("config: log_file is mandatory for the audit trail")
	}

	switch c.Agent.LogLevel {
	case "debug", "info", "warn", "error":
		// valid
	default:
		return fmt.Errorf("config: invalid log_level %q (must be debug, info, warn, error)", c.Agent.LogLevel)
	}

	switch c.Agent.LogOutput {
	case "stdout", "stderr", "none":
		// valid
	default:
		return fmt.Errorf("config: invalid log_output %q (must be stdout, stderr, none)", c.Agent.LogOutput)
	}

	if c.Runtime.ScanInterval <= 0 {
		return fmt.Errorf("config: runtime.scan_interval must be positive")
	}
	if c.Runtime.EventPollInterval <= 0 {
		return fmt.Errorf("config: runtime.event_poll_interval must be positive")
	}
	if c.Runtime.HeartbeatInterval <= 0 {
		return fmt.Errorf("config: runtime.heartbeat_interval must be positive")
	}
	if c.Runtime.StateFile == "" {
		return fmt.Errorf("config: runtime.state_file must not be empty")
	}
	if c.Runtime.EventQueueSize <= 0 {
		return fmt.Errorf("config: runtime.event_queue_size must be > 0, got %d", c.Runtime.EventQueueSize)
	}

	if c.LLM.Endpoint == "" {
		return fmt.Errorf("config: llm.endpoint is required")
	}
	if c.LLM.Timeout <= 0 {
		return fmt.Errorf("config: llm.timeout must be positive")
	}

	if c.Security.MaxCommandTimeout <= 0 {
		return fmt.Errorf("config: max_command_timeout must be positive")
	}

	if c.Scan.MaxConcurrentScans <= 0 {
		return fmt.Errorf("config: max_concurrent_scans must be > 0, got %d", c.Scan.MaxConcurrentScans)
	}

	if c.Scan.ScanTimeout <= 0 {
		return fmt.Errorf("config: scan_timeout must be positive")
	}

	switch c.Report.Format {
	case "json", "markdown", "html":
		// valid
	default:
		return fmt.Errorf("config: invalid report format %q", c.Report.Format)
	}

	if c.Report.RetentionDays <= 0 {
		return fmt.Errorf("config: retention_days must be > 0, got %d", c.Report.RetentionDays)
	}

	return nil
}
