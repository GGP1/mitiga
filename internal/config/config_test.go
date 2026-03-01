package config

import (
	"os"
	"testing"
	"time"
)

func TestDefault(t *testing.T) {
	cfg := Default()

	if cfg.Agent.LogLevel != "info" {
		t.Errorf("default log level: got %q, want %q", cfg.Agent.LogLevel, "info")
	}
	if cfg.Runtime.ScanInterval <= 0 {
		t.Error("default runtime scan interval should be positive")
	}
	if cfg.Security.AutoRemediate {
		t.Error("default auto_remediate should be false")
	}
	if cfg.Security.RequireManagerApproval != true {
		t.Error("default require_manager_approval should be true")
	}
	if cfg.Scan.DefaultPortRange != "1-65535" {
		t.Errorf("default port range: got %q, want %q", cfg.Scan.DefaultPortRange, "1-65535")
	}
	if cfg.Report.Format != "json" {
		t.Errorf("default report format: got %q, want %q", cfg.Report.Format, "json")
	}
}

func TestValidate_ValidConfig(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config should be valid: %v", err)
	}
}

func TestValidate_InvalidLogLevel(t *testing.T) {
	cfg := Default()
	cfg.Agent.LogLevel = "trace"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid log level")
	}
}

func TestValidate_InvalidLogOutput(t *testing.T) {
	cfg := Default()
	cfg.Agent.LogOutput = "file"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid log output")
	}
}

func TestValidate_EmptyLogFile(t *testing.T) {
	cfg := Default()
	cfg.Agent.LogFile = ""
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty log file")
	}
}

func TestValidate_InvalidTimeout(t *testing.T) {
	cfg := Default()
	cfg.Security.MaxCommandTimeout = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for zero timeout")
	}
}

func TestValidate_InvalidReportFormat(t *testing.T) {
	cfg := Default()
	cfg.Report.Format = "pdf"
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for invalid report format")
	}
}

func TestApplyEnvironment(t *testing.T) {
	cfg := Default()

	t.Setenv("MITIGA_LOG_LEVEL", "debug")
	t.Setenv("MITIGA_AGENT_ID", "test-agent-001")
	t.Setenv("MITIGA_AUTO_REMEDIATE", "true")
	t.Setenv("MITIGA_REPORT_FORMAT", "markdown")
	t.Setenv("MITIGA_SCAN_PORT_RANGE", "1-1024")

	cfg.ApplyEnvironment()

	if cfg.Agent.LogLevel != "debug" {
		t.Errorf("log level: got %q, want %q", cfg.Agent.LogLevel, "debug")
	}
	if cfg.Agent.ID != "test-agent-001" {
		t.Errorf("agent ID: got %q, want %q", cfg.Agent.ID, "test-agent-001")
	}
	if !cfg.Security.AutoRemediate {
		t.Error("auto_remediate should be true after env override")
	}
	if cfg.Report.Format != "markdown" {
		t.Errorf("report format: got %q, want %q", cfg.Report.Format, "markdown")
	}
	if cfg.Scan.DefaultPortRange != "1-1024" {
		t.Errorf("port range: got %q, want %q", cfg.Scan.DefaultPortRange, "1-1024")
	}
}

func TestApplyEnvironment_Duration(t *testing.T) {
	cfg := Default()
	t.Setenv("MITIGA_MAX_COMMAND_TIMEOUT", "120s")
	cfg.ApplyEnvironment()

	if cfg.Security.MaxCommandTimeout != 120*time.Second {
		t.Errorf("timeout: got %v, want %v", cfg.Security.MaxCommandTimeout, 120*time.Second)
	}
}

func TestLoadFromFile(t *testing.T) {
	content := `
[agent]
id = "test-from-file"
log_level = "debug"
log_output = "stderr"
log_file = "/tmp/test-mitiga.log"

[security]
auto_remediate = false
max_command_timeout = "30s"

[scan]
default_port_range = "1-1024"
scan_timeout = "60s"
max_concurrent_scans = 2

[runtime]
scan_interval = "45s"
event_poll_interval = "10s"
heartbeat_interval = "90s"

[report]
output_dir = "/tmp/mitiga-reports"
format = "markdown"
retention_days = 30
`

	tmpFile, err := os.CreateTemp(t.TempDir(), "mitiga-*.toml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmpFile.WriteString(content); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	cfg := Default()
	if err := LoadFromFile(tmpFile.Name(), &cfg); err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}

	if cfg.Agent.ID != "test-from-file" {
		t.Errorf("agent id: got %q, want %q", cfg.Agent.ID, "test-from-file")
	}
	if cfg.Agent.LogLevel != "debug" {
		t.Errorf("log level: got %q, want %q", cfg.Agent.LogLevel, "debug")
	}
	if cfg.Runtime.ScanInterval != 45*time.Second {
		t.Errorf("runtime scan interval: got %v, want %v", cfg.Runtime.ScanInterval, 45*time.Second)
	}
	if cfg.Scan.DefaultPortRange != "1-1024" {
		t.Errorf("port range: got %q, want %q", cfg.Scan.DefaultPortRange, "1-1024")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	// Load with a non-existent file should fall back to defaults.
	cfg, err := Load("/nonexistent/path/mitiga.toml")
	if err != nil {
		t.Fatalf("Load with missing file should not error: %v", err)
	}

	if cfg.Agent.LogLevel != "info" {
		t.Errorf("should use default log level: got %q", cfg.Agent.LogLevel)
	}
}

func TestLoad_EmptyPath(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load with empty path should not error: %v", err)
	}

	if cfg.Runtime.HeartbeatInterval <= 0 {
		t.Error("should use default runtime heartbeat interval")
	}
}
