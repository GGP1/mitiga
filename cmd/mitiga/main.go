// Mitiga is an autonomous security agent whose sole purpose is to keep the
// network and its systems secure and protected.
//
// Usage:
//
//	mitiga [flags]
//
// Flags:
//
//	-config string    Path to configuration file (default "config/mitiga.toml")
//	-log-level string Override log level (debug, info, warn, error)
//	-log-file string  Override log file path
//	-id string        Override agent ID
//	-version          Print version and exit
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/GGP1/mitiga/internal/agent"
	"github.com/GGP1/mitiga/internal/config"
	"github.com/GGP1/mitiga/internal/logger"
)

// Build-time variables set via -ldflags.
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	os.Exit(run())
}

func run() int {
	// --- CLI flags (highest precedence per §6) ---
	configPath := flag.String("config", "mitiga.toml", "Path to configuration file")
	logLevel := flag.String("log-level", "", "Override log level (debug, info, warn, error)")
	logFile := flag.String("log-file", "", "Override log file path")
	agentID := flag.String("id", "", "Override agent ID")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("mitiga %s (commit: %s, built: %s)\n", version, commit, buildTime)
		return 0
	}

	// --- Load configuration (layered model per §6) ---
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: load configuration: %v\n", err)
		return 1
	}

	// Apply CLI flag overrides (highest precedence).
	if *logLevel != "" {
		cfg.Agent.LogLevel = *logLevel
	}
	if *logFile != "" {
		cfg.Agent.LogFile = *logFile
	}
	if *agentID != "" {
		cfg.Agent.ID = *agentID
	}

	// Re-validate after CLI overrides.
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid configuration: %v\n", err)
		return 1
	}

	// --- Initialize logging (mandatory file + optional console per §7) ---
	cleanup, err := logger.Setup(cfg.Agent.LogFile, cfg.Agent.LogLevel, cfg.Agent.LogOutput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: initialize logging: %v\n", err)
		return 1
	}
	defer cleanup()

	ctx := logger.WithComponent(context.Background(), "main")

	logger.Info(ctx, "mitiga starting",
		"version", version,
		"commit", commit,
		"build_time", buildTime,
		"config_file", *configPath,
		"agent_id", cfg.Agent.ID,
	)

	// --- Context with signal handling (SIGTERM, SIGINT per §11) ---
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// --- Create and run the agent ---
	a := agent.New(cfg)

	if err := a.Run(ctx); err != nil {
		logger.Error(ctx, "agent exited with error",
			"error", err.Error(),
		)
		return 1
	}

	logger.Info(ctx, "mitiga shutdown complete")
	return 0
}
