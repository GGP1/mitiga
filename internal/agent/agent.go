package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/GGP1/mitiga/internal/audit"
	"github.com/GGP1/mitiga/internal/config"
	"github.com/GGP1/mitiga/internal/event"
	"github.com/GGP1/mitiga/internal/executor"
	"github.com/GGP1/mitiga/internal/hardener"
	"github.com/GGP1/mitiga/internal/llm"
	"github.com/GGP1/mitiga/internal/logaudit"
	"github.com/GGP1/mitiga/internal/logger"
	"github.com/GGP1/mitiga/internal/process"
	"github.com/GGP1/mitiga/internal/report"
	"github.com/GGP1/mitiga/internal/scanner"
	"github.com/GGP1/mitiga/internal/skills"
	"github.com/GGP1/mitiga/internal/state"
	"github.com/GGP1/mitiga/internal/system"
	"github.com/GGP1/mitiga/internal/verify"
	"github.com/GGP1/mitiga/pkg/protocol"
)

// Agent is the core Mitiga security agent. It manages the lifecycle
// (INIT → MONITOR → SHUTDOWN) and orchestrates all security modules per §11.
//
// Flow:
//  1. Time and filesystem changes produce Events.
//  2. Producer goroutines enqueue Events into the bounded event.Queue.
//  3. A single consumer loop dequeues Events and dispatches each to the
//     appropriate handler.
//  4. After every processing cycle the agent snapshot is persisted via
//     state.Store so state survives restarts.
type Agent struct {
	cfg      config.Config
	executor *executor.Executor
	state    protocol.AgentState

	// Security modules
	scanner   *scanner.Scanner
	procMon   *process.Monitor
	sysAudit  *system.Auditor
	verifier  *verify.Verifier
	logAudit  *logaudit.Analyzer
	codeAudit *audit.Auditor
	hardener  *hardener.Assessor
	llmClient *llm.Client

	// Event-driven infrastructure
	queue      *event.Queue
	stateStore *state.Store

	lastCodeAuditRun   time.Time
	lastHardenerRun    time.Time
	lastPersistenceRun time.Time
	lastSUIDRun        time.Time
	llmInsights        []string
	pathState          map[string]time.Time

	mu       sync.RWMutex
	findings []protocol.Finding
}

// New creates a new Agent with the given configuration.
func New(cfg config.Config) *Agent {
	exec := executor.New(cfg.Security.MaxCommandTimeout)
	rootDir, err := os.Getwd()
	if err != nil {
		rootDir = "."
	}
	rootDir, _ = filepath.Abs(rootDir)

	a := &Agent{
		cfg:         cfg,
		executor:    exec,
		state:       protocol.StateInit,
		scanner:     scanner.New(exec),
		procMon:     process.New(exec),
		sysAudit:    system.New(exec),
		verifier:    verify.New(),
		logAudit:    logaudit.New(exec),
		codeAudit:   audit.New(exec, rootDir),
		hardener:    hardener.New(exec),
		llmClient:   llm.New(cfg.LLM),
		queue:       event.NewQueue(cfg.Runtime.EventQueueSize),
		stateStore:  state.NewStore(cfg.Runtime.StateFile),
		llmInsights: make([]string, 0),
		pathState:   make(map[string]time.Time),
		findings:    make([]protocol.Finding, 0),
	}

	// Create per-task sub-agents and attach them to the corresponding security
	// modules. All finding sub-agents share cfg.LLM.FindingsModel; the advisory
	// sub-agent uses cfg.LLM.AdvisoryModel.
	//
	// Each sub-agent's prompt is enriched with the relevant skill documentation
	// so the LLM understands the tools, their output formats, and safety notes.
	reg, err := skills.NewRegistry()
	if err != nil {
		// Skills are non-critical — log and continue without enrichment.
		logger.Warn(context.Background(), "failed to load skills registry", "error", err.Error())
	}

	skillCtx := func(tools ...string) llm.SubAgentOption {
		if reg == nil {
			return func(*llm.SubAgent) {} // no-op
		}
		return llm.WithSkillContext(reg.FormatForPrompt(tools...))
	}

	a.scanner.SetSubAgent(llm.NewSubAgent(cfg.LLM, llm.TaskScanner, llm.PromptScanner, skillCtx("ss", "nmap", "ip", "lsof")))
	a.procMon.SetSubAgent(llm.NewSubAgent(cfg.LLM, llm.TaskProcess, llm.PromptProcess, skillCtx("ps", "pgrep", "lsof", "top")))
	a.sysAudit.SetSubAgent(llm.NewSubAgent(cfg.LLM, llm.TaskSystem, llm.PromptSystem, skillCtx("getent", "id", "who", "chage", "passwd", "find", "stat")))
	a.hardener.SetSubAgent(llm.NewSubAgent(cfg.LLM, llm.TaskHardener, llm.PromptHardener, skillCtx("sysctl", "chmod", "chown", "iptables", "ufw", "systemctl", "apparmor", "selinux")))
	a.logAudit.SetSubAgent(llm.NewSubAgent(cfg.LLM, llm.TaskLogAudit, llm.PromptLogAudit, skillCtx("journalctl", "auditctl", "ausearch", "last")))
	a.codeAudit.SetSubAgent(llm.NewSubAgent(cfg.LLM, llm.TaskAudit, llm.PromptAudit, skillCtx("gosec", "gitleaks", "semgrep", "govulncheck", "grype", "trivy")))

	return a
}

// State returns the current agent lifecycle state.
func (a *Agent) State() protocol.AgentState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.state
}

// setState transitions the agent to a new state with logging.
func (a *Agent) setState(ctx context.Context, newState protocol.AgentState) {
	a.mu.Lock()
	oldState := a.state
	a.state = newState
	a.mu.Unlock()

	logger.Info(ctx, "agent state transition",
		"from", string(oldState),
		"to", string(newState),
	)
}

// Config returns the agent's configuration (read-only).
func (a *Agent) Config() config.Config {
	return a.cfg
}

// AddFinding records a new security finding.
func (a *Agent) AddFinding(f protocol.Finding) {
	a.mu.Lock()
	defer a.mu.Unlock()

	f.Timestamp = time.Now().UTC()
	a.findings = append(a.findings, f)
}

// Findings returns a copy of all recorded findings.
func (a *Agent) Findings() []protocol.Finding {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make([]protocol.Finding, len(a.findings))
	copy(result, a.findings)
	return result
}

// ClearFindings removes all recorded findings (e.g., after report generation).
func (a *Agent) ClearFindings() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.findings = a.findings[:0]
}

// Run starts the agent lifecycle. It blocks until the context is cancelled
// (typically by a signal handler) or a fatal error occurs.
//
// Lifecycle per §11:
//  1. INIT   — validate config, self-integrity check, restore persisted state
//  2. MONITOR — event producers enqueue events; single consumer dispatches them
//  3. SHUTDOWN — persist final state, generate shutdown report
func (a *Agent) Run(ctx context.Context) error {
	agentCtx := logger.WithComponent(ctx, "agent")

	// Phase 1: INIT
	if err := a.init(agentCtx); err != nil {
		return fmt.Errorf("agent init: %w", err)
	}

	// Phase 2: MONITOR & PROTECT
	if err := a.monitor(agentCtx); err != nil {
		// Context cancellation is normal shutdown, not an error.
		if ctx.Err() != nil {
			logger.Info(agentCtx, "agent stopping due to context cancellation")
		} else {
			return fmt.Errorf("agent monitor: %w", err)
		}
	}

	// Phase 3: SHUTDOWN
	a.shutdown(agentCtx)

	return nil
}

// init performs the INIT phase per §11.
func (a *Agent) init(ctx context.Context) error {
	a.setState(ctx, protocol.StateInit)

	logger.Info(ctx, "initializing agent",
		"agent_id", a.cfg.Agent.ID,
		"log_level", a.cfg.Agent.LogLevel,
	)

	if err := a.cfg.Validate(); err != nil {
		return fmt.Errorf("config validation: %w", err)
	}

	if expectedHash := os.Getenv("MITIGA_SELF_HASH"); expectedHash != "" {
		if err := a.verifier.SelfCheck(ctx, expectedHash); err != nil {
			return fmt.Errorf("self-integrity check: %w", err)
		}
	} else {
		logger.Warn(ctx, "self-integrity check skipped",
			"reason", "MITIGA_SELF_HASH not configured",
		)
	}

	logger.Info(ctx, "single-host mode active")

	// Restore persisted state from the previous run so findings and LLM
	// insights that were not yet reported survive restarts.
	snap, err := a.stateStore.Load(ctx, a.cfg.Agent.ID)
	if err != nil {
		return fmt.Errorf("load persisted state: %w", err)
	}
	if len(snap.Findings) > 0 {
		a.mu.Lock()
		a.findings = append(a.findings, snap.Findings...)
		a.mu.Unlock()
		logger.Info(ctx, "restored findings from prior state",
			"count", len(snap.Findings),
		)
	}
	if len(snap.LLMInsights) > 0 {
		a.mu.Lock()
		a.llmInsights = append(a.llmInsights, snap.LLMInsights...)
		a.mu.Unlock()
	}

	a.initializePathState(ctx)

	logger.Info(ctx, "agent initialization complete")
	return nil
}

// monitor runs the MONITOR & PROTECT main loop per §11.
//
// Three producer goroutines emit events into the bounded queue:
//   - Scan ticker   → EventTypeScheduledScan
//   - FS-poll ticker → EventTypeFilesystemChange (only when a watched path changes)
//   - Heartbeat ticker → EventTypeHeartbeat
//
// A single consumer loop dequeues and dispatches each event, then persists
// state to disk.  Single-consumer dispatch guarantees in-order processing
// without additional locking.
func (a *Agent) monitor(ctx context.Context) error {
	a.setState(ctx, protocol.StateMonitor)

	logger.Info(ctx, "entering monitor loop")

	scanTicker := time.NewTicker(a.cfg.Runtime.ScanInterval)
	fsPollTicker := time.NewTicker(a.cfg.Runtime.EventPollInterval)
	heartbeatTicker := time.NewTicker(a.cfg.Runtime.HeartbeatInterval)
	defer scanTicker.Stop()
	defer fsPollTicker.Stop()
	defer heartbeatTicker.Stop()

	// Enqueue the startup event so the first scan cycle runs immediately
	// without waiting for the first tick.
	a.queue.Enqueue(ctx, event.NewEvent(protocol.EventTypeStartup, "agent", nil))

	// Producer goroutines: each timer fires into the queue independently.
	// They exit when ctx is cancelled.
	var producers sync.WaitGroup

	producers.Add(1)
	go func() {
		defer producers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-scanTicker.C:
				a.queue.Enqueue(ctx, event.NewEvent(
					protocol.EventTypeScheduledScan, "timer:scan", nil,
				))
			}
		}
	}()

	producers.Add(1)
	go func() {
		defer producers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-fsPollTicker.C:
				changed, changedPaths := a.pollPathChanges(ctx)
				if changed {
					a.queue.Enqueue(ctx, event.NewEvent(
						protocol.EventTypeFilesystemChange,
						"fs:watch",
						map[string]string{"paths": changedPaths},
					))
				}
			}
		}
	}()

	producers.Add(1)
	go func() {
		defer producers.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case <-heartbeatTicker.C:
				a.queue.Enqueue(ctx, event.NewEvent(
					protocol.EventTypeHeartbeat, "timer:heartbeat", nil,
				))
			}
		}
	}()

	// Consumer: process events one at a time in arrival order.
	for {
		select {
		case <-ctx.Done():
			producers.Wait()
			return ctx.Err()
		case ev := <-a.queue.Chan():
			a.dispatchEvent(ctx, ev)
		}
	}
}

// dispatchEvent routes a single event to the appropriate handler and
// persists agent state afterwards.
func (a *Agent) dispatchEvent(ctx context.Context, ev protocol.Event) {
	logger.Debug(ctx, "dispatching event",
		"event_id", ev.ID,
		"event_type", string(ev.Type),
		"source", ev.Source,
	)

	switch ev.Type {
	case protocol.EventTypeStartup,
		protocol.EventTypeScheduledScan,
		protocol.EventTypeFilesystemChange:
		a.runScanCycle(ctx)
	case protocol.EventTypeHeartbeat:
		a.emitHeartbeat(ctx)
	default:
		logger.Warn(ctx, "unknown event type, ignoring",
			"event_type", string(ev.Type),
		)
	}

	a.persistState(ctx)
}

// persistState snapshots the current in-memory findings and LLM insights to
// disk so they survive a crash or restart.
func (a *Agent) persistState(ctx context.Context) {
	a.mu.RLock()
	findings := make([]protocol.Finding, len(a.findings))
	copy(findings, a.findings)
	insights := make([]string, len(a.llmInsights))
	copy(insights, a.llmInsights)
	a.mu.RUnlock()

	snap := &state.Snapshot{
		AgentID:     a.cfg.Agent.ID,
		Findings:    findings,
		LLMInsights: insights,
		EventCounts: map[string]int64{},
	}

	if err := a.stateStore.Save(ctx, snap); err != nil {
		logger.Warn(ctx, "failed to persist state",
			"error", err.Error(),
		)
	}
}

// runScanCycle performs one iteration of all monitoring checks.
// Called exclusively from the single consumer goroutine so no additional
// locking is needed to prevent concurrent cycles.
func (a *Agent) runScanCycle(ctx context.Context) {
	logger.Debug(ctx, "starting scan cycle")

	checks := []func(context.Context){
		a.scanPorts,
		a.checkProcesses,
		a.auditUsers,
		a.checkLogAnomalies,
		a.checkCodeAudit,
		a.checkHardening,
		a.checkPersistence,
		a.checkPrivilegeEscalation,
		a.checkSuspiciousConnections,
		a.checkRootkitModules,
		a.checkSudoAudit,
	}

	var wg sync.WaitGroup
	for _, check := range checks {
		checkFunc := check
		wg.Add(1)
		go func() {
			defer wg.Done()
			checkFunc(ctx)
		}()
	}
	wg.Wait()

	// Report findings if any accumulated.
	findings := a.Findings()
	if len(findings) > 0 {
		a.runLLMAdvisory(ctx, findings)

		logger.Info(ctx, "scan cycle complete",
			"findings_count", len(findings),
		)
		a.generateReport(ctx, "scan")
	} else {
		logger.Debug(ctx, "scan cycle complete, no findings")
	}

}

// scanPorts runs port scanning checks.
func (a *Agent) scanPorts(ctx context.Context) {
	logger.Debug(ctx, "port scan check", "port_range", a.cfg.Scan.DefaultPortRange)

	// Use expected listeners from config if available; otherwise detect all.
	findings, err := a.scanner.FindUnexpectedListeners(ctx, nil)
	if err != nil {
		logger.Error(ctx, "port scan failed",
			"error", err.Error(),
		)
		return
	}

	for i := range findings {
		a.AddFinding(findings[i])
	}
}

// checkProcesses runs process monitoring checks.
func (a *Agent) checkProcesses(ctx context.Context) {
	logger.Debug(ctx, "process check")

	findings, err := a.procMon.DetectAnomalies(ctx)
	if err != nil {
		logger.Error(ctx, "process check failed",
			"error", err.Error(),
		)
		return
	}

	for i := range findings {
		a.AddFinding(findings[i])
	}
}

// auditUsers runs user and group auditing checks.
func (a *Agent) auditUsers(ctx context.Context) {
	logger.Debug(ctx, "user audit check")

	findings, err := a.sysAudit.AuditUsers(ctx)
	if err != nil {
		logger.Error(ctx, "user audit failed",
			"error", err.Error(),
		)
		return
	}

	for i := range findings {
		a.AddFinding(findings[i])
	}

	// Also check critical file permissions.
	permFindings, err := a.sysAudit.CheckFilePermissions(ctx)
	if err != nil {
		logger.Error(ctx, "file permission check failed",
			"error", err.Error(),
		)
		return
	}

	for i := range permFindings {
		a.AddFinding(permFindings[i])
	}
}

// checkLogAnomalies runs log analysis checks.
func (a *Agent) checkLogAnomalies(ctx context.Context) {
	logger.Debug(ctx, "log anomaly check")

	findings, err := a.logAudit.AnalyzeAuthFailures(ctx, 15*time.Minute)
	if err != nil {
		logger.Error(ctx, "log anomaly analysis failed",
			"error", err.Error(),
		)
		return
	}

	for i := range findings {
		a.AddFinding(findings[i])
	}
}

func (a *Agent) checkCodeAudit(ctx context.Context) {
	now := time.Now().UTC()
	a.mu.RLock()
	lastRun := a.lastCodeAuditRun
	a.mu.RUnlock()

	if !lastRun.IsZero() && now.Sub(lastRun) < 30*time.Minute {
		return
	}

	findings, err := a.codeAudit.ScanForSecrets(ctx)
	if err != nil {
		logger.Error(ctx, "code audit failed",
			"error", err.Error(),
		)
		return
	}

	for i := range findings {
		a.AddFinding(findings[i])
	}

	a.mu.Lock()
	a.lastCodeAuditRun = now
	a.mu.Unlock()
}

func (a *Agent) checkHardening(ctx context.Context) {
	now := time.Now().UTC()
	a.mu.RLock()
	lastRun := a.lastHardenerRun
	a.mu.RUnlock()

	if !lastRun.IsZero() && now.Sub(lastRun) < 30*time.Minute {
		return
	}

	findings, err := a.hardener.AssessBaseline(ctx)
	if err != nil {
		logger.Error(ctx, "hardening baseline check failed",
			"error", err.Error(),
		)
		return
	}

	for i := range findings {
		a.AddFinding(findings[i])
	}

	a.mu.Lock()
	a.lastHardenerRun = now
	a.mu.Unlock()
}

// checkPersistence runs persistence-vector checks (authorized_keys, sudoers,
// cron).  Rate-limited to once every 30 minutes as these are expensive I/O
// walks that rarely change between cycles.
func (a *Agent) checkPersistence(ctx context.Context) {
	now := time.Now().UTC()
	a.mu.RLock()
	lastRun := a.lastPersistenceRun
	a.mu.RUnlock()

	if !lastRun.IsZero() && now.Sub(lastRun) < 30*time.Minute {
		return
	}

	typeChecks := []struct {
		name string
		fn   func(context.Context) ([]protocol.Finding, error)
	}{
		{"authorized_keys", a.sysAudit.CheckAuthorizedKeys},
		{"sudoers", a.hardener.CheckSudoers},
		{"cron_jobs", a.hardener.CheckCronJobs},
	}

	for _, tc := range typeChecks {
		findings, err := tc.fn(ctx)
		if err != nil {
			logger.Error(ctx, tc.name+" check failed", "error", err.Error())
			continue
		}
		for i := range findings {
			a.AddFinding(findings[i])
		}
	}

	a.mu.Lock()
	a.lastPersistenceRun = now
	a.mu.Unlock()
}

// checkPrivilegeEscalation scans for SUID/SGID binaries outside the known-good
// baseline.  Rate-limited to once every 30 minutes due to filesystem walk cost.
func (a *Agent) checkPrivilegeEscalation(ctx context.Context) {
	now := time.Now().UTC()
	a.mu.RLock()
	lastRun := a.lastSUIDRun
	a.mu.RUnlock()

	if !lastRun.IsZero() && now.Sub(lastRun) < 30*time.Minute {
		return
	}

	findings, err := a.sysAudit.CheckSUIDFiles(ctx)
	if err != nil {
		logger.Error(ctx, "SUID/SGID check failed", "error", err.Error())
		return
	}
	for i := range findings {
		a.AddFinding(findings[i])
	}

	a.mu.Lock()
	a.lastSUIDRun = now
	a.mu.Unlock()
}

// checkSuspiciousConnections examines ESTABLISHED TCP connections for outbound
// activity on C2 or backdoor ports.  Runs every scan cycle.
func (a *Agent) checkSuspiciousConnections(ctx context.Context) {
	findings, err := a.scanner.FindSuspiciousConnections(ctx)
	if err != nil {
		logger.Error(ctx, "suspicious connections check failed", "error", err.Error())
		return
	}
	for i := range findings {
		a.AddFinding(findings[i])
	}
}

// checkRootkitModules reads /proc/modules and flags known LKM rootkit names.
// Runs every scan cycle.
func (a *Agent) checkRootkitModules(ctx context.Context) {
	findings, err := a.procMon.DetectRootkitModules(ctx)
	if err != nil {
		logger.Error(ctx, "rootkit module detection failed", "error", err.Error())
		return
	}
	for i := range findings {
		a.AddFinding(findings[i])
	}
}

// checkSudoAudit parses the last 10 minutes of sudo journal entries and flags
// unauthorized sudo attempts.  Runs every scan cycle with a 10-minute window.
func (a *Agent) checkSudoAudit(ctx context.Context) {
	findings, err := a.logAudit.AuditSudoUsage(ctx, 10*time.Minute)
	if err != nil {
		logger.Error(ctx, "sudo audit failed", "error", err.Error())
		return
	}
	for i := range findings {
		a.AddFinding(findings[i])
	}
}

// shutdown performs the SHUTDOWN phase per §11.
func (a *Agent) shutdown(ctx context.Context) {
	a.setState(ctx, protocol.StateShutdown)

	logger.Info(ctx, "agent shutting down")

	// Persist state one final time before generating the report so that
	// findings are durable even if report writing fails.
	a.persistState(ctx)

	// Generate final status report with all accumulated findings.
	a.generateReport(ctx, "shutdown")

	logger.Info(ctx, "agent shutdown complete")
}

// generateReport creates and writes a report with current findings.
func (a *Agent) generateReport(ctx context.Context, reportType string) {
	hostname, _ := os.Hostname()

	rpt := report.New(
		fmt.Sprintf("%s-%d", reportType, time.Now().Unix()),
		a.cfg.Agent.ID,
		hostname,
		reportType,
	)

	findings := a.Findings()
	rpt.AddFindings(findings)

	a.mu.RLock()
	insights := make([]string, len(a.llmInsights))
	copy(insights, a.llmInsights)
	a.mu.RUnlock()
	rpt.AddLLMInsights(insights)

	rpt.GenerateSummary()

	// Write in the configured format.
	switch a.cfg.Report.Format {
	case "json":
		path, err := rpt.WriteJSON(ctx, a.cfg.Report.OutputDir)
		if err != nil {
			logger.Error(ctx, "failed to write JSON report",
				"error", err.Error(),
			)
			return
		}
		logger.Info(ctx, "report generated",
			"format", "json",
			"path", path,
			"findings", len(findings),
		)
	case "markdown":
		path, err := rpt.WriteMarkdown(ctx, a.cfg.Report.OutputDir)
		if err != nil {
			logger.Error(ctx, "failed to write Markdown report",
				"error", err.Error(),
			)
			return
		}
		logger.Info(ctx, "report generated",
			"format", "markdown",
			"path", path,
			"findings", len(findings),
		)
	default:
		// JSON is the primary format per §10.2.
		path, err := rpt.WriteJSON(ctx, a.cfg.Report.OutputDir)
		if err != nil {
			logger.Error(ctx, "failed to write report",
				"error", err.Error(),
			)
			return
		}
		logger.Info(ctx, "report generated",
			"format", "json",
			"path", path,
			"findings", len(findings),
		)
	}

	// Clear findings after successful report generation.
	a.ClearFindings()
	a.mu.Lock()
	a.llmInsights = a.llmInsights[:0]
	a.mu.Unlock()
}

func (a *Agent) runLLMAdvisory(ctx context.Context, findings []protocol.Finding) {
	analysis, err := a.llmClient.AnalyzeFindings(ctx, a.cfg.Agent.ID, findings)
	if err != nil {
		logger.Warn(ctx, "llm advisory analysis failed",
			"error", err.Error(),
		)
		return
	}
	if analysis == nil {
		return
	}

	insights := make([]string, 0, len(analysis.Recommendations)+1)
	if analysis.Summary != "" {
		insights = append(insights, analysis.Summary)
	}
	for _, recommendation := range analysis.Recommendations {
		line := recommendation.Title
		if recommendation.Rationale != "" {
			line = line + ": " + recommendation.Rationale
		}
		insights = append(insights, line)
	}

	a.mu.Lock()
	a.llmInsights = append(a.llmInsights, insights...)
	a.mu.Unlock()
}

func (a *Agent) emitHeartbeat(ctx context.Context) {
	logger.Info(ctx, "daemon heartbeat",
		"state", string(a.State()),
		"watch_paths", len(a.cfg.Runtime.WatchPaths),
	)
}

func (a *Agent) initializePathState(ctx context.Context) {
	for _, path := range a.cfg.Runtime.WatchPaths {
		info, err := os.Stat(path)
		if err != nil {
			logger.Warn(ctx, "watch path unavailable",
				"path", path,
				"error", err.Error(),
			)
			continue
		}
		a.pathState[path] = info.ModTime().UTC()
	}
}

// pollPathChanges checks each watched path for metadata changes since the
// last poll.  It returns whether any path changed and a comma-separated
// string of the changed paths for inclusion in the event payload.
func (a *Agent) pollPathChanges(ctx context.Context) (changed bool, paths string) {
	for _, path := range a.cfg.Runtime.WatchPaths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		mod := info.ModTime().UTC()
		last, ok := a.pathState[path]
		if !ok {
			a.pathState[path] = mod
			continue
		}

		if mod.After(last) {
			a.pathState[path] = mod
			logger.Info(ctx, "watch path changed",
				"path", path,
				"previous", last,
				"current", mod,
			)
			changed = true
			if paths == "" {
				paths = path
			} else {
				paths += "," + path
			}
		}
	}
	return changed, paths
}
