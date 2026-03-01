# Mitiga

Mitiga is a multi-agents LLM security framework written in Go.

It runs on a Linux host, watches for threats, and reports what it finds. The design is deliberately conservative: it prefers detecting and reporting over automatic remediation, and any action that could disrupt a running service requires explicit approval from the system manager.

## What it does

On each scan cycle, Mitiga runs a fixed set of checks against the local system:

- **Port scanning** — enumerates network listeners, flags unexpected services and suspicious connections
- **Process monitoring** — inspects running processes for anomalies, suspicious execution patterns, and rootkit indicators
- **User and group auditing** — reviews user accounts, access controls, and privileged binaries
- **Log analysis** — examines system logs for authentication failures, brute-force attempts, and privilege escalation patterns
- **Hardening checks** — evaluates kernel parameters, access policies, and scheduled tasks against a security baseline
- **Code auditing** — scans source code for hardcoded secrets and insecure patterns
- **Binary verification** — validates checksums of files against known-good baselines

Findings are written to a structured report under the configured output directory after each scan. The agent also watches key system paths and triggers an incremental scan when files change.

## Requirements

- Linux
- Go 1.20+
- An LLM endpoint — either a locally running server (e.g. [Ollama](https://ollama.com)) or an external API (e.g. [OpenRouter](https://openrouter.ai)).

## Building

```bash
just build
```

This produces a statically linked, stripped binary at `./mitiga` with version information embedded from the current git tag. A SHA-256 checksum is written alongside the binary.

The binary has a single runtime dependency: nothing. CGO is disabled and all dependencies are compiled in.

## Configuration

Copy the sample config and edit it:

```bash
cp sample.mitiga.toml mitiga.toml
```

The configuration uses a layered model — values are resolved in this order, highest precedence first:

1. CLI flags
2. Environment variables prefixed with `MITIGA_`
3. The TOML config file
4. Hardcoded safe defaults

The most relevant sections:

```toml
[agent]
log_level = "info"
log_file  = "/var/log/mitiga/mitiga.log"

[runtime]
scan_interval   = "30s"
watch_paths     = ["/etc", "/usr/local/bin", "/var/lib/mitiga"]
state_file      = "/var/lib/mitiga/state.json"

[security]
auto_remediate           = false
require_manager_approval = true

[report]
output_dir     = "/var/lib/mitiga/reports"
format         = "json"   # json | markdown | html
retention_days = 90
```

The agent always writes to `log_file` regardless of `log_output`. The console output is supplementary; the file is the authoritative audit trail.

## Running

```bash
./mitiga -config mitiga.toml
```

The agent runs continuously until it receives `SIGTERM` or `SIGINT`, at which point it flushes logs and exits cleanly. Override individual settings without touching the config file:

```bash
./mitiga -config mitiga.toml -log-level debug -log-file /tmp/mitiga-debug.log
```

Print the build version:

```bash
./mitiga -version
```

## LLM-assisted analysis

Each security module sends its raw tool output to an LLM endpoint for interpretation via a task-specific sub-agent. The deterministic Go parsing logic runs as a fallback if the LLM is unavailable or returns no findings.

Both local inference servers and external API providers are supported:

```toml
# Local (e.g. Ollama)
[llm]
endpoint       = "http://127.0.0.1:11434/api/mitiga/analyze"
findings_model = "llama3:latest"
advisory_model = "llama3:latest"
timeout        = "10s"
advisory_only  = true

# External (e.g. OpenRouter)
[llm]
endpoint       = "https://openrouter.ai/api/v1/chat/completions"
api_key        = "sk-or-..."
findings_model = "anthropic/claude-4-haiku"
advisory_model = "anthropic/claude-4-6-sonnet"
timeout        = "30s"
advisory_only  = true
```

The `api_key` is sent as a `Authorization: Bearer` header and can also be set via the `MITIGA_LLM_API_KEY` environment variable to avoid storing credentials in the config file.

Before anything reaches the LLM:

1. Invisible Unicode characters and ANSI escape sequences are stripped.
2. Known prompt injection phrases are detected, redacted, and logged at WARN.
3. Sensitive values (IPs, credentials, email addresses, AWS key IDs, private key blocks, usernames) are replaced with stable tokens (`<IP_1>`, `<CRED_2>`, etc.) so the LLM never sees real data.
4. The payload is wrapped in explicit `<data>` tags, and a trust-boundary preamble is prepended to every system prompt to prevent the LLM from acting on injected instructions.

Tokens remain in findings for the lifetime of the LLM pipeline. They are only restored to real values when producing the final human-readable report.

After all scan modules finish, the advisory sub-agent receives the full set of findings for a holistic review. Its output ends up in the `llm_insights` field of the report.

## Reports

Each scan writes a report to `output_dir`. Reports contain a header with agent ID, hostname, and timestamp; an executive summary; findings ordered by severity (CRITICAL first), each with a description, evidence, impact, and a specific recommendation; any automated actions taken; and advisory insights from the LLM.

JSON is the primary format for machine consumption. Markdown and HTML are available for human review:

```toml
[report]
format = "markdown"
```

## Development

```bash
just test          # go test -race -count=1
just lint          # golangci-lint run
just vet           # go vet
just vulncheck     # govulncheck
just fmt           # gofmt + goimports
just fuzz          # Fuzz tests for all input-parsing functions
```

The project has a single external dependency (`github.com/BurntSushi/toml`). Keep it that way — every new dependency is an attack surface.
