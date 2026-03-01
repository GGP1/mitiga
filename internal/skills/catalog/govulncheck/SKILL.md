# govulncheck — Go Vulnerability Checker

## Category
Vulnerability Scanning

## License
BSD-3-Clause

## Source
https://github.com/golang/vuln (official Go project)

## Purpose
Check Go source code and binaries against the Go vulnerability database. Only reports vulnerabilities in functions actually called by the code — minimizing false positives.

## Use Cases
- Audit Go module dependencies for known vulnerabilities
- Verify built binaries against the vulnerability database
- CI/CD gating for Go projects
- Targeted analysis of reachable vulnerable code paths

## Examples
```bash
# Scan Go source code
govulncheck ./...

# Scan a compiled binary
govulncheck -mode=binary ./mitiga

# JSON output for machine consumption
govulncheck -json ./...
```

## Safety Notes
- Read-only analysis — does not modify source code or binaries.
- Part of the official Go toolchain. Preferred scanner for Go-specific vulnerability detection.
