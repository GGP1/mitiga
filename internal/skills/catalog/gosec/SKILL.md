# gosec — Go Security Checker

## Category
Code Auditing

## License
Apache 2.0

## Source
https://github.com/securego/gosec

## Purpose
Inspects Go source code for security problems by scanning the AST and SSA form. Go-specific rules for crypto, SQL injection, file permissions, command execution, etc.

## Use Cases
- Audit Go code for insecure `exec.Command` usage
- Detect weak cryptographic primitives
- Find unvalidated redirects and hardcoded credentials
- Identify file permission issues
- Check for SQL injection vulnerabilities

## Examples
```bash
# Scan all packages with JSON output
gosec -fmt=json -out=results.json ./...

# Scan with severity filter
gosec -severity=medium -fmt=json ./...

# Scan specific packages
gosec -fmt=json ./internal/scanner/... ./internal/process/...

# Exclude specific rules
gosec -exclude=G104 -fmt=json ./...
```

## Safety Notes
- Read-only analysis — does not modify source code.
- Go-specific: preferred over generic SAST tools for Go codebases.
