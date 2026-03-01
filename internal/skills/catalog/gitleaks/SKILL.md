# gitleaks — Secret Detection

## Category
Code Auditing

## License
MIT

## Source
https://github.com/gitleaks/gitleaks

## Purpose
Detect hardcoded secrets (API keys, passwords, tokens, private keys) in Git repositories and files.

## Use Cases
- Scan source code for committed secrets
- Audit Git history for leaked credentials
- Pre-commit secret detection enforcement
- Scan arbitrary directories for secret patterns

## Examples
```bash
# Detect secrets in a repository
gitleaks detect --source=/path/to/repo --report-format=json --report-path=leaks.json

# Scan Git history
gitleaks detect --source=/path/to/repo --log-opts="--all" --report-format=json --report-path=leaks.json

# Scan files without Git (no-git mode)
gitleaks detect --no-git --source=/path/to/dir --report-format=json --report-path=leaks.json
```

## Safety Notes
- Read-only analysis — does not modify files or Git history.
- Report files may contain secret locations — treat reports as sensitive data.
