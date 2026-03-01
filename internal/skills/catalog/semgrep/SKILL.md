# semgrep — Static Analysis Engine

## Category
Code Auditing

## License
LGPL 2.1

## Source
https://github.com/semgrep/semgrep

## Purpose
Pattern-based static analysis across many languages. Supports custom rules for detecting insecure patterns, logic bugs, and anti-patterns.

## Use Cases
- Detect hardcoded credentials in source code
- Find insecure cryptographic usage
- Identify command injection patterns
- Detect missing input validation
- Enforce coding standards with custom rules
- OWASP Top 10 vulnerability detection

## Examples
```bash
# Auto-detect language and run default rules
semgrep scan --config=auto --json --output=results.json /path/to/code

# Run OWASP Top 10 rules
semgrep scan --config=p/owasp-top-ten /path/to/code

# Run Go-specific security rules
semgrep scan --config=p/golang --json /path/to/code

# Run with custom rules file
semgrep scan --config=rules.yaml /path/to/code
```

## Safety Notes
- Read-only analysis — does not modify source code.
- Custom rules should be reviewed before use to avoid false negatives.
