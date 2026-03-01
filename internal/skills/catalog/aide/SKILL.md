# aide — Advanced Intrusion Detection Environment

## Category
File Integrity & Verification

## License
GPLv2

## Source
https://github.com/aide/aide

## Purpose
File and directory integrity checker. Creates a baseline database of file attributes and detects unauthorized modifications.

## Use Cases
- Monitor critical system files for unauthorized changes
- Detect unauthorized binary replacements
- Track configuration drift over time
- Establish and verify file integrity baselines

## Examples
```bash
# Initialize the baseline database
aide --init

# Check current state against baseline
aide --check

# Update the baseline after verified changes
aide --update

# Compare two databases
aide --compare
```

## Safety Notes
- `--init` and `--check` are read-only operations.
- `--update` modifies the baseline database — only run after verified, authorized changes.
- Store the baseline database in a secure, tamper-evident location.
