# pgrep / pkill — Process Grep and Signal

## Category
Process Management

## License
GPLv2 (procps-ng)

## Source
https://gitlab.com/procps-ng/procps (included in all Linux distributions)

## Purpose
Search for processes by name, user, or other attributes. Signal matching processes.

## Use Cases
- Detect running instances of known-malicious binaries
- Locate processes by owner or name pattern
- Targeted process termination during incident response
- Count instances of a service

## Examples
```bash
# List processes owned by nobody
pgrep -la -u nobody

# Search for cryptominer-like processes
pgrep -af "crypto|miner"

# Count instances of a process
pgrep -c sshd

# List all processes matching a pattern with full details
pgrep -af "suspicious_pattern"
```

## Safety Notes
- `pgrep` is read-only and safe.
- `pkill` **terminates processes** — requires system manager approval for any use except responding to CRITICAL threats per §4.3.
- Always verify the target processes with `pgrep` before using `pkill`.
