# journalctl — Systemd Journal Reader

## Category
Log Analysis

## License
LGPLv2.1+ (systemd)

## Source
https://github.com/systemd/systemd (included in systemd-based distributions)

## Purpose
Query and display logs from the systemd journal.

## Use Cases
- Search for authentication failures
- Investigate service crashes and restarts
- Query kernel messages for security events
- Filter logs by time range, unit, and priority
- Export logs in JSON format for machine consumption

## Examples
```bash
# SSH authentication events in the last hour
journalctl -u sshd --since "1 hour ago" --no-pager -o json

# All errors since today
journalctl -p err --since today --no-pager

# Audit events in JSON format
journalctl _TRANSPORT=audit --no-pager -o json

# Kernel messages
journalctl -k --since "1 hour ago" --no-pager

# Follow logs in real-time (for monitoring)
journalctl -f -u sshd --no-pager
```

## Safety Notes
- Read-only operation — does not modify journal entries.
- Use `--no-pager` to avoid interactive mode in automated contexts.
- JSON output (`-o json`) is preferred for machine parsing.
