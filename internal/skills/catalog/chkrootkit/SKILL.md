# chkrootkit — Rootkit Checker

## Category
Malware & Rootkit Detection

## License
BSD-like

## Source
http://www.chkrootkit.org/

## Purpose
Check the local system for signs of rootkits — hidden processes, modified system binaries, suspicious kernel modules.

## Use Cases
- Periodic rootkit detection sweeps
- Incident response verification
- Detect hidden processes and modified binaries
- Identify suspicious kernel modules

## Examples
```bash
# Quick check, report warnings only
chkrootkit -q

# Full verbose check
chkrootkit

# Check specific tests
chkrootkit sniffer rootkit
```

## Safety Notes
- Read-only detection — does not modify the system.
- Should be run as root for comprehensive checks.
- Complement with `rkhunter` for defense-in-depth.
