# rkhunter — Rootkit Hunter

## Category
Malware & Rootkit Detection

## License
GPLv2

## Source
https://github.com/installation/rkhunter

## Purpose
Scan for rootkits, backdoors, and local exploits by comparing file hashes, checking for hidden files, and inspecting system configuration.

## Use Cases
- Complementary rootkit detection alongside `chkrootkit`
- Scan for backdoors and local exploits
- File hash comparison against known-good baselines
- Hidden file and directory detection

## Examples
```bash
# Full check with warnings-only output
rkhunter --check --skip-keypress --report-warnings-only --logfile /var/log/rkhunter.log

# Update file properties database (after confirmed-clean state)
rkhunter --propupd

# Check with verbose output
rkhunter --check --skip-keypress --logfile /var/log/rkhunter.log
```

## Safety Notes
- Read-only detection — does not modify the system.
- Database updates (`--update`) require system manager approval as they involve network access.
- Should be run as root for comprehensive checks.
