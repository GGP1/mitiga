# clamav — Antivirus Engine

## Category
Malware & Rootkit Detection

## License
GPLv2

## Source
https://github.com/Cisco-Talos/clamav (Cisco Talos)

## Purpose
Open-source antivirus engine for detecting trojans, viruses, malware, and other malicious payloads.

## Use Cases
- Scan files and directories for known malware signatures
- Verify downloaded artifacts for malicious content
- Periodic malware sweeps of critical directories
- Incident response file analysis

## Examples
```bash
# Recursive scan with infected-only output
clamscan --recursive --infected --log=clamscan.log /path/to/scan

# Scan a specific file
clamscan /path/to/suspicious_file

# Scan with no file size limit
clamscan --recursive --infected --max-filesize=0 --max-scansize=0 /path/to/scan
```

## Safety Notes
- Read-only scanning — does not modify or delete files by default.
- Signature database updates (`freshclam`) require system manager approval as they involve network access.
- Do not use `--remove` flag without explicit system manager approval.
