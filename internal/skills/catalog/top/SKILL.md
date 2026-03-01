# top — Process Monitoring

## Category
Process Management

## License
GPLv2 (procps-ng)

## Source
https://gitlab.com/procps-ng/procps (included in all Linux distributions)

## Purpose
Real-time process activity monitoring — CPU, memory, I/O usage.

## Use Cases
- Detect resource-abusing processes (cryptominers, DoS tools)
- Monitor system load during security scans
- Identify processes with abnormal CPU or memory consumption
- Snapshot system resource state for reports

## Examples
```bash
# Batch mode snapshot sorted by CPU
top -b -n 1 -o %CPU | head -30

# Batch mode sorted by memory
top -b -n 1 -o %MEM | head -30

# Monitor specific user's processes
top -b -n 1 -u www-data
```

## Safety Notes
- Read-only monitoring — does not modify processes.
- Always use `-b` (batch mode) and `-n 1` in automated contexts to avoid interactive mode.
