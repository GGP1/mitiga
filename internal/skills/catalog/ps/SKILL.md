# ps — Process Status

## Category
Process Management

## License
GPLv2 (procps-ng)

## Source
https://gitlab.com/procps-ng/procps (included in all Linux distributions)

## Purpose
Snapshot of current processes with details on PID, user, CPU, memory, command line.

## Use Cases
- List all running processes for audit
- Detect processes running as root unexpectedly
- Find processes with suspicious parent relationships
- Identify high-resource-consuming processes
- Detect processes with unusual command-line arguments

## Examples
```bash
# Full process tree with user info
ps auxf

# Custom format sorted by CPU usage
ps -eo pid,ppid,user,args --sort=-pcpu

# Processes owned by a specific user
ps -u www-data -f

# All processes with full command lines
ps -eo pid,ppid,uid,user,%cpu,%mem,stat,start,args
```

## Safety Notes
- Read-only operation — safe to run at any time.
