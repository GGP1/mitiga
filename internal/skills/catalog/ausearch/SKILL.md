# ausearch / aureport — Linux Audit Tools

## Category
Log Analysis

## License
GPLv2 (audit)

## Source
https://github.com/linux-audit/audit-userspace (Linux Audit Framework)

## Purpose
Search and report on Linux Audit Framework events — file access, syscalls, authentication, authorization.

## Use Cases
- Investigate file access patterns on sensitive files
- Detect privilege escalation attempts
- Trace syscall activity for specific processes
- Generate authentication and authorization summaries
- Review failed operations across the system

## Examples
```bash
# Search recent authentication events
ausearch -m USER_AUTH --start recent -i

# Search for access to /etc/passwd today
ausearch -f /etc/passwd --start today -i

# Authentication summary report
aureport --auth --summary -i

# Failed operations summary
aureport --failed --summary

# Search by specific user
ausearch -ua username --start today -i

# Syscall events for a specific PID
ausearch -p <pid> -i
```

## Safety Notes
- Read-only query operations — do not modify audit logs.
- Requires the Linux Audit Framework to be active (`auditd`).
- Use `-i` flag for interpretable (human-readable) output.
