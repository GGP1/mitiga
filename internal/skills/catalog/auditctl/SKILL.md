# auditctl — Linux Audit Rule Management

## Category
Log Analysis

## License
GPLv2 (audit)

## Source
https://github.com/linux-audit/audit-userspace (Linux Audit Framework)

## Purpose
Configure the Linux Audit Framework rules at runtime. Companion to `ausearch`/`aureport` — `auditctl` defines *what* to audit, while `ausearch` queries the results.

## Use Cases
- Add audit rules to monitor access to sensitive files (shadow, passwd, SSH keys)
- Watch for privilege escalation syscalls (execve, setuid, setgid)
- Monitor modifications to critical configuration directories
- List current audit rules to verify coverage
- Temporarily add rules during active incident investigation

## Examples
```bash
# List all current audit rules
auditctl -l

# Watch for modifications to /etc/passwd
auditctl -w /etc/passwd -p wa -k passwd_changes

# Watch for modifications to SSH configuration
auditctl -w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor execve syscalls (process execution)
auditctl -a always,exit -F arch=b64 -S execve -k exec_monitor

# Watch for changes to the audit configuration itself
auditctl -w /etc/audit/ -p wa -k audit_config

# Monitor privilege escalation attempts
auditctl -a always,exit -F arch=b64 -S setuid -S setgid -k privesc

# Check audit system status
auditctl -s
```

## Safety Notes
- **Adding audit rules increases system overhead.** Each rule adds processing to every matching syscall. Avoid overly broad rules (e.g., auditing all syscalls on all files).
- **Rules added with `auditctl` are not persistent across reboots** — they must be written to `/etc/audit/rules.d/` for persistence. Use `auditctl` for runtime/investigation rules only.
- **Deleting audit rules during an active investigation is strongly discouraged.** This could destroy evidence.
- Always list existing rules (`auditctl -l`) before adding new ones to avoid duplicates.
- Requires root or `CAP_AUDIT_CONTROL` capability.
- The agent should prefer **adding** rules over **deleting** them. Rule deletion requires system manager approval.
