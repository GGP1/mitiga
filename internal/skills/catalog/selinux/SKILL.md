# SELinux — Security-Enhanced Linux

## Category
System Hardening

## License
GPLv2

## Source
https://github.com/SELinuxProject/selinux (included in RHEL/Fedora/CentOS)

## Purpose
Inspect SELinux mode and policy status.

## Tools
- `sestatus` — Show SELinux status and policy details
- `getenforce` — Show current enforcement mode

## Use Cases
- Verify SELinux is in enforcing mode
- Check for permissive domains that may indicate weakened security
- Audit SELinux policy configuration
- Detect if SELinux has been disabled

## Examples
```bash
# Full SELinux status
sestatus

# Current enforcement mode
getenforce

# List booleans (policy toggles)
getsebool -a
```

## Safety Notes
- **Status queries are read-only and safe.**
- **Mode changes (`setenforce`) and policy modifications require system manager approval.**
- Switching from Enforcing to Permissive weakens security — violates §2 NEVER rule #5.
