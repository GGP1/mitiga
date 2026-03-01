# chmod — File Permission Management

## Category
System Hardening

## License
GPLv3+ (GNU coreutils)

## Source
https://github.com/coreutils/coreutils (included in all Linux distributions)

## Purpose
Modify file and directory permissions. For ownership changes, see [chown](../chown/SKILL.md).

## Use Cases
- Restrict permissions on sensitive configuration files
- Fix overly permissive file permissions
- Set correct ownership on system files
- Harden file access controls

## Examples
```bash
# Restrict SSH config permissions
chmod 600 /etc/ssh/sshd_config

# Set correct ownership on shadow file
chown root:root /etc/shadow

# Remove world-readable from a config file
chmod o-r /etc/sensitive.conf

# Set directory permissions
chmod 750 /etc/mitiga/
```

## Safety Notes
- **These commands modify the filesystem — always verify before and after.**
- Record the previous permissions in logs before any changes.
- Incorrect permissions can break services or lock out users.
- Test in a non-destructive way when possible (e.g., verify with `stat` first).
