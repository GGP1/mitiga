# chown — File Ownership Management

## Category
System Hardening

## License
GPLv3+ (GNU coreutils)

## Source
https://github.com/coreutils/coreutils (included in all Linux distributions)

## Purpose
Change file and directory ownership (user and group). Companion to `chmod` — together they provide complete file access control.

## Use Cases
- Restore correct ownership on system files tampered by an attacker
- Set ownership on newly created configuration files
- Ensure sensitive files (shadow, SSH keys, TLS certs) are owned by the correct user/group
- Audit and remediate ownership drift from security baselines

## Examples
```bash
# Set correct ownership on shadow file
chown mitiga:shadow /etc/shadow

# Fix SSH directory ownership
chown -R mitiga:mitiga /etc/ssh/

# Set ownership on TLS certificates
chown mitiga:ssl-cert /etc/ssl/private/mitiga.key

# Verify current ownership before changing (use stat first)
stat -c '%U:%G %a %n' /etc/shadow
chown mitiga:shadow /etc/shadow

# Recursively fix ownership on a config directory
chown -R mitiga:mitiga /etc/mitiga/
```

## Safety Notes
- **All ownership changes require explicit system manager approval** unless correcting a known-bad state detected during hardening.
- **Always verify current ownership with `stat` before modifying.** Log the before-and-after state.
- Incorrect ownership can break services, prevent logins, or create privilege escalation vectors.
- Use `-R` (recursive) with extreme caution — verify the target path is correct.
- Never change ownership of running system binaries without a restart plan.
