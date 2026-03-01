# passwd — Password Management

## Category
User & Group Management

## License
BSD-3-Clause (shadow-utils)

## Source
https://github.com/shadow-maint/shadow (included in all Linux distributions)

## Purpose
Change user passwords, lock/unlock accounts, set password status.

## Use Cases
- Audit password status for accounts
- Lock compromised accounts during incident response
- Verify password policy enforcement

## Examples
```bash
# Check password status for a user
passwd -S username

# Lock a compromised account
passwd -l compromised_user

# Unlock an account
passwd -u username
```

## Safety Notes
- `passwd -S` is read-only and safe for auditing.
- **Any modifications (lock/unlock/change) require system manager approval.**
- Locking accounts may be performed autonomously only for CRITICAL threats per §4.3.
