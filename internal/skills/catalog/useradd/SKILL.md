# useradd / usermod / userdel — User Account Management

## Category
User & Group Management

## License
BSD-3-Clause (shadow-utils)

## Source
https://github.com/shadow-maint/shadow (included in all Linux distributions)

## Purpose
Create, modify, and delete user accounts.

## Use Cases
- Create service accounts for Mitiga components
- Modify user group memberships
- Disable or remove compromised accounts
- Audit account configurations

## Examples
```bash
# Create a system service account (no login, no home)
useradd --system --shell /usr/sbin/nologin --no-create-home svc_mitiga

# Add a user to a group
usermod -aG mitiga_agents username

# Lock a user account
usermod -L username

# Set account expiration
usermod -e 2026-03-01 username
```

## Safety Notes
- **All operations require explicit system manager approval.** These commands are never executed autonomously.
- Always verify current account state before modifications.
- Record the previous state in logs before any changes.
