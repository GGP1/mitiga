# id — User Identity

## Category
User & Group Management

## License
GPLv3+ (GNU coreutils)

## Source
https://github.com/coreutils/coreutils (included in all Linux distributions)

## Purpose
Display user and group IDs for a given user.

## Use Cases
- Verify user privileges and group memberships
- Audit service account configurations
- Check if a user has unexpected group access
- Confirm the agent's own running identity

## Examples
```bash
# Current user identity
id

# Specific user identity
id www-data

# Show only groups
id -Gn username

# Show numeric IDs
id -u username
```

## Safety Notes
- Read-only operation — safe to run at any time.
