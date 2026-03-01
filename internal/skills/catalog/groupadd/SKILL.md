# groupadd / groupmod / groupdel — Group Account Management

## Category
User & Group Management

## License
BSD-3-Clause (shadow-utils)

## Source
https://github.com/shadow-maint/shadow (included in all Linux distributions)

## Purpose
Create, modify, and delete groups. Companion to `useradd` — together they provide full user and group lifecycle management.

## Use Cases
- Create dedicated groups for Mitiga agent operations (e.g., `mitiga_agents`)
- Remove unauthorized or orphaned groups
- Modify group properties (name, GID)
- Audit group membership as part of access control reviews

## Examples
```bash
# Create a dedicated group for Mitiga agents
groupadd mitiga_agents

# Create a system group (low GID, no login)
groupadd --system mitiga_svc

# Rename a group
groupmod -n new_name old_name

# Delete an unauthorized group (after verifying no active members)
groupdel unauthorized_group

# List all groups (via getent)
getent group

# List members of a specific group
getent group mitiga_agents
```

## Safety Notes
- **All group operations require explicit system manager approval.** These commands are never executed autonomously.
- Always verify current group state with `getent group` before modifications.
- Deleting a group that owns files creates orphaned ownership — audit with `find / -gid <gid> -ls` before deletion.
- Record the previous state in logs before any changes.
- Modifying system groups (root, wheel, sudo, adm) is extremely high-risk and requires documented justification.
