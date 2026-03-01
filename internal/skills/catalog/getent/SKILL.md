# getent — Name Service Lookup

## Category
User & Group Management

## License
LGPLv2.1+ (glibc)

## Source
Included in all Linux distributions (part of glibc).

## Purpose
Query NSS databases — passwd, group, shadow, hosts, services.

## Use Cases
- Enumerate all system users and groups (including LDAP/NIS)
- Verify account existence
- Audit group memberships
- Resolve hostnames and service names

## Examples
```bash
# List all system users
getent passwd

# List all system groups
getent group

# Check sudo/wheel group membership
getent group sudo
getent group wheel

# Look up a specific user
getent passwd username

# List all services
getent services
```

## Safety Notes
- Read-only operation — safe to run at any time.
- Returns data from all configured NSS sources (local files, LDAP, NIS, etc.).
