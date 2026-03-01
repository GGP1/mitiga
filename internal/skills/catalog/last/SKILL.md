# last / lastb / lastlog — Login History

## Category
Log Analysis

## License
GPLv2 (util-linux / shadow-utils)

## Source
Included in all Linux distributions.

## Purpose
Display login history (`last`), failed login attempts (`lastb`), and per-user last login times (`lastlog`).

## Use Cases
- Detect unauthorized logins
- Identify brute-force patterns via failed attempts
- Find accounts that have never logged in
- Review login sources and timestamps
- Detect logins from unusual IP addresses or terminals

## Examples
```bash
# Recent login history with full timestamps
last -n 50 -F

# Failed login attempts (requires root)
lastb -n 50 -F

# Per-user last login times
lastlog

# Logins for a specific user
last -n 20 username

# Currently logged-in users
last -w | head -5
```

## Safety Notes
- Read-only operations — do not modify login records.
- `lastb` requires root or appropriate permissions to access `/var/log/btmp`.
