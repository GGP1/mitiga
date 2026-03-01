# who / w — Logged-in Users

## Category
User & Group Management

## License
GPLv3+ (GNU coreutils) / GPLv2 (procps-ng)

## Source
Included in all Linux distributions.

## Purpose
Show who is currently logged in and what they are doing.

## Use Cases
- Detect unauthorized active sessions
- Monitor interactive logins in real-time
- Identify login sources (IP, terminal)
- Review idle times for active sessions

## Examples
```bash
# All login information
who -a

# Currently logged-in users with activity
w

# Simple user list
who

# Show dead processes (recently logged out)
who -d
```

## Safety Notes
- Read-only operation — safe to run at any time.
