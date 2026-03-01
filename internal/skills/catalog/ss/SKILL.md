# ss — Socket Statistics

## Category
Network Reconnaissance

## License
GPLv2 (iproute2)

## Source
https://github.com/iproute2/iproute2 (included in Linux)

## Purpose
Display local socket information — listening ports, established connections, socket states.

## Use Cases
- Audit which processes are listening on which ports
- Detect unauthorized listeners
- Verify expected services are running on correct ports
- Check established connections for suspicious destinations

## Examples
```bash
# List all listening TCP/UDP sockets with process info
ss -tulnp

# Show established connections
ss -tnp state established

# Show sockets listening on a specific port
ss -tlnp sport = :27027

# Show all sockets with timer information
ss -to
```

## Safety Notes
- Read-only operation — safe to run at any time.
- The `-p` flag requires appropriate permissions to show process info.
