# lsof — List Open Files

## Category
Process Management

## License
Custom permissive

## Source
https://github.com/lsof-org/lsof

## Purpose
List open files, sockets, pipes, and network connections per process.

## Use Cases
- Identify which process owns a network connection
- Find processes with open handles on sensitive files
- Detect hidden network activity
- Audit open sockets on specific ports
- Investigate file descriptor leaks

## Examples
```bash
# List all network connections with process info
lsof -i -P -n

# Show processes using a specific port
lsof -i :27027

# Files opened by root under /etc
lsof -u root +D /etc

# Network connections for a specific process
lsof -i -a -p <pid>

# Show all listening sockets
lsof -i -P -n | grep LISTEN
```

## Safety Notes
- Read-only operation — does not modify files or processes.
- May require root privileges for full visibility.
