# ufw — Uncomplicated Firewall

## Category
System Hardening

## License
GPLv3

## Source
https://code.launchpad.net/ufw (included in Ubuntu/Debian)

## Purpose
Simplified interface for managing iptables/nftables rules.

## Use Cases
- Quick firewall status checks
- Rule modifications on systems using ufw
- Block malicious sources during incident response

## Examples
```bash
# Show firewall status and rules
ufw status verbose

# Block a malicious IP
ufw deny from <malicious_ip>

# Allow a specific port
ufw allow 27027/tcp

# Show numbered rules
ufw status numbered
```

## Safety Notes
- **Status queries are read-only and safe.**
- **Rule modifications require verification before and after.**
- Available primarily on Ubuntu/Debian systems.
