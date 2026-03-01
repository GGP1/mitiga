# iptables / nftables — Firewall Management

## Category
System Hardening

## License
GPLv2

## Source
https://git.netfilter.org/ (included in Linux kernel/userspace)

## Purpose
Configure kernel packet filtering rules — block/allow traffic by port, IP, protocol, interface.

## Use Cases
- Block malicious IPs during incident response
- Restrict outbound traffic to authorized destinations
- Verify current firewall rule sets
- Containment actions for CRITICAL threats
- Audit network filtering policies

## Examples
```bash
# List all rules (iptables)
iptables -L -n -v --line-numbers

# List all rules (nftables)
nft list ruleset

# Block a malicious IP
iptables -A INPUT -s <malicious_ip> -j DROP

# Block outbound to a suspicious destination
iptables -A OUTPUT -d <suspicious_ip> -j DROP

# Save current rules
iptables-save > /tmp/iptables-backup.rules
```

## Safety Notes
- **Rule queries (`-L`, `list`) are read-only and safe.**
- **Rule modifications require verification before and after** (§2 ALWAYS rule #4).
- Always save a backup of current rules before making changes.
- Incorrect rules can cause network outages — prefer detection and reporting over automated changes.
- Reversal plan must exist before adding rules.
