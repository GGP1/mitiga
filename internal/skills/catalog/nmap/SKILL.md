# nmap — Network Mapper

## Category
Network Reconnaissance

## License
GPLv2

## Source
https://github.com/nmap/nmap

## Purpose
Port scanning, service/version detection, OS fingerprinting, network discovery.

## Use Cases
- Detect open ports on local and remote hosts
- Identify unexpected listeners on the network
- Map network services and their versions
- Verify firewall rules by testing reachability
- OS fingerprinting for asset inventory

## Examples
```bash
# Full TCP port scan with service detection, XML output
nmap -sT -sV -p 1-65535 --open -oX scan_result.xml <target>

# Quick scan of common ports
nmap -sT -F --open <target>

# Ping sweep to discover live hosts on subnet
nmap -sn 192.168.1.0/24

# Scan specific ports with version detection
nmap -sT -sV -p 22,80,443,27027 <target>
```

## Safety Notes
- Always use `-sT` (TCP connect) scans — SYN scans (`-sS`) require root privileges.
- Never scan hosts outside the local network without explicit system manager authorization.
- Use `--max-rate` to avoid flooding the network.
- All scan results must be logged and included in reports.
