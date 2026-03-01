# tcpdump — Packet Capture

## Category
Network Traffic Analysis

## License
BSD-3-Clause

## Source
https://github.com/the-tcpdump-group/tcpdump

## Purpose
Capture and inspect network packets at the interface level.

## Use Cases
- Investigate suspicious network connections
- Verify mTLS is active on peer communications
- Detect plaintext transmissions that should be encrypted
- Forensic packet capture during security incidents
- Monitor traffic patterns on specific ports

## Examples
```bash
# Capture peer protocol traffic
tcpdump -i any port 27027 -c 100 -w /tmp/capture.pcap

# Capture non-SSH traffic (avoid noise)
tcpdump -i any 'not port 22' -n -c 50

# Capture with timestamps and no DNS resolution
tcpdump -i any -tttt -n port 27027 -c 50

# Capture traffic to/from a specific host
tcpdump -i any host <suspicious_ip> -n -c 100 -w /tmp/investigation.pcap
```

## Safety Notes
- **Captures may contain sensitive data** — handle with the same caution as logs.
- Never log raw packet content containing credentials or secrets.
- Requires appropriate privileges (typically root or `CAP_NET_RAW`).
- Use `-c` to limit capture count and avoid filling disk.
- Clean up capture files after analysis.
