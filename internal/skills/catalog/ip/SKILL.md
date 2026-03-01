# ip — Network Interface and Routing

## Category
Network Reconnaissance

## License
GPLv2 (iproute2)

## Source
https://github.com/iproute2/iproute2 (included in Linux)

## Purpose
Query network interfaces, addresses, routes, and neighbors.

## Use Cases
- Verify network configuration and interface status
- Detect rogue interfaces or unexpected addresses
- Inspect routing tables for suspicious entries
- Confirm local subnet scope for peer communication
- Review ARP/neighbor table for anomalies

## Examples
```bash
# Show all interfaces and addresses
ip addr show

# Show routing table
ip route list

# Show ARP/neighbor table
ip neigh show

# Show only IPv4 addresses
ip -4 addr show

# Show link-layer info for all interfaces
ip link show
```

## Safety Notes
- Read-only queries are safe. Modification commands (`ip addr add`, `ip route add`) require system manager approval.
