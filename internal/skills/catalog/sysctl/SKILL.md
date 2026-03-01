# sysctl — Kernel Parameter Tuning

## Category
System Hardening

## License
GPLv2 (procps-ng)

## Source
https://gitlab.com/procps-ng/procps (included in all Linux distributions)

## Purpose
Read and modify kernel parameters at runtime.

## Use Cases
- Verify security-related kernel settings
- Enforce hardened kernel parameters (IP forwarding, SYN cookies, ASLR)
- Detect weakened kernel security settings
- Audit network stack configuration

## Examples
```bash
# Read all kernel parameters
sysctl -a 2>/dev/null

# Check specific security parameters
sysctl -a 2>/dev/null | grep -E "ip_forward|syncookies|randomize_va_space|accept_redirects"

# Verify ASLR is enabled
sysctl kernel.randomize_va_space

# Check IP forwarding status
sysctl net.ipv4.ip_forward
```

## Safety Notes
- **Read operations (`sysctl -a`, `sysctl <param>`) are safe.**
- **Write operations (`sysctl -w`) modify kernel behavior at runtime** — require system manager approval and verification before and after.
- Incorrect kernel parameters can cause network issues or security degradation.
