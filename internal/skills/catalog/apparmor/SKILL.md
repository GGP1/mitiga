# AppArmor — Mandatory Access Control

## Category
System Hardening

## License
GPLv2

## Source
https://gitlab.com/apparmor/apparmor (included in Ubuntu/Debian/SUSE)

## Purpose
Inspect and manage AppArmor profiles — mandatory access control enforcement.

## Use Cases
- Verify AppArmor is active and enforcing
- Check profile enforcement status for all confined processes
- Audit which applications are running unconfined
- Verify specific profiles are in enforce mode

## Tools
- `aa-status` — Show AppArmor status and profile modes
- `apparmor_parser` — Load and manage profiles

## Examples
```bash
# Show AppArmor status and all profiles
aa-status

# Check if AppArmor is enabled
aa-enabled

# List profiles in enforce mode
aa-status --enforced
```

## Safety Notes
- **Status queries are read-only and safe.**
- **Profile changes (enforce, complain, disable) modify security policy** — require system manager approval.
- Never disable AppArmor profiles without documented justification.
