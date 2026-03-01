# systemctl — Service Management

## Category
System Hardening

## License
LGPLv2.1+ (systemd)

## Source
https://github.com/systemd/systemd (included in systemd-based distributions)

## Purpose
Control systemd services — start, stop, enable, disable, inspect status.

## Use Cases
- Audit running services for unnecessary attack surface
- Disable unnecessary services
- Check service dependencies and states
- Restart misconfigured services after hardening
- Verify critical services are enabled and running

## Examples
```bash
# List all running services
systemctl list-units --type=service --state=running --no-pager

# Check if a service is enabled
systemctl is-enabled sshd

# Show service status
systemctl status sshd --no-pager

# List failed services
systemctl list-units --type=service --state=failed --no-pager

# Show service dependencies
systemctl list-dependencies sshd --no-pager
```

## Safety Notes
- **Status and listing commands are read-only and safe.**
- **Start/stop/enable/disable operations modify system state** — require system manager approval except for CRITICAL threat response.
- Stopping critical services can cause outages.
