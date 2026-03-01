# lynis — Security Auditing Tool

## Category
System Hardening

## License
GPLv3

## Source
https://github.com/CISOfy/lynis

## Purpose
Comprehensive security auditing and hardening assessment. Checks hundreds of security controls and produces a hardening index with specific recommendations.

## Use Cases
- Full system security audit
- Compliance checking (CIS, HIPAA, PCI-DSS baselines)
- Hardening gap analysis
- Periodic posture assessment
- Generate remediation recommendations

## Examples
```bash
# Quick system audit
lynis audit system --quick --no-colors --logfile /var/log/lynis.log --report-file /var/log/lynis-report.dat

# Full audit with all tests
lynis audit system --no-colors --logfile /var/log/lynis.log --report-file /var/log/lynis-report.dat

# Show only warnings and suggestions
lynis show warnings
lynis show suggestions
```

## Safety Notes
- Read-only auditing — does not modify the system.
- Produces a hardening index score useful for tracking security posture over time.
