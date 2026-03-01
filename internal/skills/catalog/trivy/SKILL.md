# trivy — Comprehensive Vulnerability Scanner

## Category
Vulnerability Scanning

## License
Apache 2.0

## Source
https://github.com/aquasecurity/trivy (CNCF project)

## Purpose
Scan filesystems, container images, Git repositories, and IaC configurations for known vulnerabilities (CVEs), misconfigurations, and exposed secrets.

## Use Cases
- Audit project dependencies for known CVEs
- Scan configuration files for misconfigurations
- Detect embedded secrets in repositories
- Scan container images before deployment
- Generate SBOM (Software Bill of Materials)

## Examples
```bash
# Filesystem scan for HIGH and CRITICAL vulnerabilities
trivy fs --severity HIGH,CRITICAL --format json /path/to/project

# Repository scan with all scanners
trivy repo --scanners vuln,secret,misconfig /path/to/repo

# Scan with JSON output for machine consumption
trivy fs --format json --output trivy-results.json /path/to/project

# Scan a container image
trivy image --severity HIGH,CRITICAL <image:tag>
```

## Safety Notes
- Read-only scanning operation — does not modify the target.
- Requires an up-to-date vulnerability database. Database updates require system manager approval as they involve network access.
