# grype — Dependency Vulnerability Scanner

## Category
Vulnerability Scanning

## License
Apache 2.0

## Source
https://github.com/anchore/grype

## Purpose
Match software dependencies and packages against known vulnerability databases.

## Use Cases
- Scan Go modules for known CVEs
- Audit OS packages for vulnerabilities
- Scan container layers for CVEs
- SBOM-based vulnerability matching
- Focused alternative to `trivy` for dependency-level scanning

## Examples
```bash
# Scan a project directory
grype dir:/path/to/project --output json

# Scan from an SBOM
grype sbom:bom.json

# Scan with severity filter
grype dir:/path/to/project --only-fixed --output json

# Scan a container image
grype <image:tag> --output json
```

## Safety Notes
- Read-only scanning operation — does not modify the target.
- Database updates require system manager approval.
