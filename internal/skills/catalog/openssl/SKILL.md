# openssl — Cryptographic Toolkit

## Category
TLS & Certificate Operations

## License
Apache 2.0

## Source
https://github.com/openssl/openssl

## Purpose
TLS/SSL testing, certificate inspection, cryptographic operations, connection diagnostics.

## Use Cases
- Verify TLS configurations on peer agent connections
- Inspect peer certificates for validity and expiry
- Test cipher suites offered by a service
- Generate CSRs for certificate rotation
- Check certificate chain integrity
- Verify certificate expiry dates

## Examples
```bash
# Connect to a peer and show certificates
openssl s_client -connect <host>:27027 -showcerts </dev/null

# Inspect a certificate file
openssl x509 -in cert.pem -text -noout

# Check if certificate expires within 24 hours
openssl x509 -in cert.pem -checkend 86400

# Verify a certificate chain
openssl verify -CAfile ca.pem cert.pem

# Show certificate fingerprint
openssl x509 -in cert.pem -fingerprint -sha256 -noout

# Test TLS connection with specific protocol
openssl s_client -connect <host>:27027 -tls1_3 </dev/null
```

## Safety Notes
- Inspection and verification commands are read-only and safe.
- Certificate generation and key operations should follow §6 configuration for TLS paths.
- Never output private keys to logs or reports.
