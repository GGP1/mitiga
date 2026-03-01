# sha256sum / sha512sum — Checksum Verification

## Category
File Integrity & Verification

## License
GPLv3+ (GNU coreutils)

## Source
https://github.com/coreutils/coreutils (included in all Linux distributions)

## Purpose
Generate and verify SHA-256/SHA-512 cryptographic checksums.

## Use Cases
- Verify binary integrity against known-good checksums
- Detect tampered files
- Record baselines for known-good binaries
- Validate downloaded artifacts

## Examples
```bash
# Generate SHA-256 checksum
sha256sum /usr/local/bin/mitiga

# Verify checksums from a file
sha256sum -c checksums.sha256

# Generate SHA-512 checksum
sha512sum /usr/local/bin/mitiga

# Generate checksums for multiple files
sha256sum /etc/ssh/sshd_config /etc/passwd /etc/shadow
```

## Safety Notes
- Read-only operation — safe to run at any time.
- Always record checksums of known-good binaries during initial setup.
