# gpg — GNU Privacy Guard

## Category
File Integrity & Verification

## License
GPLv3

## Source
https://github.com/gpg/gnupg

## Purpose
Verify digital signatures on packages, binaries, and documents.

## Use Cases
- Verify package signatures before installation
- Validate signed release artifacts
- Check release integrity against publisher keys
- Verify detached signatures

## Examples
```bash
# Verify a detached signature
gpg --verify release.sig release.tar.gz

# Import a public key
gpg --import publisher-key.asc

# List imported keys
gpg --list-keys

# Verify with specific keyring
gpg --keyring /path/to/keyring.gpg --verify release.sig release.tar.gz
```

## Safety Notes
- Verification operations are read-only and safe.
- Key imports should be verified against trusted sources.
- Never import keys from untrusted or unverified sources.
