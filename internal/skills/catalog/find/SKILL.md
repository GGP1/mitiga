# find — File System Search

## Category
File Integrity & Verification

## License
GPLv3+ (GNU findutils)

## Source
https://github.com/coreutils/coreutils (included in all Linux distributions)

## Purpose
Search for files matching specific criteria — permissions, ownership, timestamps, types.

## Use Cases
- Find SUID/SGID binaries (potential privilege escalation vectors)
- Detect world-writable files and directories
- Find recently modified files during investigations
- Locate orphaned files with no valid owner
- Search for files by name, type, or content

## Examples
```bash
# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Find world-writable files (excluding /proc)
find / -perm -0002 -type f -not -path '/proc/*' 2>/dev/null

# Find files modified since a timestamp
find /etc -newer /etc/baseline_timestamp -type f

# Find files owned by a specific user
find / -user suspicious_user -type f 2>/dev/null

# Find SGID directories
find / -perm -2000 -type d 2>/dev/null
```

## Safety Notes
- Read-only search operation — does not modify the filesystem.
- Use `-exec` cautiously — never pass untrusted input to `-exec` commands.
- Redirect stderr to avoid cluttering output with permission errors.
