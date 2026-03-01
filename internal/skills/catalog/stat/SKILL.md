# stat — File Status

## Category
File Integrity & Verification

## License
GPLv3+ (GNU coreutils)

## Source
https://github.com/coreutils/coreutils (included in all Linux distributions)

## Purpose
Display detailed file or filesystem status — permissions, ownership, timestamps, inode.

## Use Cases
- Inspect file metadata during investigations
- Verify file permissions match security baselines
- Check modification and access times
- Examine inode details for forensic analysis

## Examples
```bash
# Display full file status
stat /etc/shadow

# Display specific format fields
stat -c '%U %G %a %n' /etc/shadow

# Check timestamps
stat -c '%y %n' /etc/passwd

# Filesystem status
stat -f /
```

## Safety Notes
- Read-only operation — safe to run at any time.
