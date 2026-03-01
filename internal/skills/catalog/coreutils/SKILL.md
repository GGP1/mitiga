# coreutils — General System Utilities

## Category
General System Utilities

## License
GPLv2/GPLv3+ (GNU coreutils, util-linux, procps-ng)

## Source
- https://github.com/coreutils/coreutils
- https://github.com/util-linux/util-linux
- https://gitlab.com/procps-ng/procps

Included in every Linux distribution.

## Purpose
Standard GNU/Linux utilities used as building blocks in agent operations — file inspection, text processing, system information gathering.

## Tools

### File & Text Processing

| Tool | Purpose | Example |
|---|---|---|
| `cat` | Read file contents | `cat /etc/os-release` |
| `head` | Read beginning of files | `head -n 50 /var/log/auth.log` |
| `tail` | Read end of files | `tail -n 100 /var/log/auth.log` |
| `grep` | Pattern matching in text | `grep -r "PermitRootLogin" /etc/ssh/` |
| `awk` | Text processing and field extraction | `awk -F: '$3==0 {print $1}' /etc/passwd` |
| `sed` | Stream editing | `sed -n '/Failed password/p' /var/log/auth.log` |
| `wc` | Line/word/byte counting | `wc -l /var/log/auth.log` |
| `diff` | File comparison | `diff /etc/ssh/sshd_config sshd_config.baseline` |
| `sort` | Sort lines | `sort -rn access.log` |
| `uniq` | Deduplicate adjacent lines | `sort access.log \| uniq -c \| sort -rn` |
| `cut` | Field extraction | `cut -d: -f1 /etc/passwd` |
| `file` | File type identification | `file /usr/local/bin/mitiga` |
| `ldd` | Shared library dependencies | `ldd /usr/local/bin/suspicious_binary` |

### System Information

| Tool | Purpose | Example |
|---|---|---|
| `uname` | System and kernel information | `uname -a` |
| `hostname` | System hostname | `hostname -f` |
| `date` | Timestamps | `date -u +%Y-%m-%dT%H:%M:%SZ` |
| `uptime` | System uptime and load | `uptime` |
| `free` | Memory usage | `free -h` |
| `df` | Disk usage (filesystem level) | `df -h` |
| `du` | Disk usage (directory level) | `du -sh /var/log/*` |
| `mount` | Mounted filesystems | `mount \| grep -E 'nosuid\|noexec'` |
| `env` | Environment variables | `env \| grep MITIGA_` |
| `dmesg` | Kernel ring buffer | `dmesg -T --level=err,warn` |

## Safety Notes
- All read-only utilities listed here are safe to run at any time.
- `sed` with `-i` (in-place editing) modifies files — avoid unless explicitly authorized.
- `ldd` should not be run on untrusted binaries (it may execute them); use `objdump -p` as a safer alternative for unknown binaries.
- Never pipe untrusted data directly into commands that can execute code (e.g., `awk`, `sed` with system calls).
