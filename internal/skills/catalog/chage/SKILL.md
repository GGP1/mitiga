# chage — Password Age Management

## Category
User & Group Management

## License
BSD-3-Clause (shadow-utils)

## Source
https://github.com/shadow-maint/shadow (included in all Linux distributions)

## Purpose
View and set password aging parameters — expiration, min/max age, warning days.

## Use Cases
- Audit password policies per user
- Detect accounts with non-expiring passwords
- Verify password rotation compliance
- Check password expiration dates

## Examples
```bash
# View password aging info for a user
chage -l username

# View for all users (loop)
getent passwd | cut -d: -f1 | xargs -I{} sh -c 'echo "=== {} ===" && chage -l {}'
```

## Safety Notes
- `chage -l` is read-only and safe for auditing.
- Modifications to password aging (`chage -M`, `-m`, `-E`) require system manager approval.
