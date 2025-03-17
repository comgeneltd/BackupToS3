# Email Notifications for Backup Jobs

The S3 Windows Share Backup Tool now supports email notifications for backup operations. This is especially useful for scheduled jobs where you want to receive notifications about backup status.

## Configuration

Add the following section to your `config.ini` file:

```ini
[Email]
enabled = false
smtp_server = localhost
smtp_port = 25
from = backup@example.com
to = admin@example.com
subject_prefix = [S3 Backup]
```

## Settings Explained

| Setting | Description | Example |
|---------|-------------|---------|
| `enabled` | Set to `true` to enable email notifications | `enabled = true` |
| `smtp_server` | SMTP server address | `smtp_server = mail.company.com` |
| `smtp_port` | SMTP server port | `smtp_port = 25` |
| `from` | Email sender address | `from = backup-system@company.com` |
| `to` | Email recipient address | `to = it-department@company.com` |
| `subject_prefix` | Prefix added to email subjects | `subject_prefix = [BACKUP]` |

## Usage Notes

1. **Local Mail Relay**: The system is designed to work with a local mail relay without authentication. For secure SMTP servers requiring authentication, you would need to modify the script.

2. **Optional Feature**: Email notifications are entirely optional and disabled by default. If enabled but email sending fails, the backup job will continue without interruption - the failure will only be logged.

3. **Multiple Recipients**: To send to multiple recipients, separate email addresses with commas, e.g., `to = admin1@example.com, admin2@example.com`

## Example Configurations

### Local Postfix/Sendmail Server

```ini
[Email]
enabled = true
smtp_server = localhost
smtp_port = 25
from = backups@myserver.local
to = admin@company.com
subject_prefix = [S3 Backup]
```

### Corporate Mail Server

```ini
[Email]
enabled = true
smtp_server = mail.company.com
smtp_port = 25
from = no-reply@company.com
to = alerts@company.com
subject_prefix = [IT-BACKUP]
```

## Email Contents

The email notification will include:
- A summary of files processed
- Number of files uploaded, moved, or renamed
- Any errors encountered
- Total data transferred
- Operation status

This gives you a quick overview of backup status without needing to log in to the server to check logs.
