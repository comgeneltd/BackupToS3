# Email Notifications for Backup Jobs

The S3 Windows Share Backup Tool now supports email notifications for backup operations, which is especially useful for scheduled jobs to receive alerts about backup status.

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

| Setting | Description | Default | 
|---------|-------------|---------|
| `enabled` | Whether email notifications are active | `false` |
| `smtp_server` | SMTP server address | `localhost` |
| `smtp_port` | SMTP server port | `25` |
| `from` | Email sender address | `backup@example.com` |
| `to` | Email recipient address | `admin@example.com` |
| `subject_prefix` | Prefix added to email subjects | `[S3 Backup]` |

## Important Notes

- **Local Mail Relay**: This feature is designed to work with a local mail relay (e.g., postfix, sendmail) that doesn't require authentication.
- **Failed Email Won't Stop Backup**: If email sending fails for any reason, the backup job will continue uninterrupted. Only a warning will be logged.
- **Multiple Recipients**: For multiple recipients, separate email addresses with commas: `to = admin@example.com, alerts@example.com`

## Example Configurations

### Using Local Mail Relay

```ini
[Email]
enabled = true
smtp_server = localhost
smtp_port = 25
from = s3backup@myserver.local
to = admin@example.com
subject_prefix = [S3 BACKUP]
```

### Using Corporate Mail Server

```ini
[Email]
enabled = true
smtp_server = mail.company.com
smtp_port = 25
from = backups@company.com
to = it-team@company.com
subject_prefix = [BACKUP ALERT]
```

## What's Included in Email Notifications

The email notifications include:

1. For backup operations:
   - Number of files processed, uploaded, failed
   - Total data transferred
   - Files moved or renamed
   - Files marked as deleted
   - Any errors encountered

2. For AWS sync operations:
   - Files indexed from S3
   - Files indexed from Windows shares
   - Files matched between locations
   - Files existing only in S3
   - Statistics for each share

## For Scheduled Operations

When setting up scheduled jobs, ensure your system has a properly configured mail transport agent if you want to use email notifications:

```bash
# Check if mail works on your system
echo "Test" | mail -s "Test Email" admin@example.com

# If not, install postfix or another MTA
sudo apt install postfix  # For Ubuntu/Debian
```
