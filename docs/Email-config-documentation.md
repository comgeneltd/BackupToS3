# Email Notifications for Backup Jobs

The S3 Windows Share Backup Tool supports email notifications for backup operations, which is especially useful for scheduled jobs to receive alerts about backup status.

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

- **Local Mail Relay**: This feature is designed to work with a local mail relay (e.g., postfix, sendmail) that doesn't require authentication. For secure SMTP servers requiring authentication, you would need to modify the script.
- **Failed Email Won't Stop Backup**: If email sending fails for any reason, the backup job will continue uninterrupted. Only a warning will be logged.
- **Multiple Recipients**: For multiple recipients, separate email addresses with commas: `to = admin@example.com, alerts@example.com`
- **Optional Feature**: Email notifications are entirely optional and disabled by default.

## Example Configurations

### Using Local Mail Relay (Postfix/Sendmail)

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
   - Operation status

2. For AWS sync operations:
   - Files indexed from S3
   - Files indexed from Windows shares
   - Files matched between locations
   - Files existing only in S3
   - Statistics for each share

This gives you a quick overview of backup status without needing to log in to the server to check logs.

## Setting Up Mail Transport Agent

When setting up scheduled jobs, ensure your system has a properly configured mail transport agent if you want to use email notifications:

```bash
# Check if mail works on your system
echo "Test" | mail -s "Test Email" admin@example.com

# If not, install postfix or another MTA
sudo apt install postfix  # For Ubuntu/Debian
```

## Testing Email Configuration

To test if your email configuration is working:

```bash
# Run a test backup with email notifications enabled
./s3backup.sh --run-now

# Check the logs for email sending status
grep "email" s3_backup.log

# If there are issues, verify your mail transport agent is working
systemctl status postfix  # Or your mail service
```

## Troubleshooting Email Issues

If you're not receiving email notifications:

1. **Check SMTP Server**: Verify the SMTP server is accessible
   ```bash
   telnet your-smtp-server 25
   ```

2. **Verify Mail Transport Agent**: Make sure postfix or another MTA is running
   ```bash
   systemctl status postfix
   ```

3. **Test Basic Mail Functionality**: Ensure system mail works
   ```bash
   echo "Test message" | mail -s "Test from server" your@email.com
   ```

4. **Check Logs**: Look for email-related messages in the backup logs
   ```bash
   grep -i "email\|smtp\|mail" s3_backup.log
   ```

5. **Spam Filters**: Check if notifications are being caught by spam filters
