# Email Notifications for Backup Jobs

The S3 Windows Share Backup Tool supports email notifications for backup operations, which is especially useful for scheduled jobs to receive alerts about backup status.

## Basic Configuration

Add the following section to your `config.ini` file:

```ini
[Email]
enabled = false
smtp_server = localhost
smtp_port = 25
from = backup@example.com
to = admin@example.com
subject_prefix = S3 Tool
attach_report = false
max_attachment_size = 10485760
```

## Basic Settings Explained

| Setting | Description | Default | 
|---------|-------------|---------|
| `enabled` | Whether email notifications are active | `false` |
| `smtp_server` | SMTP server address | `localhost` |
| `smtp_port` | SMTP server port | `25` |
| `from` | Email sender address | `backup@example.com` |
| `to` | Email recipient address | `admin@example.com` |
| `subject_prefix` | Prefix added to email subjects (can be empty for no prefix) | `S3 Tool` |
| `attach_report` | Whether to attach the backup report CSV file | `false` |
| `max_attachment_size` | Maximum allowed attachment size in bytes | `10485760` (10MB) |

## SMTP Authentication Configuration

For mail servers that require authentication, add these settings:

```ini
[Email]
# Basic settings as above, plus:
auth_required = true
username = your_username
password = your_password
use_tls = true
```

## SMTP Authentication Settings

| Setting | Description | Default | 
|---------|-------------|---------|
| `auth_required` | Whether SMTP authentication is required | `false` |
| `username` | SMTP authentication username | `` |
| `password` | SMTP authentication password | `` |
| `use_tls` | Whether to use TLS encryption | `false` |

## Microsoft Graph API Configuration (Office 365)

For modern Office 365 integration using Graph API instead of traditional SMTP:

```ini
[GraphAPI]
enabled = false
client_id = your_azure_app_id
tenant_id = your_azure_tenant_id
client_secret = your_client_secret
user_id = user@yourdomain.com
save_to_sent_items = true
```

## Microsoft Graph API Settings

| Setting | Description | Default | 
|---------|-------------|---------|
| `enabled` | Whether to use Graph API instead of SMTP | `false` |
| `client_id` | Azure AD application (client) ID | `` |
| `tenant_id` | Azure AD directory (tenant) ID | `` |
| `client_secret` | Client secret value | `` |
| `user_id` | User ID to send as (typically email address) | `` |
| `save_to_sent_items` | Whether to save to sent items folder | `true` |

## Important Notes

- **Email Sending Priority**: If both Graph API and SMTP are enabled, Graph API will be used.
- **Dependencies**: Graph API requires the `azure-identity` and `msgraph-core` Python packages.
  Install them with: `pip install azure-identity msgraph-core`
- **Failed Email Won't Stop Backup**: If email sending fails for any reason, the backup job will continue uninterrupted. Only a warning will be logged.
- **Multiple Recipients**: For multiple recipients, separate email addresses with commas: `to = admin@example.com, alerts@example.com`
- **Optional Feature**: Email notifications are entirely optional and disabled by default.
- **Report Attachments**: When enabled, the CSV report file is attached to the email notification.

## Example Configurations

### Using Local Mail Relay (Postfix/Sendmail)

```ini
[Email]
enabled = true
smtp_server = localhost
smtp_port = 25
from = s3backup@myserver.local
to = admin@example.com
subject_prefix = S3 Tool
```

### Using Authenticated SMTP with TLS (Gmail, etc.)

```ini
[Email]
enabled = true
smtp_server = smtp.gmail.com
smtp_port = 587
from = youraccount@gmail.com
to = admin@company.com
subject_prefix = S3 Tool
auth_required = true
username = youraccount@gmail.com
password = your_app_password
use_tls = true
attach_report = true
```

### Using Microsoft Graph API with Office 365

```ini
[Email]
enabled = true
from = backups@company.com
to = it-team@company.com
subject_prefix = S3 Tool
attach_report = true

[GraphAPI]
enabled = true
client_id = 01234567-89ab-cdef-0123-456789abcdef
tenant_id = 98765432-10fe-dcba-9876-543210fedcba
client_secret = your_secret_value_from_azure_portal
user_id = backups@company.com
save_to_sent_items = true
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

When report attachment is enabled, a CSV file with detailed information about the backup job will be attached to the email.

## Setting Up Microsoft Graph API for Office 365

1. **Register an application in Azure AD:**
   - Go to the [Azure Portal](https://portal.azure.com)
   - Navigate to Azure Active Directory → App registrations → New registration
   - Name your application (e.g., "S3 Backup Email Sender")
   - Set the supported account type (typically "Single tenant")
   - Click Register

2. **Configure API permissions:**
   - In your app registration, go to API permissions
   - Add Microsoft Graph permissions:
     - Mail.Send
     - Mail.ReadWrite (if saving to sent items)
   - Grant admin consent for these permissions

3. **Create a client secret:**
   - Go to Certificates & secrets
   - Create a new client secret
   - Copy the value immediately (it will only be shown once)

4. **Configure the backup tool with the values obtained above**

## Testing Email Configuration

To test if your email configuration is working:

```bash
# Run a test backup with email notifications enabled
./s3backup.sh --run-now

# Check the logs for email sending status
grep "email" logs/s3_backup_*.log
```

## Troubleshooting Email Issues

If you're not receiving email notifications:

1. **Check SMTP Server**: Verify the SMTP server is accessible
   ```bash
   telnet your-smtp-server 25
   ```

2. **Verify Authentication**: For servers requiring authentication, double-check credentials

3. **Check TLS**: If using TLS, verify port and TLS settings

4. **Test Basic Mail Functionality**: Ensure system mail works
   ```bash
   echo "Test message" | mail -s "Test from server" your@email.com
   ```

5. **Check Dependencies**: For Graph API, verify dependencies are installed
   ```bash
   pip install azure-identity msgraph-core
   ```

6. **Check App Permissions**: For Graph API, verify Azure AD app permissions

7. **Check Logs**: Look for email-related messages in the backup logs
   ```bash
   grep -i "email\|smtp\|mail\|graph" logs/s3_backup_*.log
   ```

8. **Spam Filters**: Check if notifications are being caught by spam filters
