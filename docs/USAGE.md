# Usage Guide for S3 Windows Share Backup Tool

## Quick Start

```bash
# Create a wrapper script for convenience
cat > s3backup.sh << 'EOF'
#!/bin/bash
source "$PWD/s3backup_env/bin/activate"
python "$PWD/s3_backup.py" "$@"
deactivate
EOF

chmod +x s3backup.sh

# Create a default configuration
./s3backup.sh --create-config

# Edit the configuration file
vi config.ini

# Test connection to shares
./s3backup.sh --test-connection

# Initialize the database and index
./s3backup.sh --initialize

# Run your first backup
./s3backup.sh --run-now
```

## Configuration File Format

### AWS Settings

```ini
[AWS]
access_key = YOUR_AWS_ACCESS_KEY
secret_key = YOUR_AWS_SECRET_KEY
region = us-east-1
bucket = your-bucket-name
prefix = 
storage_class = STANDARD_IA
```

- `prefix` can be empty for no prefix, or set to a folder name like "backup/"
- `storage_class` determines the S3 storage class (STANDARD_IA, DEEP_ARCHIVE, etc.)

### General Settings

```ini
[General]
db_path = backup_index.db
report_path = reports/
scan_interval = 24
thread_count = 4
```

- `db_path` - Path to the SQLite database file that stores the backup index
- `report_path` - Directory where backup reports will be saved
- `scan_interval` - Hours between automatic backups (only used with `--schedule` flag, ignored when using cron/systemd)
- `thread_count` - Number of parallel upload threads (higher values may improve performance)

### Email Notification Settings

```ini
[Email]
enabled = false
smtp_server = localhost
smtp_port = 25
from = backup@example.com
to = admin@example.com
subject_prefix = [S3 Backup]
```

- Set `enabled` to `true` to receive email notifications for backup operations
- Email uses a local mail relay with no authentication
- Email failures will not interrupt the backup process

### Share Settings

```ini
[Shares]
finance = 192.168.1.10,FinanceShare,username,password,WORKGROUP
marketing = 192.168.1.10,MarketingShare,username,password,WORKGROUP
guest_share = 192.168.1.10,PublicShare,guest,,
```

Format: `server_ip,share_name,username,password,domain/workgroup`

- The key name (e.g., `finance`) becomes the folder prefix in S3
- Use `guest` as username for guest/anonymous access
- The domain/workgroup field can be empty for workgroups

## Command Line Options

### Basic Operations

```bash
# Create a default configuration file
./s3backup.sh --create-config

# Initialize the database and build initial index
./s3backup.sh --initialize

# Run backup immediately
./s3backup.sh --run-now

# Verify files in index exist in S3 without running a backup
./s3backup.sh --run-now-verify

# Start built-in scheduler (uses scan_interval from config.ini)
./s3backup.sh --schedule
```

The `--schedule` flag activates the tool's built-in scheduler, which runs backups at intervals defined by the `scan_interval` setting (default: 24 hours). This is separate from and an alternative to using cron or systemd scheduling.

The `--run-now-verify` option checks that each file in the index actually exists in S3 and has the correct checksum, without uploading any new files. This is useful to verify backup integrity or identify any synchronization issues.

### AWS Sync Operations

```bash
# Synchronize index with AWS S3 and Windows shares (no uploads)
# Perfect when migrating from another backup solution
./s3backup.sh --sync-index-with-aws

# After syncing, review files that exist only in S3 
./s3backup.sh --list-index --s3-only

# Run a backup to upload only the missing files
./s3backup.sh --run-now
```

### Testing and Reporting

```bash
# Test connection to Windows shares
./s3backup.sh --test-connection

# List the backup index
./s3backup.sh --list-index

# Show only deleted files
./s3backup.sh --list-index --show-deleted

# Filter by share name
./s3backup.sh --list-index --share finance

# Export to CSV
./s3backup.sh --list-index --export-csv index.csv

# Generate a report of deleted files
./s3backup.sh --deleted-report --report-path deleted_files.csv

# Generate an AWS CLI script to delete files from S3
./s3backup.sh --generate-delete-script --script-path delete_script.sh
```

## Encrypted Configuration

To protect sensitive credentials in the config.ini file:

```bash
# Create a new encrypted config
./s3backup.sh --create-config --encrypt-config

# Encrypt an existing config
./s3backup.sh --encrypt-config

# Create a password file for unattended operations
./s3backup.sh --create-password-file /path/to/.backup_password

# Run with password file
./s3backup.sh --run-now --password-file /path/to/.backup_password

# Run with environment variable
export BACKUP_PASSWORD=your_password
./s3backup.sh --run-now --password-env BACKUP_PASSWORD
```

## Setting Up Scheduled Jobs

You can set up automated backups using either the built-in scheduler or external scheduling systems.

### Using Built-in Scheduler

```bash
# Start the built-in scheduler (runs based on scan_interval in config.ini)
./s3backup.sh --schedule
```

The built-in scheduler is suitable for simple setups but lacks the reliability features of system schedulers. It will continue to run until the process is terminated.

### Using Cron (Recommended)

```bash
# Edit crontab
crontab -e

# Add a line to run daily at 2 AM
0 2 * * * /path/to/s3backup.sh --run-now --password-file /path/to/.backup_password

# Add verification job to run weekly (Sundays at 3 AM)
0 3 * * 0 /path/to/s3backup.sh --run-now-verify --password-file /path/to/.backup_password
```

### Using Systemd

1. Create a service file:

```bash
sudo vi /etc/systemd/system/s3backup.service
```

2. Add the following content:

```ini
[Unit]
Description=S3 Windows Share Backup
After=network.target

[Service]
Type=simple
User=username
WorkingDirectory=/path/to/s3backup
ExecStart=/path/to/s3backup.sh --run-now --password-file /path/to/.backup_password
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

3. Create a timer file:

```bash
sudo vi /etc/systemd/system/s3backup.timer
```

4. Add the following content:

```ini
[Unit]
Description=Run S3 Backup Daily

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

5. Enable and start the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable s3backup.timer
sudo systemctl start s3backup.timer
```

6. Optionally, create a verification service and timer:

```bash
sudo vi /etc/systemd/system/s3backup-verify.service
```

```ini
[Unit]
Description=S3 Windows Share Backup Verification
After=network.target

[Service]
Type=simple
User=username
WorkingDirectory=/path/to/s3backup
ExecStart=/path/to/s3backup.sh --run-now-verify --password-file /path/to/.backup_password
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo vi /etc/systemd/system/s3backup-verify.timer
```

```ini
[Unit]
Description=Run S3 Backup Verification Weekly

[Timer]
OnCalendar=Sun *-*-* 03:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

## Migrating from Another Backup Solution

If you're replacing an existing backup solution and already have files in S3:

1. Configure the tool with your S3 bucket and shares

```bash
./s3backup.sh --create-config
vi config.ini
```

2. Test connection to your shares

```bash
./s3backup.sh --test-connection
```

3. Synchronize the index with AWS S3 and your shares

```bash
./s3backup.sh --sync-index-with-aws
```

4. Review the synchronization report to see what matched and what needs to be uploaded

5. Run a backup to upload only the files not already in S3

```bash
./s3backup.sh --run-now
```

6. Optionally, check files that exist only in S3 (potentially orphaned)

```bash
./s3backup.sh --list-index --s3-only
```

7. Verify all indexed files exist in S3 with correct checksums

```bash
./s3backup.sh --run-now-verify
```

This migration workflow prevents re-uploading already backed up files, saving time and bandwidth.

## Troubleshooting

### Connection Issues

- **SMB Connection Failures**: Ensure Windows file sharing is enabled and ports 139/445 are open
- **Authentication Issues**: Check credentials and workgroup/domain settings
- **AWS Connection Failures**: Verify IAM permissions and network connectivity

### Database Issues

If you encounter database errors:

```bash
# Make a backup of the database
cp backup_index.db backup_index.db.bak

# Check database integrity
sqlite3 backup_index.db "PRAGMA integrity_check;"

# Repair if needed
sqlite3 backup_index.db "VACUUM;"
```

### Log Files

Check the log file for detailed information:

```bash
tail -100 s3_backup.log
```

### Backup Verification Failures

If `--run-now-verify` reports missing or different files:

1. Check if the files have been accidentally deleted from S3
2. Verify the S3 bucket, prefix, and storage class settings
3. Run a regular backup with `--run-now` to re-upload any missing files

## Understanding Backup Reports

After each backup run, a report is generated in the `reports/` directory containing:

- Files successfully uploaded
- Failed uploads
- Scan errors
- File statistics

The report format is CSV and can be opened in any spreadsheet application.

When using the AWS sync functionality, a special sync report is also generated showing:
- Files matched between S3 and shares
- Files that exist only in S3
- Files that need to be uploaded

Verification reports include:
- Files successfully verified in S3
- Files missing from S3
- Files with checksum mismatches