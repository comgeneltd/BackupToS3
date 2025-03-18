# BackupToS3 Usage Guide



## Basic Operations

```bash
# Initialize the database and build initial index
./s3backup.sh --initialize

# Run backup immediately
./s3backup.sh --run-now

# Verify files in index exist in S3 without running a backup
./s3backup.sh --run-now-verify

# Start built-in scheduler (uses scan_interval from config.ini)
./s3backup.sh --schedule
```

## AWS Sync Operations

```bash
# Synchronize index with AWS S3 and Windows shares (no uploads)
./s3backup.sh --sync-index-with-aws

# After syncing, review files that exist only in S3 
./s3backup.sh --list-index --s3-only

# Run a backup to upload only the missing files
./s3backup.sh --run-now
```

## Testing and Reporting

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

### Using Built-in Scheduler

```bash
# Start the built-in scheduler (runs based on scan_interval in config.ini)
./s3backup.sh --schedule
```

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

Create service file `/etc/systemd/system/s3backup.service`:

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

Create timer file `/etc/systemd/system/s3backup.timer`:

```ini
[Unit]
Description=Run S3 Backup Daily

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and start the timer:

```bash
sudo systemctl daemon-reload
sudo systemctl enable s3backup.timer
sudo systemctl start s3backup.timer
```

## Migrating from Another Backup Solution

1. Configure the tool with your S3 bucket and shares
2. Test connection to your shares
3. Synchronize the index with AWS S3 and your shares:
   ```bash
   ./s3backup.sh --sync-index-with-aws
   ```
4. Run a backup to upload only the files not already in S3:
   ```bash
   ./s3backup.sh --run-now
   ```
5. Verify all indexed files exist in S3 with correct checksums:
   ```bash
   ./s3backup.sh --run-now-verify
   ```

## Troubleshooting

### Connection Issues

- Ensure Windows file sharing is enabled and ports 139/445 are open
- Verify credentials and workgroup/domain settings
- Check AWS IAM permissions and network connectivity

### Database Issues

```bash
# Make a backup of the database
cp backup_index.db backup_index.db.bak

# Check database integrity
sqlite3 backup_index.db "PRAGMA integrity_check;"

# Repair if needed
sqlite3 backup_index.db "VACUUM;"
```

### Force Re-upload

If you need to force re-upload of all files:

```bash
sqlite3 backup_index.db "UPDATE files SET last_modified = '2000-01-01T00:00:00';"
```

### Log Files

Check the log file for detailed information:

```bash
tail -100 s3_backup.log
```
