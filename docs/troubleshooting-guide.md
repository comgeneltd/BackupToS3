# BackupToS3 Troubleshooting Guide

This document provides solutions for common issues encountered when using the BackupToS3 tool.

## Force Re-upload

If you need to force the tool to re-upload all files (for example, after storage class changes):

```bash
# Force re-upload of all files in the index
sqlite3 backup_index.db "UPDATE files SET last_modified = '2000-01-01T00:00:00';"
```

For more targeted re-uploads:

```bash
# Force re-upload for a specific share
sqlite3 backup_index.db "UPDATE files SET last_modified = '2000-01-01T00:00:00' WHERE local_path LIKE 'sharename:%';"

# Force re-upload for a specific file or path
sqlite3 backup_index.db "UPDATE files SET last_modified = '2000-01-01T00:00:00' WHERE local_path LIKE 'sharename:path/to/folder/%';"
```

## Connection Issues

### SMB Connection Problems

#### Authentication Issues
```bash
# Test connection to a specific share
./s3backup.sh --test-connection

# Check if smbclient can access the share directly
smbclient //server/share -U username%password -W domain -c "ls"
```

#### Connection Method Troubleshooting
The tool attempts multiple connection methods in this order:
1. NTLM v2 over TCP/IP (port 445)
2. NTLM v2 over NetBIOS (port 139)
3. NTLM v1 over TCP/IP (port 445)
4. NTLM v1 over NetBIOS (port 139)

For Windows 10/11 compatibility:
- Check if SMB1 is disabled (common in newer Windows versions)
- Try enabling guest access if appropriate
- Use domain authentication when possible

### AWS Connection Issues

```bash
# Test AWS credentials and bucket access
aws s3 ls s3://your-bucket-name/

# Check connection to S3 endpoint
ping s3.amazonaws.com

# Verify IAM permissions (should see the policy attachment)
aws iam list-attached-user-policies --user-name your-iam-user
```

## Database Issues

### Database Integrity and Maintenance

```bash
# Make a backup before any operations
cp backup_index.db backup_index.db.bak

# Check database integrity
sqlite3 backup_index.db "PRAGMA integrity_check;"

# Perform maintenance
sqlite3 backup_index.db "VACUUM;"
sqlite3 backup_index.db "PRAGMA optimize;"

# Remove database locks (if tool crashed)
fuser -v backup_index.db
kill -9 [PID]  # Replace [PID] with process ID from previous command
```

### Database Corruption Recovery

If your database becomes corrupted beyond repair:

```bash
# Rename corrupted database
mv backup_index.db backup_index.db.corrupted

# Create new database
./s3backup.sh --initialize

# Synchronize with existing S3 data
./s3backup.sh --sync-index-with-aws
```

### Database Performance Optimization

For large backup sets:

```bash
# Create indexes for better performance
sqlite3 backup_index.db << EOF
CREATE INDEX IF NOT EXISTS idx_checksum ON files (checksum, is_deleted);
CREATE INDEX IF NOT EXISTS idx_local_path_deleted ON files (local_path, is_deleted);
ANALYZE;
EOF

# Check database size and statistics
du -h backup_index.db
sqlite3 backup_index.db "SELECT COUNT(*) FROM files;"
sqlite3 backup_index.db "SELECT COUNT(*) FROM files WHERE is_deleted=0;"
```

## Storage Class Issues

If you're experiencing incorrect storage classes:

```bash
# Check S3 objects' current storage class
aws s3api list-objects-v2 --bucket your-bucket-name --prefix your-prefix --query 'Contents[].{Key: Key, StorageClass: StorageClass}' --output table

# Verify config.ini storage_class setting
grep storage_class config.ini

# Force re-upload with new storage class (after updating config.ini)
sqlite3 backup_index.db "UPDATE files SET last_modified = '2000-01-01T00:00:00';"
```

## Performance Issues

### Slow Backups

```bash
# Increase thread count in config.ini
# Edit the file and set higher thread_count:
# thread_count = 8

# Monitor network usage during backup
iftop  # Install with: apt install iftop

# Check CPU and memory usage
htop   # Install with: apt install htop

# Look for bottlenecks in the logs
grep "time:" s3_backup.log | tail -20
```

### Memory Issues

If the tool is using too much memory:

```bash
# Check memory usage
ps aux | grep s3_backup

# Reduce thread count in config.ini
# thread_count = 2

# Monitor memory usage during backup
watch -n 1 "ps aux | grep s3_backup"
```

## Log Analysis

```bash
# View recent errors
grep ERROR s3_backup.log | tail -50

# Look for specific error patterns
grep "timeout" s3_backup.log
grep "connection" s3_backup.log

# Check for S3 errors
grep "S3Error" s3_backup.log

# Monitor logs in real-time during backup
tail -f s3_backup.log
```

## Disk Space Issues

```bash
# Check available disk space
df -h

# Identify large temporary files
find /tmp -type f -size +100M | sort -k5 -n

# Clean up temporary files
find /tmp -name "s3backup_*" -mtime +1 -delete

# Check database size
du -h backup_index.db

# Archive old reports to save space
tar -czf old_reports.tar.gz reports/* --remove-files
```

## Index Synchronization Issues

If `--sync-index-with-aws` fails or is incomplete:

```bash
# Check synchronization logs
grep "sync" s3_backup.log

# Force a fresh sync (backup database first)
cp backup_index.db backup_index.db.bak
rm backup_index.db
./s3backup.sh --initialize
./s3backup.sh --sync-index-with-aws
```

## Email Notification Issues

```bash
# Test email configuration
echo "Test" | mail -s "Test Email" admin@example.com

# Check local mail transport agent
systemctl status postfix  # Or your mail transport agent

# Enable verbose logging in the tool (edit source code)
# Change logging.INFO to logging.DEBUG in s3_backup.py
```

## Common Error Solutions

### "Access Denied" Errors
- Verify share permissions on Windows server
- Check username/password in config.ini
- Try with domain prefix for username (DOMAIN\\username)

### "Connection Timeout" Errors
- Check network connectivity between servers
- Verify firewall rules allow SMB traffic
- Try different connection parameters

### "Database is locked" Errors
- Kill any zombie backup processes
- Check for other tools accessing the database
- Restore from backup if corruption persists

### "S3 Access Denied" Errors
- Verify IAM permissions
- Check bucket policy for restrictions
- Ensure bucket name is correct in config.ini

### "Storage Class Not Supported" Errors
- Verify storage class setting in config.ini
- Not all S3-compatible services support all storage classes
- Try STANDARD storage class as a fallback
