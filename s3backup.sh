#!/bin/bash
# Use absolute path to virtual environment
source "/home/shared/BackupToS3/s3backup_env/bin/activate" || {
  echo "Warning: Failed to activate virtual environment, using system Python"
}

# Use absolute path to Python script
cd "/home/shared/BackupToS3" && python "s3_backup.py" "$@"

# Try to deactivate if active
type deactivate >/dev/null 2>&1 && deactivate
