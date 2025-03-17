# S3 Windows Share Backup Tool

A tool for backing up Windows shares to S3 storage with local indexing and AWS synchronization capabilities.

## Features

- Automatic backup of Windows SMB/CIFS shares to Amazon S3
- AWS synchronization for migrating from existing backup solutions
- Local SQLite database for tracking file changes
- Deduplication of files using checksum comparison
- Support for encrypted configuration to protect credentials
- Tracking of renamed and moved files for efficient S3 operations
- Detailed reporting and logging

## Key Features

### Windows Share Backup
- Connect to SMB/CIFS shares with various authentication methods
- Handle guest access and domain/workgroup configurations
- Efficiently detect file changes using size and modification time

### AWS S3 Integration
- Upload files to S3 Standard-IA storage
- Track file history and changes in local database
- Detect file moves and renames to avoid unnecessary uploads
- Synchronize with existing S3 files when migrating from another solution

### Reporting and Management
- Generate detailed backup reports
- Track deleted files
- Generate S3 deletion scripts for cleanup
- Export index to CSV for analysis

## Installation

See [Prerequisites](PREREQUISITES.md) for system requirements and dependencies.

## Usage

See the [Usage Guide](USAGE.md) for detailed instructions on setting up and using the tool.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/your-username/s3-windows-share-backup.git
cd BackupToS3

# Set up Python environment
python3 -m venv s3backup_env
source s3backup_env/bin/activate
pip install -r requirements.txt

# Create a configuration file
python s3_backup.py --create-config

# Edit the configuration with your details
vi config.ini

# Test connections to shares
python s3_backup.py --test-connection

# If migrating from an existing backup solution
python s3_backup.py --sync-index-with-aws

# Otherwise, initialize a fresh index
python s3_backup.py --initialize

# Run your first backup
python s3_backup.py --run-now
```

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
