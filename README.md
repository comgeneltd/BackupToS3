# S3 Windows Share Backup Tool

A tool for backing up Windows shares to S3 storage with local indexing.

## Features

- Automatic backup of Windows SMB/CIFS shares to Amazon S3
- Local SQLite database for tracking file changes
- Deduplication of files using checksum comparison
- Support for encrypted configuration to protect credentials
- Scheduling capabilities for automated backups
- Verification of backups to ensure data integrity
- Detailed reports and logging
- Intelligent multipart uploads for large files
- Configurable concurrency settings for improved performance

## Documentation

- [Prerequisites](docs/prerequisites.md)
- [Installation](docs/installation-guide.md)
- [Usage Guide](docs/usage-guide.md)
- [Email notifications](docs/Email-config-documentation.md)
- [Troubleshooting](docs/troubleshooting-guide.md)
- [Storage Class](docs/Storage-Class.md)
- [Multipart upload](docs/multipart-upload.md)



## Quick Start

See the [Usage Guide](docs/USAGE.md) for detailed instructions.

## License

GNU General Public License v3.0
