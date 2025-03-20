# S3 Windows Share Sync Tool

A tool for automatic uploading files from Windows shares to S3 storage with local indexing.
Compared to AWS DataSync:
    1. Zero transfer fees.
    2. No API calls to list whole S3 on each job execution
    3. Simple and fast install on your device.

## Features

- Automatic sync of Windows SMB/CIFS shares to Amazon S3
- Local SQLite database for tracking file changes
- Duplicate files detection by using checksum comparison
- Support for encrypted configuration to protect credentials
- Scheduling capabilities for automated jobs
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
