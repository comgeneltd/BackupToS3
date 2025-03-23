# S3 Windows Share Sync Tool

A tool for automatic uploading files from Windows shares to S3 storage with local indexing.

Compared to AWS DataSync:
1. Zero transfer fees.
2. No S3 List/Get API calls on each job execution
3. Simple and fast install anywhere
    

## Features

- Automatic sync of Windows SMB/CIFS shares to Amazon S3
- Local SQLite database for tracking file changes
- Duplicate files detection by using checksum comparison
- Support for encrypted configuration to protect credentials
- Scheduling capabilities for automated jobs
- Detailed reports and logging
- Intelligent multipart uploads for large files (threshold adjustable in config)
    Intelligent part sizing based on file size 
    Parallel part uploads for improved throughput
- Optimized handling of large files with smart checksumming
    Tiered checksum strategy based on file size:
        Large files (>500MB): Uses partial sampling (beginning, middle, end)
        Medium files (50MB-500MB): Uses parallel checksumming
        Small files (<50MB): Uses standard checksumming
- Checksum calculation with automatic retries and connection recovery
- Configurable concurrency settings for improved performance


## Documentation

- [Prerequisites](docs/prerequisites.md)
- [Installation](docs/installation-guide.md)
- [Usage Guide](docs/usage-guide.md)
- [Email notifications](docs/Email-config-documentation.md)
- [Troubleshooting](docs/troubleshooting-guide.md)
- [Storage Class](docs/Storage-Class.md)
- [Multipart upload](docs/multipart-upload.md)
- [Checksum Configuration Parameters](docs/checksum-config.md)



## Quick Start

See the [Usage Guide](docs/USAGE.md) for detailed instructions.

## License

GNU General Public License v3.0
