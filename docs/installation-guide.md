# BackupToS3 Installation Guide

## Prerequisites

Before installing the S3 Windows Share Backup Tool, ensure your system meets the following requirements:

* **Operating System**: Linux (Ubuntu/Debian recommended)
* **Python**: Version 3.6 or higher
* **Memory**: 8GB recommended (minimum 4GB)
* **Storage**: At least 50GB free space for the database and temporary files
* **Network**: High-speed connection to both Windows shares and AWS

## Required Linux Packages

Install these system dependencies:

```bash
# For Debian/Ubuntu
sudo apt update
sudo apt install -y python3 python3-pip python3-venv smbclient libsmbclient-dev build-essential

# For Red Hat/CentOS
sudo yum install -y python3 python3-pip python3-devel samba-client-libs samba-client
```

## Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/comgeneltd/BackupToS3.git
   ```

2. Navigate to the project directory:
   ```bash
   cd BackupToS3
   ```

3. Set up virtual environment:
   ```bash
   # Create a virtual environment
   python3 -m venv s3backup_env
   
   # Activate the virtual environment
   source s3backup_env/bin/activate
   ```

4. Install required Python packages:
   ```bash
   pip install boto3 pysmb pandas schedule configparser cryptography
   ```

5. Create a wrapper script for convenience:
   ```bash
   cat > s3backup.sh << 'EOF'
   #!/bin/bash
   source "$PWD/s3backup_env/bin/activate"
   python "$PWD/s3_backup.py" "$@"
   deactivate
   EOF

   chmod +x s3backup.sh
   # Deactivate the virtual environment after setup
   deactivate
   ```

6. Create a default configuration:
   ```bash
   ./s3backup.sh --create-config
   ```

7. Edit the configuration file with your settings:
   ```bash
   vi config.ini
   ```

## AWS Requirements

1. **S3 Bucket**: You must have an existing S3 bucket
2. **IAM User/Role**: With the following permissions:
   - s3:PutObject
   - s3:GetObject
   - s3:DeleteObject
   - s3:ListBucket
   - s3:CopyObject

3. **Access Keys**: AWS access key and secret key

### IAM Policy Example

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::your-bucket-name"
            ]
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:PutObject",
                "s3:DeleteObject",
                "s3:CopyObject"
            ],
            "Resource": [
                "arn:aws:s3:::your-bucket-name/*"
            ]
        }
    ]
}
```

## Verifying Installation

Test your connection to Windows shares:

```bash
./s3backup.sh --test-connection
```

If everything is set up correctly, you should see successful connection messages for each of your configured shares.

## Next Steps

After installation, refer to the Usage Guide for instructions on configuring and running backups.
