# Prerequisites for S3 Windows Share Backup Tool

## System Requirements

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

## Required Python Packages

The following Python packages are needed:

```bash
# Create and activate virtual environment
python3 -m venv s3backup_env
source s3backup_env/bin/activate

# Install dependencies
pip install boto3 pysmb pandas schedule configparser cryptography

deactivate
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

## Network Access

1. **Windows Shares**:
   - Access to SMB/CIFS shares (ports 139 and 445)
   - Valid credentials for the Windows shares
   - Firewall rules allowing connections from the Linux server

2. **AWS S3**:
   - Outbound internet access to S3 endpoints

## Storage Considerations

* **Database Size**: For large backups (>1TB), the SQLite database can grow to several GB
* **Temp Storage**: Temporary space is needed during file uploads (equal to the largest file size)
* **SSD Recommended**: For better performance with database operations
