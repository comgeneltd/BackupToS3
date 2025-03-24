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


## AWS Requirements

1. **S3 Bucket**: You must have an existing S3 bucket
2. **IAM User/Role**: With the following permissions:
   - s3:PutObject
   - s3:GetObject
   - s3:DeleteObject
   - s3:ListBucket
   - s3:CopyObject

3. **Access Keys**: AWS access key and secret key

### IAM Policy for AWS Sync Functionality

When using the AWS sync functionality to synchronize your index with existing S3 files, your IAM user/role must have sufficient permissions. Here's a recommended policy:

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

Replace `your-bucket-name` with your actual S3 bucket name. The `s3:ListBucket` permission is particularly important for the AWS sync functionality as it needs to list objects in your bucket.

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

## Index Synchronization Considerations

When using the `--sync-index-with-aws` functionality:

* **Memory Usage**: The synchronization process builds an in-memory dictionary of S3 files. For very large buckets (millions of files), ensure you have sufficient RAM (8GB or more).
* **Network Bandwidth**: Initial synchronization requires listing all objects in your S3 bucket, which may take time depending on your connection speed and bucket size.
* **Time Requirements**: For large buckets and many shares, the initial synchronization can take several hours.
