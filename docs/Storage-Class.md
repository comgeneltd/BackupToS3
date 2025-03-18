# S3 Storage Class Configuration

The S3 Windows Share Backup Tool now supports configurable storage classes for Amazon S3 through the `config.ini` file.

## Configuration

In your `config.ini` file, add a `storage_class` parameter to the `[AWS]` section:

```ini
[AWS]
access_key = YOUR_AWS_ACCESS_KEY
secret_key = YOUR_AWS_SECRET_KEY
region = us-east-1
bucket = your-bucket-name
prefix = 
storage_class = STANDARD_IA
```

## Available Storage Classes

You can use any of the following S3 storage classes:

| Storage Class | Description | Use Case |
|---------------|-------------|----------|
| `STANDARD` | Default S3 storage | Frequently accessed data |
| `STANDARD_IA` | Standard Infrequent Access | Long-lived, infrequently accessed data |
| `ONEZONE_IA` | One Zone Infrequent Access | Long-lived, infrequently accessed, non-critical data |
| `INTELLIGENT_TIERING` | S3 Intelligent-Tiering | Data with unknown or changing access patterns |
| `GLACIER` | S3 Glacier | Long-term archival with retrieval times of minutes to hours |
| `DEEP_ARCHIVE` | S3 Glacier Deep Archive | Long-term archival with retrieval times of hours |
| `GLACIER_IR` | S3 Glacier Instant Retrieval | Long-lived archive data that needs immediate access |

## Cost Considerations

Different storage classes have different pricing for:
- Storage per GB
- Request pricing
- Retrieval fees
- Minimum storage duration
- Minimum billable object size

Refer to [AWS S3 pricing](https://aws.amazon.com/s3/pricing/) for the most up-to-date information.

## Examples

### Deep Archive for Long-Term Backup

```ini
[AWS]
access_key = YOUR_AWS_ACCESS_KEY
secret_key = YOUR_AWS_SECRET_KEY
region = us-east-1
bucket = your-archive-bucket
prefix = 
storage_class = DEEP_ARCHIVE
```

### Intelligent Tiering for Mixed Access Patterns

```ini
[AWS]
access_key = YOUR_AWS_ACCESS_KEY
secret_key = YOUR_AWS_SECRET_KEY
region = us-east-1
bucket = your-bucket
prefix = 
storage_class = INTELLIGENT_TIERING
```

## Changing Storage Class

If you change the storage class in your configuration, it will only affect new uploads and copies. Existing files in S3 will remain in their current storage class unless they are re-uploaded or moved.
