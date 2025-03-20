# Multipart Upload Configuration

The S3 Windows Share Backup Tool now supports intelligent multipart uploads for large files, significantly improving performance and reliability when backing up larger files.

## How It Works

Files larger than the configured threshold will automatically be split into multiple parts and uploaded in parallel. This provides several benefits:

1. **Improved throughput**: Multiple parts upload simultaneously
2. **Better reliability**: Failed parts can be retried individually
3. **Resumable uploads**: Compatible with S3's resumable upload capabilities
4. **Efficient use of bandwidth**: Parallel connections utilize available bandwidth better

## Configuration Options

Add these settings to the `[General]` section of your `config.ini` file:

```ini
[General]
# Existing settings...
multipart_threshold = 8388608  # 8MB in bytes
multipart_max_concurrent = 4   # Maximum concurrent part uploads
```

### Parameters Explained

| Parameter | Description | Default | Min | Max | Recommended |
|-----------|-------------|---------|-----|-----|------------|
| `multipart_threshold` | File size in bytes above which multipart uploads are used | 8388608 (8MB) | 5242880 (5MB) | - | 8MB for most cases |
| `multipart_max_concurrent` | Number of parts to upload simultaneously for each file | 4 | 1 | 16 | 4-8 depending on bandwidth |

### Part Size Calculation

The tool automatically determines optimal part sizes based on file size:
- Each file can have a maximum of 10,000 parts (S3 limitation)
- Minimum part size is 5MB (S3 requirement)
- For very large files, larger part sizes are used automatically:
  - Files >10GB: 100MB+ part size
  - Files >1GB: 50MB+ part size

## Performance Considerations

### Network Bandwidth

Higher concurrency values will consume more bandwidth. For optimal performance:

- On high-speed connections (1Gbps+): Use higher concurrency values
- On slower connections: Reduce concurrency to avoid saturating the link

### System Resources

Multipart uploads consume additional system resources:

- Memory: Each concurrent part upload requires memory proportional to part size
- CPU: Additional processing for managing concurrent uploads
- Disk I/O: Multiple parts may be read simultaneously

### Example Configurations

#### High-Performance Environment
```ini
[General]
thread_count = 16
multipart_max_concurrent = 8
multipart_threshold = 8388608  # 8MB
```

#### Balanced Environment
```ini
[General]
thread_count = 8
multipart_max_concurrent = 4
multipart_threshold = 8388608  # 8MB
```

#### Resource-Constrained Environment
```ini
[General]
thread_count = 4
multipart_max_concurrent = 2
multipart_threshold = 16777216  # 16MB
```

## Logging and Monitoring

When multipart uploads are active, additional log entries will be generated:

- Initiation of multipart uploads
- Completion of individual parts
- Completion of entire multipart uploads
- Any failures during the process

## Troubleshooting

If experiencing issues with multipart uploads:

1. **Memory errors**: Reduce `multipart_max_concurrent` or increase part size by increasing `multipart_threshold`
2. **Slow performance**: Check network bandwidth and increase concurrency if not saturated
3. **Failed uploads**: Check AWS credentials and S3 bucket permissions

The tool will automatically abort failed multipart uploads to prevent incomplete uploads from lingering in your S3 bucket.
