# Checksum Configuration Parameters

The S3 Windows Share Backup Tool now supports advanced checksum configuration to optimize performance for different file sizes and improve reliability. Add these settings to the `[General]` section of your `config.ini` file:

```ini
[General]
# Existing settings...
large_file_threshold = 1073741824     # 1GB in bytes
checksum_parallel_threshold = 104857600  # 100MB in bytes
checksum_parallel_processes = 4        # Number of processes for parallel checksumming
use_xxhash = false                    # Whether to use xxHash instead of MD5
checksum_retry_count = 3              # Number of retry attempts for failed checksums
```

## Parameter Details

| Parameter | Description | Default | Min | Max | Recommended |
|-----------|-------------|---------|-----|-----|------------|
| `large_file_threshold` | File size in bytes above which optimized large file checksum methods are used | 1073741824 (1GB) | 52428800 (50MB) | No limit | 1GB for most environments |
| `checksum_parallel_threshold` | File size in bytes above which parallel processing is used for checksums | 104857600 (100MB) | 10485760 (10MB) | Should be less than large_file_threshold | 100MB for most environments |
| `checksum_parallel_processes` | Number of processes to use for parallel checksum calculation | 4 | 1 | CPU core count | 4 for quad-core, half of available cores for higher-end systems |
| `use_xxhash` | Whether to use xxHash algorithm (faster) instead of MD5 (more compatible) | false | - | - | false for compatibility, true for performance |
| `checksum_retry_count` | Number of times to retry checksum calculation if file not found or other errors | 3 | 0 | 5 | 3 for most environments |

## Performance Impact

These parameters significantly impact performance for different file types:

### Large Files (>1GB)
- For a 4GB ISO file, standard checksumming can take 120+ seconds
- With optimized settings, the same operation may complete in 40-60 seconds

### Medium Files (100MB-1GB)
- Can benefit from parallel processing (30-50% speedup)
- Not large enough to require specialized large file handling

### Small Files (<100MB)
- Standard checksum methods work efficiently
- No need for parallel processing or specialized handling

## Algorithm Choice: MD5 vs xxHash

The `use_xxhash` parameter lets you choose between:

- **MD5** (Default, `use_xxhash = false`):
  - Industry-standard algorithm
  - Compatible with existing backups
  - Well-understood security properties
  - Slower performance

- **xxHash** (`use_xxhash = true`):
  - 5-10x faster than MD5
  - Excellent collision resistance
  - Less widely used in backup systems
  - Not compatible with previous MD5-based backups

**IMPORTANT**: Changing from MD5 to xxHash will cause all files to be treated as new/changed during the next backup!

## Error Handling & Resilience

The `checksum_retry_count` parameter helps manage intermittent SMB/network issues:

- When set to 0: Fails immediately if a file can't be accessed
- When set to 3 (default): Makes three total attempts before failing
- Each retry includes a connection check and potential reconnection

## Example Configurations

### Performance-Optimized (Large Files)
```ini
[General]
large_file_threshold = 536870912      # 512MB
checksum_parallel_threshold = 52428800  # 50MB
checksum_parallel_processes = 8        # For 8+ core systems
use_xxhash = true
checksum_retry_count = 2
```

### Balanced (Default)
```ini
[General]
large_file_threshold = 1073741824     # 1GB
checksum_parallel_threshold = 104857600  # 100MB
checksum_parallel_processes = 4
use_xxhash = false
checksum_retry_count = 3
```

### Resource-Constrained
```ini
[General]
large_file_threshold = 2147483648     # 2GB
checksum_parallel_threshold = 268435456  # 256MB
checksum_parallel_processes = 2
use_xxhash = true
checksum_retry_count = 1
```

## Implementation Notes

- When changing `use_xxhash` from false to true, the first backup after the change will re-upload all files
- The `checksum_parallel_processes` should not exceed your system's CPU core count for optimal performance
- For systems with limited RAM, reduce `checksum_parallel_processes` to prevent memory exhaustion
