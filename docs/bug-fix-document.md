# File Identification Bug Fix

## Issue Description

There's currently a bug in the backup logic where the tool treats multiple copies of a file as the same file and doesn't upload them separately if they have the same content (hash). This causes problems when you have:

1. Multiple copies of the same file in different locations
2. Files with identical content but different names or purposes
3. Moved files that should actually be treated as new files if the original still exists

## Root Cause

The issue is in the file detection logic where the tool is primarily using the file checksum (hash) to identify files, without properly considering the file name and whether the original file still exists.

## Fix Implementation

The fix requires modifying the `scan_shares` method in the `BackupManager` class, specifically the file move/rename detection logic. Here's how to update the code:

### 1. Modify the ShareScanner class detection logic

In `s3_backup.py`, locate the `scan_directory` method in the `ShareScanner` class and update it to include filename in the tracking information:

```python
# Add file_name to the yield dictionary 
yield {
    'local_path': local_path,
    'share_path': full_path,
    'size': file_info.file_size,
    'last_modified': last_modified,
    'checksum': checksum,
    'share_config': self.share_config,
    'file_name': file_name  # Add filename for proper comparison
}
```

### 2. Update the DatabaseManager class

Modify the `add_file` method in the `DatabaseManager` class to store the filename:

```python
def add_file(self, local_path, s3_path, size, last_modified, checksum, previous_path=None, moved_in_s3=0, file_name=None):
    """Add or update a file in the index."""
    try:
        with self.lock:
            conn = self.get_connection()
            cursor = conn.cursor()
            now = datetime.datetime.now()
            
            # Add file_name parameter to the SQL
            cursor.execute('''
            INSERT INTO files (local_path, s3_path, size, last_modified, checksum, last_backup, previous_path, moved_in_s3, file_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(local_path) DO UPDATE SET
                s3_path=excluded.s3_path,
                size=excluded.size,
                last_modified=excluded.last_modified,
                checksum=excluded.checksum,
                is_deleted=0,
                last_backup=excluded.last_backup,
                previous_path=excluded.previous_path,
                moved_in_s3=excluded.moved_in_s3,
                file_name=excluded.file_name
            ''', (local_path, s3_path, size, last_modified, checksum, now, previous_path, moved_in_s3, file_name))
            
            conn.commit()
            return True
    except sqlite3.Error as e:
        logger.error(f"Error adding file to database: {str(e)}")
        return False
```

### 3. Update the Database Schema

You'll need to modify the database schema to include the file_name column:

```python
def initialize_db(self):
    """Initialize the database and create tables if they don't exist."""
    try:
        with self.lock:
            self.conn = sqlite3.connect(self.db_path)
            cursor = self.conn.cursor()
            
            # Add file_name column to files table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY,
                local_path TEXT NOT NULL,
                s3_path TEXT NOT NULL,
                size INTEGER NOT NULL,
                last_modified TIMESTAMP NOT NULL,
                checksum TEXT NOT NULL,
                is_deleted INTEGER DEFAULT 0,
                last_backup TIMESTAMP,
                previous_path TEXT,
                moved_in_s3 INTEGER DEFAULT 0,
                file_name TEXT,
                UNIQUE(local_path)
            )
            ''')
            
            # Create index on file_name for faster lookups
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_name ON files (file_name)')
            
            # Check if file_name column exists (for backward compatibility)
            cursor.execute("PRAGMA table_info(files)")
            columns = [column[1] for column in cursor.fetchall()]
            
            # If file_name column is missing, add it
            if 'file_name' not in columns:
                try:
                    logger.info("Adding file_name column to files table")
                    cursor.execute("ALTER TABLE files ADD COLUMN file_name TEXT")
                    # Initialize file_name with basename from local_path
                    cursor.execute("""
                    UPDATE files SET file_name = 
                    SUBSTR(local_path, INSTR(local_path, ':') + 1, 
                    LENGTH(local_path) - INSTR(local_path, ':'))
                    """)
                    logger.info(f"Updated {cursor.rowcount} existing files with file_name")
                    self.conn.commit()
                except sqlite3.Error as e:
                    logger.error(f"Error adding file_name column: {str(e)}")
            
            self.conn.commit()
            logger.info("Database initialized successfully")
    except sqlite3.Error as e:
        logger.error(f"Database initialization error: {str(e)}")
        with self.lock:
            if self.conn:
                self.conn.close()
                self.conn = None
        raise
```

### 4. Fix the scan_shares method in BackupManager

Modify the move/rename detection logic in the `scan_shares` method to properly check:
1. If a file exists in its previous location
2. If a file has the same name as the potentially moved file

```python
# In BackupManager.scan_shares method, update the "moved file" detection logic:

# If file not found at this path, check if it exists elsewhere by checksum (moved)
if not existing_file:
    checksum_match = self.db_manager.get_file_by_checksum(file_info['checksum'])
    
    if checksum_match:
        # Get original file name and new file name
        old_path = checksum_match[1]
        old_name = os.path.basename(old_path.split(':', 1)[1] if ':' in old_path else old_path)
        new_name = os.path.basename(file_info['share_path'])
        
        # Check if file with same path still exists in original location
        old_file_exists = False
        
        # Extract share name and path from old_path
        old_path_parts = old_path.split(':', 1)
        if len(old_path_parts) == 2:
            old_share_name, old_file_path = old_path_parts
            
            # Find matching share config
            old_share_config = None
            for share in self.config.shares:
                if share['local_name'] == old_share_name:
                    old_share_config = share
                    break
            
            if old_share_config:
                # Check if file exists in original location
                old_scanner = ShareScanner(old_share_config, self.db_manager)
                try:
                    if old_scanner.connect():
                        try:
                            old_scanner.conn.getAttributes(old_share_config['name'], old_file_path)
                            old_file_exists = True
                        except:
                            old_file_exists = False
                finally:
                    old_scanner.disconnect()
        
        # Only consider it a move/rename if:
        # 1. The file no longer exists in the old location, AND
        # 2. The filename matches the old filename
        if not old_file_exists and old_name == new_name:
            # This is likely a moved file - update S3 to match
            # [existing move logic here]
            logger.info(f"Detected moved file: {old_path} -> {file_info['local_path']}")
            # Rest of your existing move handling code...
        else:
            # This is a new file that happens to have the same content
            # Treat as a new file and upload it
            files_changed += 1
            yield file_info, s3_key
```

## Testing the Fix

After implementing these changes, you should test the fix thoroughly by:

1. Creating multiple copies of the same file in different locations on a Windows share
2. Moving a file to a new location while keeping the original (should be treated as a duplicate)
3. Moving a file to a new location after deleting the original (should be treated as a move)
4. Creating files with different names but identical content

Run a backup with verbose logging to verify that the tool correctly identifies and handles each case.

## Implementation Notes

1. This fix introduces a database schema change, so be sure to back up your database before applying it.
2. The code adds a new column to track filenames explicitly, which provides more robust file identification.
3. The move detection logic now correctly checks if the original file still exists before considering it a move.
4. Files with identical content but different names or locations will now be properly treated as separate files.

If you have a large existing database, consider running a script to properly populate the file_name field for existing records before using the updated tool.
