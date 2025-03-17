#!/usr/bin/env python3
"""
S3 Windows Share Backup Tool
A tool for backing up Windows shares to S3 storage with local indexing.
"""

import os
import sys
import argparse
import logging
import datetime
import hashlib
import sqlite3
import csv
import time
import configparser
import base64
import getpass
import smtplib
from email.message import EmailMessage
from io import StringIO
from pathlib import Path
import boto3
import botocore
from smb.SMBConnection import SMBConnection
import pandas as pd
import schedule
import threading
from concurrent.futures import ThreadPoolExecutor

# For config encryption
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('s3_backup.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('s3_backup')

# Global configuration
CONFIG_FILE = 'config.ini'
CONFIG_SALT_FILE = '.config.salt'  # File to store the salt

def derive_key(password, salt=None):
    """Derive an encryption key from a password."""
    if salt is None:
        # Generate a new salt if one isn't provided
        salt = os.urandom(16)
        
    # Create a key derivation function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    
    # Derive the key
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def encrypt_config(config_data, password):
    """Encrypt configuration data with the given password."""
    # Derive a key from the password
    key, salt = derive_key(password)
    
    # Create an encryption object
    fernet = Fernet(key)
    
    # Encrypt the data
    encrypted_data = fernet.encrypt(config_data.encode())
    
    return encrypted_data, salt

def decrypt_config(encrypted_data, password, salt):
    """Decrypt configuration data with the given password and salt."""
    # Derive the key using the same salt
    key, _ = derive_key(password, salt)
    
    # Create a decryption object
    fernet = Fernet(key)
    
    # Decrypt the data
    try:
        decrypted_data = fernet.decrypt(encrypted_data).decode()
        return decrypted_data, True
    except Exception as e:
        logger.error(f"Decryption failed: {str(e)}")
        return None, False

def is_encrypted(file_path):
    """Check if a file appears to be encrypted."""
    try:
        with open(file_path, 'rb') as f:
            data = f.read(10)  # Read first few bytes
            # Encrypted data will be base64-encoded and start with 'g' typically
            return data.startswith(b'g') and all(c in b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=' for c in data)
    except:
        return False


class Config:
    """Configuration manager for the backup tool."""
    
    def __init__(self, config_file=CONFIG_FILE, password=None):
        self.config_file = config_file
        self.config = configparser.ConfigParser()
        self.password = password
        self.salt = None
        self.encrypted = False
        
        # Try to load salt if it exists
        salt_file = os.path.join(os.path.dirname(config_file), CONFIG_SALT_FILE)
        if os.path.exists(salt_file):
            try:
                with open(salt_file, 'rb') as f:
                    self.salt = f.read()
            except Exception as e:
                logger.error(f"Error reading salt file: {str(e)}")
        
        # Default values
        self.aws_access_key = ''
        self.aws_secret_key = ''
        self.aws_region = 'us-east-1'
        self.s3_bucket = ''
        self.s3_prefix = ''  # No prefix by default
        self.storage_class = 'STANDARD_IA'  # Default storage class
        self.db_path = 'backup_index.db'
        self.report_path = 'reports/'
        self.shares = []
        self.scan_interval = 24  # hours
        self.thread_count = 4
        
        # Email notification defaults
        self.email_enabled = False
        self.email_smtp_server = 'localhost'
        self.email_smtp_port = 25
        self.email_from = ''
        self.email_to = ''
        self.email_subject_prefix = '[S3 Backup]'
        
        self.load_config()
    
    def load_config(self):
        """Load configuration from file."""
        if not os.path.exists(self.config_file):
            logger.warning(f"Config file {self.config_file} not found. Using defaults.")
            return
            
        # Set log level to DEBUG for more detailed connection information
        logger.setLevel(logging.DEBUG)
        
        # Check if the file appears to be encrypted
        self.encrypted = is_encrypted(self.config_file)
        
        try:
            if self.encrypted:
                # Verify we have a password
                if not self.password:
                    logger.error("Config file appears to be encrypted but no password was provided.")
                    raise ValueError("Password required for encrypted config file")
                
                # Verify we have a salt
                if not self.salt:
                    logger.error("Config file is encrypted but no salt file was found.")
                    raise ValueError("Salt file missing for encrypted config")
                
                # Read the encrypted data
                with open(self.config_file, 'rb') as f:
                    encrypted_data = f.read()
                
                # Decrypt the data
                config_data, success = decrypt_config(encrypted_data, self.password, self.salt)
                if not success:
                    raise ValueError("Failed to decrypt configuration with provided password")
                
                # Parse the decrypted data
                self.config.read_string(config_data)
                logger.info("Successfully decrypted and loaded configuration")
            else:
                # Just read the file normally
                self.config.read(self.config_file)
            
            # AWS Settings
            if 'AWS' in self.config:
                self.aws_access_key = self.config['AWS'].get('access_key', '')
                self.aws_secret_key = self.config['AWS'].get('secret_key', '')
                self.aws_region = self.config['AWS'].get('region', 'us-east-1')
                self.s3_bucket = self.config['AWS'].get('bucket', '')
                self.s3_prefix = self.config['AWS'].get('prefix', '')
                self.storage_class = self.config['AWS'].get('storage_class', 'STANDARD_IA')
            
            # General Settings
            if 'General' in self.config:
                self.db_path = self.config['General'].get('db_path', 'backup_index.db')
                self.report_path = self.config['General'].get('report_path', 'reports/')
                self.scan_interval = int(self.config['General'].get('scan_interval', '24'))
                self.thread_count = int(self.config['General'].get('thread_count', '4'))
            
            # Email notification settings
            if 'Email' in self.config:
                self.email_enabled = self.config['Email'].getboolean('enabled', False)
                self.email_smtp_server = self.config['Email'].get('smtp_server', 'localhost')
                self.email_smtp_port = int(self.config['Email'].get('smtp_port', '25'))
                self.email_from = self.config['Email'].get('from', '')
                self.email_to = self.config['Email'].get('to', '')
                self.email_subject_prefix = self.config['Email'].get('subject_prefix', '[S3 Backup]')
            
            # Shares
            if 'Shares' in self.config:
                for key, value in self.config['Shares'].items():
                    # Use any key name, not just those starting with "share"
                    parts = value.split(',')
                    if len(parts) >= 4:
                        share = {
                            'server': parts[0].strip(),
                            'name': parts[1].strip(),
                            'username': parts[2].strip(),
                            'password': parts[3].strip(),
                            'domain': parts[4].strip() if len(parts) > 4 else '',
                            'local_name': key  # The key name in config becomes the S3 prefix for this share
                        }
                        self.shares.append(share)
            
            logger.info("Configuration loaded successfully")
        except Exception as e:
            logger.error(f"Error loading config: {str(e)}")
    
    def create_default_config(self, encrypt=False):
        """Create a default configuration file."""
        self.config['AWS'] = {
            'access_key': 'YOUR_ACCESS_KEY',
            'secret_key': 'YOUR_SECRET_KEY',
            'region': 'us-east-1',
            'bucket': 'your-bucket-name',
            'prefix': '',  # No prefix by default
            'storage_class': 'STANDARD_IA'  # Default to Standard-IA storage
        }
        
        self.config['General'] = {
            'db_path': 'backup_index.db',
            'report_path': 'reports/',
            'scan_interval': '24',
            'thread_count': '4'
        }
        
        self.config['Email'] = {
            'enabled': 'false',
            'smtp_server': 'localhost',
            'smtp_port': '25',
            'from': 'backup@example.com',
            'to': 'admin@example.com',
            'subject_prefix': '[S3 Backup]'
        }
        
        self.config['Shares'] = {
            'finance': 'server_ip,share_name,username,password,domain',
            'marketing': 'server_ip,share_name,username,password,domain',
            'guest_share': 'server_ip,share_name,guest,,',  # Example of guest/anonymous access
        }
        
        if encrypt and self.password:
            # Convert config to string
            config_io = StringIO()
            self.config.write(config_io)
            config_data = config_io.getvalue()
            
            # Encrypt the config data
            encrypted_data, salt = encrypt_config(config_data, self.password)
            
            # Write the encrypted data
            with open(self.config_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Save the salt to a separate file
            salt_file = os.path.join(os.path.dirname(self.config_file), CONFIG_SALT_FILE)
            with open(salt_file, 'wb') as f:
                f.write(salt)
            
            logger.info(f"Default encrypted configuration created at {self.config_file}")
            print(f"Created encrypted configuration at {self.config_file}")
        else:
            # Write unencrypted config
            with open(self.config_file, 'w') as f:
                self.config.write(f)
            
            logger.info(f"Default configuration created at {self.config_file}")
            
        print(f"""
Configuration file created at {self.config_file}.
Please edit it with your details. {'The file is encrypted for security.' if encrypt else ''}

For workgroup connections, here are some tips:
1. If using a local account, set the domain field to the workgroup name or leave empty
2. For guest/anonymous access, use 'guest' as username and leave password empty
3. Make sure the share name is exactly as it appears on the Windows system
4. The S3 prefix is empty by default, so objects will be stored as 'share_name/path/to/file'
5. You can use any name for your share in the config file (e.g., 'finance', 'marketing') - this name will be used as the prefix in S3
6. Test the connection first: python3 s3_backup.py --test-connection

For automated/scheduled operations with encrypted config:
- Create a password file: python3 s3_backup.py --create-password-file /path/to/.backup_password
- Use it in scheduled jobs: python3 s3_backup.py --run-now --password-file /path/to/.backup_password
- Or set an environment variable: export BACKUP_PASSWORD=your_password
  and use: python3 s3_backup.py --run-now --password-env BACKUP_PASSWORD
""")


class DatabaseManager:
    """Manager for the local index database."""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = None
        self.initialize_db()
    
    def initialize_db(self):
        """Initialize the database and create tables if they don't exist."""
        try:
            self.conn = sqlite3.connect(self.db_path)
            cursor = self.conn.cursor()
            
            # Create files table
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
                UNIQUE(local_path)
            )
            ''')
            
            # Create backup_runs table to track each backup operation
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS backup_runs (
                id INTEGER PRIMARY KEY,
                start_time TIMESTAMP NOT NULL,
                end_time TIMESTAMP,
                status TEXT,
                files_processed INTEGER DEFAULT 0,
                files_uploaded INTEGER DEFAULT 0,
                bytes_uploaded INTEGER DEFAULT 0,
                files_failed INTEGER DEFAULT 0
            )
            ''')
            
            # Index for faster lookups
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_local_path ON files (local_path)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_is_deleted ON files (is_deleted)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_checksum ON files (checksum)')  # Add index for checksum lookups
            
            # Check if moved_in_s3 column exists (for backward compatibility)
            cursor.execute("PRAGMA table_info(files)")
            columns = [column[1] for column in cursor.fetchall()]
            
            # If moved_in_s3 column is missing, add it and mark all files with a previous_path
            if 'moved_in_s3' not in columns:
                try:
                    logger.info("Adding moved_in_s3 column to files table")
                    cursor.execute("ALTER TABLE files ADD COLUMN moved_in_s3 INTEGER DEFAULT 0")
                    cursor.execute("UPDATE files SET moved_in_s3 = 1 WHERE previous_path IS NOT NULL")
                    logger.info(f"Marked {cursor.rowcount} existing moved files")
                    self.conn.commit()
                except sqlite3.Error as e:
                    logger.error(f"Error adding moved_in_s3 column: {str(e)}")
            
            self.conn.commit()
            logger.info("Database initialized successfully")
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {str(e)}")
            if self.conn:
                self.conn.close()
            raise
    
    def close(self):
        """Close the database connection."""
        if self.conn:
            self.conn.close()
    
    def add_file(self, local_path, s3_path, size, last_modified, checksum, previous_path=None, moved_in_s3=0):
        """Add or update a file in the index."""
        try:
            cursor = self.conn.cursor()
            now = datetime.datetime.now()
            
            cursor.execute('''
            INSERT INTO files (local_path, s3_path, size, last_modified, checksum, last_backup, previous_path, moved_in_s3)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(local_path) DO UPDATE SET
                s3_path=excluded.s3_path,
                size=excluded.size,
                last_modified=excluded.last_modified,
                checksum=excluded.checksum,
                is_deleted=0,
                last_backup=excluded.last_backup,
                previous_path=excluded.previous_path,
                moved_in_s3=excluded.moved_in_s3
            ''', (local_path, s3_path, size, last_modified, checksum, now, previous_path, moved_in_s3))
            
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error adding file to database: {str(e)}")
            return False
    
    def mark_deleted(self, local_path):
        """Mark a file as deleted in the local index."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
            UPDATE files SET is_deleted=1 WHERE local_path=?
            ''', (local_path,))
            self.conn.commit()
            return cursor.rowcount > 0
        except sqlite3.Error as e:
            logger.error(f"Error marking file as deleted: {str(e)}")
            return False
    
    def get_file_by_path(self, local_path):
        """Get file information by local path."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
            SELECT id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup
            FROM files WHERE local_path=?
            ''', (local_path,))
            return cursor.fetchone()
        except sqlite3.Error as e:
            logger.error(f"Error fetching file: {str(e)}")
            return None
    
    def get_file_by_checksum(self, checksum):
        """Get file information by checksum."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
            SELECT id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup
            FROM files WHERE checksum=? AND is_deleted=0 LIMIT 1
            ''', (checksum,))
            return cursor.fetchone()
        except sqlite3.Error as e:
            logger.error(f"Error fetching file by checksum: {str(e)}")
            return None
    
    def get_all_files(self, include_deleted=False):
        """Get all files from the index."""
        try:
            cursor = self.conn.cursor()
            if include_deleted:
                cursor.execute('''
                SELECT id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup
                FROM files
                ''')
            else:
                cursor.execute('''
                SELECT id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup
                FROM files WHERE is_deleted=0
                ''')
            return cursor.fetchall()
        except sqlite3.Error as e:
            logger.error(f"Error fetching files: {str(e)}")
            return []
    
    def get_deleted_files(self):
        """Get all files marked as deleted."""
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
            SELECT id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup
            FROM files WHERE is_deleted=1
            ''')
            return cursor.fetchall()
        except sqlite3.Error as e:
            logger.error(f"Error fetching deleted files: {str(e)}")
            return []
    
    def start_backup_run(self):
        """Start a new backup run and return its ID."""
        try:
            cursor = self.conn.cursor()
            now = datetime.datetime.now()
            cursor.execute('''
            INSERT INTO backup_runs (start_time, status)
            VALUES (?, 'RUNNING')
            ''', (now,))
            self.conn.commit()
            return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error starting backup run: {str(e)}")
            return None
    
    def finish_backup_run(self, run_id, status, files_processed, files_uploaded, bytes_uploaded, files_failed):
        """Mark a backup run as finished with statistics."""
        try:
            cursor = self.conn.cursor()
            now = datetime.datetime.now()
            cursor.execute('''
            UPDATE backup_runs SET
                end_time=?,
                status=?,
                files_processed=?,
                files_uploaded=?,
                bytes_uploaded=?,
                files_failed=?
            WHERE id=?
            ''', (now, status, files_processed, files_uploaded, bytes_uploaded, files_failed, run_id))
            self.conn.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error finishing backup run: {str(e)}")
            return False


class ShareScanner:
    """Scanner for Windows SMB shares."""
    
    def __init__(self, share_config, db_manager):
        self.share_config = share_config
        self.db_manager = db_manager
        self.conn = None
    
    def connect(self):
        """Establish a connection to the SMB share."""
        try:
            # In a workgroup environment, the domain field can be used for the workgroup name
            # or left empty depending on the server configuration
            workgroup = self.share_config['domain'] or 'WORKGROUP'
            client_name = 'BackupClient'
            server_name = self.share_config['server']
            
            # Handle guest/anonymous access
            is_guest = self.share_config['username'].lower() == 'guest'
            username = '' if is_guest else self.share_config['username']
            password = '' if is_guest else self.share_config['password']
            
            logger.debug(f"Attempting connection with: username={'<guest>' if is_guest else username}, "
                        f"server={server_name}, share={self.share_config['name']}, "
                        f"workgroup={workgroup}, client_name={client_name}")
            
            # Try with various connection parameters
            connection_methods = [
                # Method 1: Standard connection with NTLM v2
                {"use_ntlm_v2": True, "is_direct_tcp": True, "port": 445},
                # Method 2: Standard connection with NTLM v2 via NetBIOS
                {"use_ntlm_v2": True, "is_direct_tcp": False, "port": 139},
                # Method 3: Legacy connection with NTLM v1
                {"use_ntlm_v2": False, "is_direct_tcp": True, "port": 445},
                # Method 4: Legacy connection with NTLM v1 via NetBIOS
                {"use_ntlm_v2": False, "is_direct_tcp": False, "port": 139}
            ]
            
            # Try each connection method until one works
            for method in connection_methods:
                try:
                    logger.debug(f"Trying connection with: {method}")
                    self.conn = SMBConnection(
                        username,
                        password,
                        client_name,
                        server_name,
                        domain=workgroup,
                        use_ntlm_v2=method["use_ntlm_v2"],
                        is_direct_tcp=method["is_direct_tcp"]
                    )
                    
                    connected = self.conn.connect(server_name, method["port"])
                    
                    if connected:
                        logger.info(f"Successfully connected to share {self.share_config['name']} "
                                  f"on {server_name} using {method}")
                        
                        # Test accessing the share
                        try:
                            shares = self.conn.listShares()
                            share_names = [share.name for share in shares]
                            logger.info(f"Available shares: {share_names}")
                            
                            if self.share_config['name'] not in share_names:
                                logger.warning(f"Share {self.share_config['name']} not found in available shares!")
                                return False
                                
                            # Try listing the root directory of the share
                            self.conn.listPath(self.share_config['name'], '/')
                            logger.info(f"Successfully listed root directory of share {self.share_config['name']}")
                            
                        except Exception as e:
                            logger.error(f"Connection established but cannot access share: {str(e)}")
                            return False
                            
                        return True
                except Exception as e:
                    logger.debug(f"Connection attempt failed with {method}: {str(e)}")
                    continue
            
            logger.error(f"All connection attempts failed for {server_name}")
            return False
            
        except Exception as e:
            import traceback
            logger.error(f"SMB connection error: {str(e)}")
            logger.debug(f"Detailed connection error: {traceback.format_exc()}")
            logger.info(f"Connection details: server={self.share_config['server']}, "
                      f"share={self.share_config['name']}, "
                      f"user={self.share_config['username']}, "
                      f"workgroup/domain={workgroup}")
            return False
    
    def disconnect(self):
        """Close the SMB connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
    
    def calculate_checksum(self, file_obj):
        """Calculate MD5 checksum for a file."""
        md5 = hashlib.md5()
        for chunk in iter(lambda: file_obj.read(4096), b''):
            md5.update(chunk)
        return md5.hexdigest()
    
    def get_temp_file(self, path, filename):
        """Download a file to a temporary location and return the path."""
        temp_path = os.path.join('/tmp', filename)
        
        with open(temp_path, 'wb') as file_obj:
            self.conn.retrieveFile(self.share_config['name'], path, file_obj)
        
        return temp_path
    
    def scan_directory(self, path='', recursive=True):
        """Scan a directory on the share and yield file information."""
        if not self.conn:
            if not self.connect():
                logger.error("Not connected to share. Scan failed.")
                return
        
        try:
            files = self.conn.listPath(self.share_config['name'], path)
            
            for file_info in files:
                file_name = file_info.filename
                
                # Skip '.' and '..' directories
                if file_name in ['.', '..']:
                    continue
                
                # Calculate the full path
                full_path = os.path.join(path, file_name) if path else file_name
                
                # If it's a directory and recursion is enabled, scan it
                if file_info.isDirectory and recursive:
                    try:
                        yield from self.scan_directory(full_path, recursive)
                    except Exception as e:
                        error_msg = f"Failed to list {full_path} on {self.share_config['name']}: {str(e)}"
                        logger.error(f"Error scanning directory {full_path}: {str(e)}")
                        # Create an error record that can be included in reports
                        yield {
                            'error': True,
                            'path': full_path,
                            'message': error_msg,
                            'share_config': self.share_config
                        }
                # If it's a file, yield its information
                elif not file_info.isDirectory:
                    # Generate a unique identifier for the file
                    local_path = f"{self.share_config['local_name']}:{full_path}"
                    
                    # Check if file has changed by comparing modification time and size
                    existing_file = self.db_manager.get_file_by_path(local_path)
                    
                    # Convert Windows file time to Unix timestamp
                    last_modified = datetime.datetime.fromtimestamp(file_info.last_write_time)
                    
                    # If file exists in DB and hasn't changed, skip checksum calculation
                    if existing_file and int(existing_file[3]) == file_info.file_size and \
                       existing_file[4] == last_modified.isoformat():
                        continue
                    
                    # For changed or new files, calculate checksum
                    try:
                        # Download to temp file
                        temp_path = self.get_temp_file(full_path, file_name)
                        
                        # Calculate checksum
                        with open(temp_path, 'rb') as file_obj:
                            checksum = self.calculate_checksum(file_obj)
                        
                        # Remove temp file
                        os.unlink(temp_path)
                        
                        # Yield the file information
                        yield {
                            'local_path': local_path,
                            'share_path': full_path,
                            'size': file_info.file_size,
                            'last_modified': last_modified,
                            'checksum': checksum,
                            'share_config': self.share_config
                        }
                    except Exception as e:
                        logger.error(f"Error processing file {full_path}: {str(e)}")
        except Exception as e:
            logger.error(f"Error scanning directory {path}: {str(e)}")


class S3Manager:
    """Manager for S3 operations."""
    
    def __init__(self, config):
        self.config = config
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=config.aws_access_key,
            aws_secret_access_key=config.aws_secret_key,
            region_name=config.aws_region
        )
    
    def upload_file(self, local_file_path, s3_key):
        """Upload a file to S3 storage."""
        try:
            # Extensive logging to understand configuration
            logger.info(f"Config object attributes: {dir(self.config)}")
            logger.info(f"Config dict representation: {vars(self.config)}")
            
            # Check config sections
            logger.info("Config sections:")
            for section in self.config.config.sections():
                logger.info(f"Section {section}:")
                for key, value in self.config.config[section].items():
                    logger.info(f"  {key}: {value}")
            
            # Specific logging for storage class
            logger.info(f"Raw storage class value: {getattr(self.config, 'storage_class', 'NOT FOUND')}")
            
            # Attempt to get storage class from config sections
            config_storage_class = self.config.config['AWS'].get('storage_class', 'STANDARD_IA') if 'AWS' in self.config.config else 'STANDARD_IA'
            logger.info(f"Storage class from config sections: {config_storage_class}")
            
            # Use the storage class from config sections
            extra_args = {
                'StorageClass': config_storage_class.upper().replace(' ', '_')
            }
            
            self.s3_client.upload_file(
                local_file_path,
                self.config.s3_bucket,
                s3_key,
                ExtraArgs=extra_args
            )
            
            logger.info(f"Successfully uploaded {local_file_path} to s3://{self.config.s3_bucket}/{s3_key}")
            return True
        except botocore.exceptions.ClientError as e:
            logger.error(f"Error uploading {local_file_path} to S3: {str(e)}")
            logger.error(f"Detailed error: {e.response}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error uploading {local_file_path}: {str(e)}")
            return False
    
    def copy_object(self, source_key, dest_key):
        """Copy an object within the same S3 bucket."""
        try:
            # Source must include the bucket name
            copy_source = {'Bucket': self.config.s3_bucket, 'Key': source_key}
            
            # Copy the object with the same storage class
            self.s3_client.copy_object(
                CopySource=copy_source,
                Bucket=self.config.s3_bucket,
                Key=dest_key,
                StorageClass=self.config.storage_class
            )
            
            logger.info(f"Successfully copied s3://{self.config.s3_bucket}/{source_key} to s3://{self.config.s3_bucket}/{dest_key}")
            return True
        except botocore.exceptions.ClientError as e:
            logger.error(f"Error copying S3 object {source_key} to {dest_key}: {str(e)}")
            return False
    
    def delete_object(self, s3_key):
        """Delete an object from S3."""
        try:
            self.s3_client.delete_object(
                Bucket=self.config.s3_bucket,
                Key=s3_key
            )
            
            logger.info(f"Successfully deleted s3://{self.config.s3_bucket}/{s3_key}")
            return True
        except botocore.exceptions.ClientError as e:
            logger.error(f"Error deleting S3 object {s3_key}: {str(e)}")
            return False
    
    def generate_s3_key(self, file_info):
        """Generate an S3 key for a file based on its local path."""
        # Create a structure like: share_key_from_config/path/to/file
        # The share_key_from_config is the key name used in the config.ini [Shares] section
        # If a global prefix is specified, it becomes: prefix/share_key_from_config/path/to/file
        share_name = file_info['share_config']['local_name']
        file_path = file_info['share_path'].lstrip('/')
        
        if self.config.s3_prefix:
            s3_key = f"{self.config.s3_prefix.rstrip('/')}/{share_name}/{file_path}"
        else:
            s3_key = f"{share_name}/{file_path}"
            
        return s3_key
    
    def list_objects(self, prefix=None):
        """List objects in the S3 bucket with the given prefix."""
        if prefix is None:
            prefix = self.config.s3_prefix
        
        paginator = self.s3_client.get_paginator('list_objects_v2')
        
        for page in paginator.paginate(Bucket=self.config.s3_bucket, Prefix=prefix):
            if 'Contents' in page:
                for obj in page['Contents']:
                    yield obj


class BackupManager:
    """Main manager for the backup process."""
    
    def __init__(self, config):
        self.config = config
        self.db_manager = DatabaseManager(config.db_path)
        self.s3_manager = S3Manager(config)
        self.scan_errors = []  # Track directory scan errors
        
        # Ensure report directory exists
        os.makedirs(config.report_path, exist_ok=True)
    
    def close(self):
        """Clean up resources."""
        self.db_manager.close()
    
    def scan_shares(self):
        """Scan all configured shares and update the index."""
        files_scanned = 0
        files_changed = 0
        self.files_moved = 0  # Track moved files
        self.files_renamed = 0  # Track renamed files
        
        # Keep track of recently deleted files by checksum for rename detection
        recently_deleted = {}
        
        # First, look for deleted files and add them to our tracking dictionary
        for share_config in self.config.shares:
            scanner = ShareScanner(share_config, self.db_manager)
            try:
                if scanner.connect():
                    # Get all non-deleted files for this share
                    cursor = self.db_manager.conn.cursor()
                    cursor.execute('''
                    SELECT id, local_path, s3_path, size, last_modified, checksum, is_deleted
                    FROM files 
                    WHERE local_path LIKE ? AND is_deleted=0
                    ''', (f"{share_config['local_name']}:%",))
                    
                    files = cursor.fetchall()
                    
                    # Check if each file still exists
                    for file in files:
                        file_id, local_path, s3_path, size, last_modified, checksum, is_deleted = file
                        
                        # Parse local path to get actual file path on share
                        parts = local_path.split(':', 1)
                        if len(parts) != 2:
                            continue
                        
                        share_name, file_path = parts
                        
                        # Check if file exists
                        try:
                            scanner.conn.getAttributes(share_config['name'], file_path)
                            # File exists, nothing to do
                        except Exception:
                            # File doesn't exist, mark as deleted and track by checksum for rename detection
                            logger.info(f"File no longer exists, possibly renamed: {local_path}")
                            self.db_manager.mark_deleted(local_path)
                            
                            # Store in recently_deleted dictionary for rename detection
                            # Use checksum as key and include file info as value
                            recently_deleted[checksum] = {
                                'local_path': local_path,
                                's3_path': s3_path,
                                'size': size,
                                'last_modified': last_modified
                            }
            finally:
                scanner.disconnect()
        
        # Now scan for new and changed files
        for share_config in self.config.shares:
            scanner = ShareScanner(share_config, self.db_manager)
            
            try:
                # Scan files in the share
                for item in scanner.scan_directory():
                    # Check if this is an error record
                    if 'error' in item and item['error']:
                        # Add to scan errors list
                        self.scan_errors.append(item)
                        continue
                        
                    # This is a normal file record
                    file_info = item
                    files_scanned += 1
                    
                    # Generate S3 key for this file
                    s3_key = self.s3_manager.generate_s3_key(file_info)
                    
                    # Check if file exists in database at current path
                    existing_file = self.db_manager.get_file_by_path(file_info['local_path'])
                    
                    # If file not found at this path, check if it was recently deleted with same checksum (rename)
                    if not existing_file and file_info['checksum'] in recently_deleted:
                        old_info = recently_deleted[file_info['checksum']]
                        old_path = old_info['local_path']
                        old_s3_path = old_info['s3_path']
                        
                        logger.info(f"Detected renamed file: {old_path} -> {file_info['local_path']}")
                        logger.info(f"S3 path: {old_s3_path} -> {s3_key}")
                        
                        # Move the file in S3
                        if old_s3_path != s3_key:
                            if self.s3_manager.copy_object(old_s3_path, s3_key):
                                if self.s3_manager.delete_object(old_s3_path):
                                    logger.info(f"Successfully moved renamed file in S3")
                                else:
                                    logger.warning(f"File copied to new location but delete from old location failed")
                            else:
                                logger.error(f"Failed to move renamed file in S3")
                                # Use the old S3 path since the move failed
                                s3_key = old_s3_path
                        
                        # Update the database with the new path
                        self.db_manager.add_file(
                            local_path=file_info['local_path'],
                            s3_path=s3_key,
                            size=file_info['size'],
                            last_modified=file_info['last_modified'].isoformat(),
                            checksum=file_info['checksum'],
                            previous_path=old_path,
                            moved_in_s3=1
                        )
                        
                        self.files_renamed += 1
                        
                        # We've handled this rename, remove from tracking
                        del recently_deleted[file_info['checksum']]
                        continue
                    
                    # If file not found at this path, check if it exists elsewhere by checksum (moved)
                    if not existing_file:
                        checksum_match = self.db_manager.get_file_by_checksum(file_info['checksum'])
                        
                        if checksum_match:
                            # Get existing record to check if it's already been moved in S3
                            cursor = self.db_manager.conn.cursor()
                            cursor.execute('''
                            SELECT moved_in_s3 FROM files WHERE local_path=?
                            ''', (file_info['local_path'],))
                            result = cursor.fetchone()
                            already_moved = result and result[0] == 1
                            
                            # This is likely a moved file - update S3 to match if not already moved
                            old_path = checksum_match[1]
                            old_s3_path = checksum_match[2]
                            new_s3_path = s3_key
                            
                            logger.info(f"Detected moved file: {old_path} -> {file_info['local_path']}")
                            logger.info(f"S3 path: {old_s3_path} -> {new_s3_path}")
                            
                            # Only move in S3 if not already moved and paths differ
                            moved_in_s3_flag = 0
                            if not already_moved and old_s3_path != new_s3_path:
                                logger.info(f"Moving file in S3 (not previously moved)")
                                # Copy to new location, then delete from old location
                                if self.s3_manager.copy_object(old_s3_path, new_s3_path):
                                    if self.s3_manager.delete_object(old_s3_path):
                                        moved_in_s3_flag = 1
                                        logger.info(f"Successfully moved file in S3")
                                    else:
                                        logger.warning(f"File copied to new location but delete from old location failed")
                                        # Still consider it a success since the copy worked
                                        moved_in_s3_flag = 1
                                else:
                                    logger.error(f"Failed to move file in S3, keeping the old S3 path in database")
                                    # Use the old S3 path since the copy failed
                                    new_s3_path = old_s3_path
                            elif already_moved:
                                logger.info(f"File was already moved in S3, skipping S3 move operation")
                                moved_in_s3_flag = 1
                            elif old_s3_path == new_s3_path:
                                # Same S3 path, no need to move in S3 but mark as moved
                                logger.info(f"S3 paths are the same, no need to move file in S3")
                                moved_in_s3_flag = 1
                            
                            # Update the database with the new path and moved status
                            self.db_manager.add_file(
                                local_path=file_info['local_path'],
                                s3_path=new_s3_path,
                                size=file_info['size'],
                                last_modified=file_info['last_modified'].isoformat(),
                                checksum=file_info['checksum'],
                                previous_path=old_path,
                                moved_in_s3=moved_in_s3_flag
                            )
                            
                            self.files_moved += 1
                            continue
                    
                    # If file changed or is new (and not moved/renamed), mark it for upload
                    if not existing_file or existing_file[4] != file_info['checksum']:
                        files_changed += 1
                        yield file_info, s3_key
            finally:
                scanner.disconnect()
        
        logger.info(f"Scanned {files_scanned} files, {files_changed} changed or new, {self.files_moved} moved, {self.files_renamed} renamed")
    
    def mark_deleted_files(self):
        """Mark files that no longer exist in shares as deleted."""
        # Get all non-deleted files from the database
        existing_files = self.db_manager.get_all_files(include_deleted=False)
        deleted_count = 0
        
        for file_record in existing_files:
            # Parse the local path to get share name and path
            local_path = file_record[1]
            
            # Skip if already marked as deleted
            if file_record[6] == 1:
                continue
            
            # Format: share_name:path/to/file
            parts = local_path.split(':', 1)
            if len(parts) != 2:
                logger.warning(f"Invalid path format: {local_path}")
                continue
            
            share_name, file_path = parts
            
            # Find matching share config
            share_config = None
            for share in self.config.shares:
                if share['local_name'] == share_name:
                    share_config = share
                    break
            
            if not share_config:
                logger.warning(f"Share {share_name} not found in configuration")
                continue
            
            # Check if file exists on share
            scanner = ShareScanner(share_config, self.db_manager)
            try:
                if scanner.connect():
                    try:
                        scanner.conn.getAttributes(share_config['name'], file_path)
                        # File exists, nothing to do
                    except Exception:
                        # File doesn't exist, mark as deleted
                        self.db_manager.mark_deleted(local_path)
                        deleted_count += 1
                        logger.info(f"Marked as deleted: {local_path}")
            finally:
                scanner.disconnect()
        
        logger.info(f"Marked {deleted_count} files as deleted")
        return deleted_count
    
    def build_initial_index(self):
        """Build initial index from S3 and Windows shares without uploading."""
        logger.info("Building initial index...")
        
        # Initialize counters
        files_indexed = 0
        
        # First, index files from S3
        logger.info("Indexing files from S3...")
        
        try:
            for obj in self.s3_manager.list_objects():
                s3_key = obj['Key']
                
                # If a prefix is configured, we need to skip objects that don't match it
                if self.config.s3_prefix:
                    prefix = self.config.s3_prefix.rstrip('/')
                    if not s3_key.startswith(prefix + '/'):
                        continue
                    # Extract share name and path from S3 key with prefix
                    # Format: prefix/share_name/path/to/file
                    path_parts = s3_key[len(prefix) + 1:].split('/', 1)
                else:
                    # No prefix, so format is: share_name/path/to/file
                    path_parts = s3_key.split('/', 1)
                
                if len(path_parts) != 2:
                    continue
                
                share_name, file_path = path_parts
                local_path = f"{share_name}:{file_path}"
                
                # Add to database without checksum (will be updated later if file exists)
                self.db_manager.add_file(
                    local_path=local_path,
                    s3_path=s3_key,
                    size=obj['Size'],
                    last_modified=obj['LastModified'].isoformat(),
                    checksum="s3_indexed",  # Placeholder
                    previous_path=None,
                    moved_in_s3=0
                )
                
                files_indexed += 1
                
                if files_indexed % 1000 == 0:
                    logger.info(f"Indexed {files_indexed} files from S3 so far")
        
        except Exception as e:
            logger.error(f"Error indexing S3: {str(e)}")
        
        logger.info(f"Indexed {files_indexed} files from S3")
        
        # Now scan shares to update checksums and find new files
        logger.info("Scanning Windows shares to update index...")
        
        for file_info, s3_key in self.scan_shares():
            # Check if this file is already in the index (from S3)
            existing = self.db_manager.get_file_by_path(file_info['local_path'])
            
            # Update database with current file information
            self.db_manager.add_file(
                local_path=file_info['local_path'],
                s3_path=s3_key,
                size=file_info['size'],
                last_modified=file_info['last_modified'].isoformat(),
                checksum=file_info['checksum'],
                previous_path=None,
                moved_in_s3=0
            )
        
        # Mark files that no longer exist as deleted
        self.mark_deleted_files()
        
        logger.info("Initial index building completed")
    
    def sync_index_with_aws(self):
        """
        Synchronize index with both AWS S3 and Windows shares.
        This builds a comprehensive index without uploading any files,
        perfect for migrating from another backup solution.
        """
        logger.info("Synchronizing index with AWS S3 and Windows shares...")
        
        # Initialize counters
        files_indexed_s3 = 0
        files_indexed_shares = 0
        files_matched = 0
        s3_only_files = 0
        
        # Step 1: Index files from S3 first
        logger.info("Indexing files from AWS S3...")
        s3_files = {}  # Dictionary to track S3 files by path
        
        try:
            for obj in self.s3_manager.list_objects():
                s3_key = obj['Key']
                
                # If a prefix is configured, handle it properly
                if self.config.s3_prefix:
                    prefix = self.config.s3_prefix.rstrip('/')
                    if not s3_key.startswith(prefix + '/'):
                        continue
                    # Extract share name and path from S3 key with prefix
                    path_parts = s3_key[len(prefix) + 1:].split('/', 1)
                else:
                    # No prefix, so format is: share_name/path/to/file
                    path_parts = s3_key.split('/', 1)
                
                if len(path_parts) != 2:
                    continue
                
                share_name, file_path = path_parts
                local_path = f"{share_name}:{file_path}"
                
                # Store in our tracking dictionary
                s3_files[local_path] = {
                    's3_path': s3_key,
                    'size': obj['Size'],
                    'last_modified': obj['LastModified'].isoformat()
                }
                
                # Add to database with placeholder checksum
                self.db_manager.add_file(
                    local_path=local_path,
                    s3_path=s3_key,
                    size=obj['Size'],
                    last_modified=obj['LastModified'].isoformat(),
                    checksum="s3_indexed",  # Placeholder to be updated later if file exists
                    previous_path=None,
                    moved_in_s3=0
                )
                
                files_indexed_s3 += 1
                
                if files_indexed_s3 % 1000 == 0:
                    logger.info(f"Indexed {files_indexed_s3} files from S3 so far")
        
        except Exception as e:
            logger.error(f"Error indexing S3: {str(e)}")
        
        logger.info(f"Indexed {files_indexed_s3} files from S3")
        
        # Step 2: Scan Windows shares to update checksums and match with S3 files
        logger.info("Scanning Windows shares to match with S3 index...")
        
        # Dictionary to track files by share for reporting
        share_stats = {}
        
        for share_config in self.config.shares:
            share_name = share_config['local_name']
            share_stats[share_name] = {
                'total': 0,
                'matched': 0,
                'new': 0
            }
            
            scanner = ShareScanner(share_config, self.db_manager)
            try:
                if not scanner.connect():
                    logger.error(f"Failed to connect to share {share_config['name']}")
                    continue
                    
                # Scan files in the share
                for item in scanner.scan_directory():
                    # Skip error records
                    if 'error' in item and item['error']:
                        continue
                        
                    # Process file info
                    file_info = item
                    files_indexed_shares += 1
                    share_stats[share_name]['total'] += 1
                    
                    local_path = file_info['local_path']
                    
                    # Check if this file exists in S3
                    if local_path in s3_files:
                        # We have a match! Update the database with the checksum
                        self.db_manager.add_file(
                            local_path=local_path,
                            s3_path=s3_files[local_path]['s3_path'],
                            size=file_info['size'],
                            last_modified=file_info['last_modified'].isoformat(),
                            checksum=file_info['checksum'],
                            previous_path=None,
                            moved_in_s3=0
                        )
                        files_matched += 1
                        share_stats[share_name]['matched'] += 1
                    else:
                        # File exists in share but not in S3
                        # Generate S3 key for this file
                        s3_key = self.s3_manager.generate_s3_key(file_info)
                        
                        # Add to database (will need to be uploaded later)
                        self.db_manager.add_file(
                            local_path=local_path,
                            s3_path=s3_key,
                            size=file_info['size'],
                            last_modified=file_info['last_modified'].isoformat(),
                            checksum=file_info['checksum'],
                            previous_path=None,
                            moved_in_s3=0
                        )
                        share_stats[share_name]['new'] += 1
                    
                    if files_indexed_shares % 1000 == 0:
                        logger.info(f"Processed {files_indexed_shares} files from shares so far")
            
            except Exception as e:
                logger.error(f"Error scanning share {share_name}: {str(e)}")
            finally:
                scanner.disconnect()
        
        # Step 3: Mark files that exist in S3 but not in shares as "s3_only"
        # First, get all files with placeholder checksums
        cursor = self.db_manager.conn.cursor()
        cursor.execute("SELECT local_path FROM files WHERE checksum='s3_indexed'")
        s3_only = cursor.fetchall()
        
        for row in s3_only:
            local_path = row[0]
            s3_only_files += 1
            
            # Update these with a special flag to indicate they're only in S3
            cursor.execute(
                "UPDATE files SET checksum='s3_only' WHERE local_path=?", 
                (local_path,)
            )
        
        self.db_manager.conn.commit()
        
        # Generate summary report
        report = f"""
AWS S3 and Windows Shares Synchronization Report
===============================================
Files indexed from AWS S3: {files_indexed_s3}
Files indexed from Windows Shares: {files_indexed_shares}
Files matched in both locations: {files_matched}
Files existing only in S3: {s3_only_files}

Share-by-Share Statistics:
"""
        
        for share_name, stats in share_stats.items():
            report += f"""
{share_name}:
  - Total files: {stats['total']}
  - Matched with S3: {stats['matched']}
  - New files (to be uploaded): {stats['new']}
"""
        
        report += """
Next Steps:
----------
1. Review the index with: python s3_backup.py --list-index
2. Run a backup to upload new files: python s3_backup.py --run-now
3. To see files that exist only in S3: python s3_backup.py --list-index --s3-only
"""
        
        logger.info(report)
        print(report)
        
        # Send email notification if enabled
        if self.config.email_enabled:
            self.send_email(
                subject="AWS S3 Sync Report",
                body=report
            )
        
        # Create a CSV report of the synchronization
        report_file = os.path.join(
            self.config.report_path, 
            f'aws_sync_report_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        )
        
        try:
            with open(report_file, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['Location', 'Share', 'Path', 'Size', 'Last Modified'])
                
                # Files only in S3
                cursor.execute(
                    "SELECT local_path, s3_path, size, last_modified FROM files WHERE checksum='s3_only'"
                )
                for row in cursor.fetchall():
                    local_path, s3_path, size, last_modified = row
                    share_name = local_path.split(':', 1)[0]
                    file_path = local_path.split(':', 1)[1] if ':' in local_path else local_path
                    writer.writerow(['S3 Only', share_name, file_path, size, last_modified])
                
                # New files that need to be uploaded
                for share_name, stats in share_stats.items():
                    if stats['new'] > 0:
                        cursor.execute(
                            "SELECT local_path, size, last_modified FROM files WHERE local_path LIKE ? AND checksum != 's3_only' AND checksum != 's3_indexed'",
                            (f"{share_name}:%",)
                        )
                        for row in cursor.fetchall():
                            local_path, size, last_modified = row
                            file_path = local_path.split(':', 1)[1] if ':' in local_path else local_path
                            writer.writerow(['To Upload', share_name, file_path, size, last_modified])
            
            logger.info(f"Detailed report saved to {report_file}")
        except Exception as e:
            logger.error(f"Error writing report: {str(e)}")
        
        logger.info("Index synchronization completed")
    
    def upload_file_to_s3(self, file_info, s3_key):
        """Upload a file to S3 and update the index."""
        try:
            # Create a temporary file
            share_path = file_info['share_path']
            share_config = file_info['share_config']
            
            # Connect to share
            scanner = ShareScanner(share_config, self.db_manager)
            try:
                if not scanner.connect():
                    logger.error(f"Failed to connect to share {share_config['name']}")
                    return False
                
                # Download to temp file
                temp_path = scanner.get_temp_file(share_path, os.path.basename(share_path))
                
                # Upload to S3
                success = self.s3_manager.upload_file(temp_path, s3_key)
                
                # Clean up temp file
                os.unlink(temp_path)
                
                if success:
                    # Update the database
                    self.db_manager.add_file(
                        local_path=file_info['local_path'],
                        s3_path=s3_key,
                        size=file_info['size'],
                        last_modified=file_info['last_modified'].isoformat(),
                        checksum=file_info['checksum'],
                        previous_path=None,
                        moved_in_s3=0
                    )
                    return True
                return False
            finally:
                scanner.disconnect()
        except Exception as e:
            logger.error(f"Error uploading {file_info['local_path']}: {str(e)}")
            return False
    
    def run_backup(self):
        """Run a full backup process."""
        logger.info("Starting backup process")
        
        # Start tracking the backup run
        run_id = self.db_manager.start_backup_run()
        
        # Initialize counters
        files_processed = 0
        files_uploaded = 0
        bytes_uploaded = 0
        files_failed = 0
        self.files_moved = 0  # Track moved files
        self.files_renamed = 0  # Track renamed files
        
        # Prepare success/failure records for reporting
        success_records = []
        failure_records = []
        
        # Create a thread pool for parallel uploads
        with ThreadPoolExecutor(max_workers=self.config.thread_count) as executor:
            # Dictionary to track futures
            future_to_file = {}
            
            # Scan shares and upload changed files
            for file_info, s3_key in self.scan_shares():
                files_processed += 1
                
                # Submit upload task to thread pool
                future = executor.submit(self.upload_file_to_s3, file_info, s3_key)
                future_to_file[future] = (file_info, s3_key)
            
            # Process completed uploads
            for future in future_to_file:
                file_info, s3_key = future_to_file[future]
                
                try:
                    success = future.result()
                    
                    if success:
                        files_uploaded += 1
                        bytes_uploaded += file_info['size']
                        
                        # Add to success records
                        success_records.append({
                            'name': os.path.basename(file_info['share_path']),
                            'local_path': file_info['local_path'],
                            's3_path': s3_key,
                            'size': file_info['size']
                        })
                    else:
                        files_failed += 1
                        
                        # Add to failure records
                        failure_records.append({
                            'name': os.path.basename(file_info['share_path']),
                            'local_path': file_info['local_path'],
                            's3_path': s3_key,
                            'size': file_info['size'],
                            'error': 'Upload failed'
                        })
                except Exception as e:
                    files_failed += 1
                    
                    # Add to failure records
                    failure_records.append({
                        'name': os.path.basename(file_info['share_path']),
                        'local_path': file_info['local_path'],
                        's3_path': s3_key,
                        'size': file_info['size'],
                        'error': str(e)
                    })
        
        # Mark deleted files
        deleted_count = self.mark_deleted_files()
        
        # Update backup run status
        status = 'COMPLETED' if files_failed == 0 else 'COMPLETED_WITH_ERRORS'
        self.db_manager.finish_backup_run(
            run_id, status, files_processed, files_uploaded, bytes_uploaded, files_failed
        )
        
        # Generate report
        self.generate_report(success_records, failure_records)
        
        # Add run details, including moved files, renamed files and scan errors
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        details = f"""
BACKUP SUMMARY ({now})
====================
Files processed: {files_processed}
Files uploaded: {files_uploaded} ({format_size(bytes_uploaded)})
Files failed: {files_failed}
Files moved (in S3): {getattr(self, 'files_moved', 0)}
Files renamed (in S3): {getattr(self, 'files_renamed', 0)}
Files marked as deleted: {deleted_count}
Directory scan errors: {len(self.scan_errors)}
Status: {status}
        """
        
        # Add scan error details
        if self.scan_errors:
            details += "\nSCAN ERRORS:\n"
            for i, error in enumerate(self.scan_errors, 1):
                details += f"{i}. {error['path']}: {error['message']}\n"
                if i >= 10 and len(self.scan_errors) > 10:
                    details += f"... and {len(self.scan_errors) - 10} more errors\n"
                    break
        
        logger.info(details)
        print(details)
        
        # Send email notification if enabled
        if self.config.email_enabled:
            self.send_email(
                subject=f"Backup Summary - {status}",
                body=details
            )
    
    def send_email(self, subject, body):
        """Send an email notification with the backup summary."""
        if not self.config.email_enabled:
            return
        
        # Verify email configuration
        if not self.config.email_from or not self.config.email_to:
            logger.warning("Email notification enabled but missing from/to address. Skipping notification.")
            return
            
        try:
            # Create the email message
            msg = EmailMessage()
            msg['Subject'] = f"{self.config.email_subject_prefix} {subject}"
            msg['From'] = self.config.email_from
            msg['To'] = self.config.email_to
            msg.set_content(body)
            
            # Send the email
            logger.info(f"Sending email notification to {self.config.email_to}")
            with smtplib.SMTP(self.config.email_smtp_server, self.config.email_smtp_port) as server:
                server.send_message(msg)
            logger.info("Email notification sent successfully")
        except Exception as e:
            # Don't fail the backup job if email fails
            logger.error(f"Failed to send email notification: {str(e)}")
            # Log the error but don't raise exception to continue the backup process
    
    def generate_report(self, success_records, failure_records):
        """Generate CSV report of backup results."""
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = os.path.join(self.config.report_path, f'backup_report_{timestamp}.csv')
        
        # Combine records and add status
        all_records = []
        for record in success_records:
            record['status'] = 'SUCCESS'
            record['error_type'] = ''
            all_records.append(record)
        
        for record in failure_records:
            record['status'] = 'FAILURE'
            record['error_type'] = 'UPLOAD_ERROR'
            all_records.append(record)
            
        # Add scan errors
        for error in self.scan_errors:
            # Create a record format compatible with the other records
            share_name = error['share_config']['local_name']
            error_record = {
                'name': os.path.basename(error['path']),
                'local_path': f"{share_name}:{error['path']}",
                's3_path': '',
                'size': 0,
                'status': 'FAILURE',
                'error': error['message'],
                'error_type': 'SCAN_ERROR'
            }
            all_records.append(error_record)
        
        # Write to CSV
        try:
            # Define all possible fields
            fieldnames = ['name', 'local_path', 's3_path', 'size', 'status', 'error', 'error_type']
            
            with open(report_file, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for record in all_records:
                    # Ensure all fields exist (set defaults for missing ones)
                    for field in fieldnames:
                        if field not in record:
                            record[field] = ''
                    
                    writer.writerow(record)
            
            logger.info(f"Report generated: {report_file}")
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")


def run_scheduled_backup(config):
    """Run a scheduled backup."""
    backup_manager = BackupManager(config)
    try:
        backup_manager.run_backup()
    finally:
        backup_manager.close()


def list_index(config, show_deleted=False, share_filter=None, export_path=None, include_moved=True, s3_only=False):
    """List the contents of the backup index."""
    logger.info("Listing backup index...")
    
    # Initialize database connection
    db_manager = DatabaseManager(config.db_path)
    
    try:
        # Get files based on filters
        if show_deleted:
            files = db_manager.get_deleted_files()
            logger.info("Showing only deleted files")
        elif s3_only:
            cursor = db_manager.conn.cursor()
            cursor.execute('''
            SELECT id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup, previous_path
            FROM files WHERE checksum='s3_only'
            ''')
            files = cursor.fetchall()
            logger.info("Showing files that exist only in S3")
        else:
            cursor = db_manager.conn.cursor()
            if include_moved:
                cursor.execute('''
                SELECT id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup, previous_path
                FROM files
                ''')
            else:
                cursor.execute('''
                SELECT id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup, previous_path
                FROM files WHERE is_deleted=0
                ''')
            files = cursor.fetchall()
            logger.info("Showing all files")
        
        # Format the data for display and export
        records = []
        for file in files:
            # Unpack the file record
            file_id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup, previous_path = file if len(file) >= 9 else file + (None,)
            
            # Parse local path to get share name
            share_name = local_path.split(':', 1)[0] if ':' in local_path else "unknown"
            
            # Skip if not matching the share filter
            if share_filter and share_name != share_filter:
                continue
            
            # Format the record
            record = {
                'id': file_id,
                'share': share_name,
                'local_path': local_path,
                's3_path': s3_path,
                'size': size,
                'size_formatted': format_size(size),
                'last_modified': last_modified,
                'checksum': checksum,
                'status': 'DELETED' if is_deleted else 'ACTIVE',
                'last_backup': last_backup or 'Never',
                'previous_path': previous_path,
                'moved': previous_path is not None
            }
            
            records.append(record)
        
        # Display summary
        total_size = sum(r['size'] for r in records)
        deleted_size = sum(r['size'] for r in records if r['status'] == 'DELETED')
        active_size = sum(r['size'] for r in records if r['status'] == 'ACTIVE')
        
        print(f"\nBackup Index Summary:")
        print(f"-------------------")
        print(f"Total Files: {len(records)}")
        print(f"Active Files: {sum(1 for r in records if r['status'] == 'ACTIVE')}")
        print(f"Deleted Files: {sum(1 for r in records if r['status'] == 'DELETED')}")
        print(f"Total Size: {format_size(total_size)}")
        print(f"Active Size: {format_size(active_size)}")
        print(f"Deleted Size: {format_size(deleted_size)}")
        
        # Display shares breakdown
        shares = {}
        for record in records:
            share = record['share']
            if share not in shares:
                shares[share] = {'count': 0, 'size': 0}
            shares[share]['count'] += 1
            shares[share]['size'] += record['size']
        
        print(f"\nShares:")
        print(f"------")
        for share, info in shares.items():
            print(f"{share}: {info['count']} files, {format_size(info['size'])}")
        
        # Display files (limited to avoid overwhelming output)
        if len(records) > 0:
            print(f"\nFile Listing (showing first 20):")
            print(f"--------------------------------")
            
            # Sort by path for easier viewing
            records.sort(key=lambda r: r['local_path'])
            
            # Display files (limited to 20)
            for record in records[:20]:
                status_marker = "[D]" if record['status'] == 'DELETED' else "   "
                moved_marker = "[M]" if record.get('moved', False) else "   "
                print(f"{status_marker} {moved_marker} {record['share']} - {record['local_path'].split(':', 1)[1] if ':' in record['local_path'] else record['local_path']} ({record['size_formatted']})")
                if record.get('moved', False) and record.get('previous_path'):
                    print(f"       Previously: {record['previous_path']}")
            
            if len(records) > 20:
                print(f"... and {len(records) - 20} more files.")
        else:
            print("\nNo files found matching the criteria.")
        
        # Export to CSV if requested
        if export_path:
            export_to_csv(records, export_path)
            print(f"\nExported {len(records)} records to {export_path}")
        
    finally:
        db_manager.close()


def format_size(size_bytes):
    """Format a size in bytes to a human-readable string."""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ("B", "KB", "MB", "GB", "TB", "PB")
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024
        i += 1
    
    return f"{size_bytes:.2f} {size_names[i]}"


def export_to_csv(records, export_path):
    """Export records to a CSV file."""
    fieldnames = ['id', 'share', 'local_path', 's3_path', 'size', 'size_formatted', 
                 'last_modified', 'checksum', 'status', 'last_backup', 'previous_path', 'moved']
    
    with open(export_path, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for record in records:
            writer.writerow(record)


def test_share_connections(config):
    """Test connection to all configured Windows shares."""
    logger.info("Testing connection to Windows shares...")
    
    import subprocess
    import sys
    
    if not config.shares:
        logger.error("No shares configured. Please check your configuration file.")
        return
    
    for share_config in config.shares:
        logger.info(f"Testing connection to {share_config['server']}/{share_config['name']}...")
        
        # Test using smbclient command
        try:
            logger.info("Testing with smbclient...")
            cmd = [
                "smbclient", 
                f"//{share_config['server']}/{share_config['name']}",
                "-U", f"{share_config['username']}%{share_config['password']}",
                "-c", "ls"
            ]
            
            if share_config['domain']:
                cmd.extend(["-W", share_config['domain']])
                
            logger.info(f"Command: {' '.join([c if not '%' in c else 'REDACTED' for c in cmd])}")
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                logger.info("smbclient connection successful")
                logger.info(f"Output: {result.stdout}")
            else:
                logger.error(f"smbclient connection failed with error code {result.returncode}")
                logger.error(f"Error output: {result.stderr}")
        except Exception as e:
            logger.error(f"Error testing with smbclient: {str(e)}")
        
        # Test using pysmb library
        try:
            logger.info("Testing with pysmb library...")
            scanner = ShareScanner(share_config, None)  # Pass None for db_manager
            if scanner.connect():
                logger.info("pysmb connection successful")
                
                # Try to list shares
                try:
                    shares = scanner.conn.listShares()
                    logger.info(f"Available shares: {[s.name for s in shares]}")
                except Exception as e:
                    logger.error(f"Error listing shares: {str(e)}")
                
                # Try to list files in the root directory
                try:
                    files = scanner.conn.listPath(share_config['name'], '/')
                    logger.info(f"Files in root: {[f.filename for f in files[:5]]}{'...' if len(files) > 5 else ''}")
                except Exception as e:
                    logger.error(f"Error listing files: {str(e)}")
                
                scanner.disconnect()
            else:
                logger.error("pysmb connection failed")
        except Exception as e:
            logger.error(f"Error testing with pysmb: {str(e)}")
        
        logger.info(f"Finished testing connection to {share_config['server']}/{share_config['name']}")
        logger.info("-" * 50)


def generate_deleted_report(config, output_path=None):
    """Generate a report of deleted files."""
    if output_path is None:
        output_path = os.path.join(config.report_path, f'deleted_files_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.csv')
    
    logger.info(f"Generating deleted files report to {output_path}")
    
    db_manager = DatabaseManager(config.db_path)
    try:
        deleted_files = db_manager.get_deleted_files()
        
        # Prepare records for CSV
        records = []
        for file in deleted_files:
            file_id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup = file
            
            share_name = local_path.split(':', 1)[0] if ':' in local_path else "unknown"
            file_path = local_path.split(':', 1)[1] if ':' in local_path else local_path
            
            records.append({
                'id': file_id,
                'share': share_name,
                'local_path': file_path,
                's3_path': s3_path,
                'size': size,
                'size_formatted': format_size(size),
                'last_modified': last_modified,
                'checksum': checksum,
                'last_backup': last_backup or 'Never'
            })
        
        # Export to CSV
        fieldnames = ['id', 'share', 'local_path', 's3_path', 'size', 'size_formatted', 
                     'last_modified', 'checksum', 'last_backup']
        
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for record in records:
                writer.writerow(record)
        
        logger.info(f"Exported {len(records)} deleted files to {output_path}")
        return len(records)
    finally:
        db_manager.close()


def generate_s3_delete_script(config, output_path=None):
    """Generate a script with AWS CLI commands to delete files from S3."""
    if output_path is None:
        output_path = os.path.join(config.report_path, f's3_delete_script_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.sh')
    
    logger.info(f"Generating S3 delete script to {output_path}")
    
    db_manager = DatabaseManager(config.db_path)
    try:
        deleted_files = db_manager.get_deleted_files()
        
        # Create script header
        script_lines = [
            "#!/bin/bash",
            "# S3 Delete Script for files marked as deleted in the backup index",
            f"# Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "# WARNING: This script will permanently delete objects from S3",
            "# Review carefully before running!",
            "",
            "# Uncomment the following line to execute all delete commands",
            "# EXECUTE=true",
            "",
            "if [ \"$EXECUTE\" != \"true\" ]; then",
            "    echo \"This script is in dry-run mode. No files will be deleted.\"",
            "    echo \"To execute the delete commands, uncomment the EXECUTE=true line.\"",
            "    echo \"\"",
            "fi",
            ""
        ]
        
        # Add delete commands
        total_size = 0
        for file in deleted_files:
            file_id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup = file
            
            # Add command to delete the file
            script_lines.append(f"# File: {local_path} (Size: {format_size(size)})")
            script_lines.append(f"if [ \"$EXECUTE\" = \"true\" ]; then")
            script_lines.append(f"    aws s3 rm s3://{config.s3_bucket}/{s3_path}")
            script_lines.append(f"else")
            script_lines.append(f"    echo \"Would delete: s3://{config.s3_bucket}/{s3_path}\"")
            script_lines.append(f"fi")
            script_lines.append("")
            
            total_size += size
        
        # Add summary comment
        script_lines.append(f"# Total: {len(deleted_files)} files, {format_size(total_size)}")
        
        # Write the script file
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write('\n'.join(script_lines))
        
        # Make the script executable
        os.chmod(output_path, 0o755)
        
        logger.info(f"Created delete script for {len(deleted_files)} files ({format_size(total_size)}) at {output_path}")
        return len(deleted_files)
    finally:
        db_manager.close()


def main():
    """Main entry point of the script."""
    parser = argparse.ArgumentParser(description='S3 Windows Share Backup Tool')
    parser.add_argument('--create-password-file', help='Create a password file with the given path')
    parser.add_argument('--config', default=CONFIG_FILE, help='Path to configuration file')
    parser.add_argument('--initialize', action='store_true', help='Initialize the database and build initial index')
    parser.add_argument('--create-config', action='store_true', help='Create a default configuration file')
    parser.add_argument('--encrypt-config', action='store_true', help='Encrypt the configuration file')
    parser.add_argument('--password', help='Password for encryption/decryption (you can omit this to be prompted)')
    parser.add_argument('--password-file', help='File containing the password for encryption/decryption')
    parser.add_argument('--password-env', help='Environment variable name containing the password')
    parser.add_argument('--run-now', action='store_true', help='Run backup immediately')
    parser.add_argument('--schedule', action='store_true', help='Run scheduled backups')
    parser.add_argument('--test-connection', action='store_true', help='Test connection to Windows shares')
    parser.add_argument('--list-index', action='store_true', help='List the contents of the backup index')
    parser.add_argument('--show-deleted', action='store_true', help='Show only deleted files when listing index')
    parser.add_argument('--show-moved', action='store_true', help='Highlight files that have been moved')
    parser.add_argument('--share', help='Filter index listing by share name')
    parser.add_argument('--export-csv', help='Export index to CSV file')
    parser.add_argument('--deleted-report', action='store_true', help='Generate report of deleted files')
    parser.add_argument('--report-path', help='Path for deleted files report')
    parser.add_argument('--generate-delete-script', action='store_true', help='Generate a script with AWS CLI commands to delete files from S3')
    parser.add_argument('--script-path', help='Path for S3 delete script')
    parser.add_argument('--sync-index-with-aws', action='store_true', 
                        help='Synchronize index with AWS S3 and Windows shares (no uploads)')
    parser.add_argument('--s3-only', action='store_true', 
                        help='Show only files that exist in S3 but not in Windows shares')
    
    args = parser.parse_args()
    
    # Create password file if requested
    if args.create_password_file:
        try:
            pw = args.password
            if not pw:
                pw = getpass.getpass("Enter password to store in file: ")
                pw_confirm = getpass.getpass("Confirm password: ")
                if pw != pw_confirm:
                    print("Passwords do not match!")
                    return
            
            # Create the file with restricted permissions
            with open(args.create_password_file, 'w') as f:
                f.write(pw)
            
            # Set permissions to owner-read-only (600)
            os.chmod(args.create_password_file, 0o600)
            
            print(f"Password file created at {args.create_password_file} with restricted permissions")
            print("You can use it with --password-file option for unattended operations")
            return
        except Exception as e:
            logger.error(f"Error creating password file: {str(e)}")
            return
    
    # Check if config exists and is encrypted
    config_exists = os.path.exists(args.config)
    encrypted = config_exists and is_encrypted(args.config)
    
    # Handle password for encryption/decryption
    password = args.password
    
    # Try to get password from environment variable if specified
    if not password and args.password_env:
        env_password = os.environ.get(args.password_env)
        if env_password:
            password = env_password
        else:
            logger.warning(f"Environment variable {args.password_env} not found or empty")
    
    # Try to get password from file if specified
    if not password and args.password_file:
        try:
            with open(args.password_file, 'r') as f:
                password = f.read().strip()
        except Exception as e:
            logger.error(f"Error reading password file: {str(e)}")
    
    # Prompt for password if still not available and needed
    if (encrypted or args.encrypt_config) and not password:
        # Request password from user if not provided and needed
        try:
            password = getpass.getpass("Enter password for config encryption/decryption: ")
        except Exception as e:
            logger.error(f"Error getting password: {str(e)}")
            return
    
    # Create config object with password if needed
    config = Config(args.config, password=password)
    
    # Handle encryption of existing config
    if args.encrypt_config and config_exists and not encrypted:
        # Read the existing config
        with open(args.config, 'r') as f:
            config_data = f.read()
        
        # Encrypt it
        encrypted_data, salt = encrypt_config(config_data, password)
        
        # Write the encrypted data
        with open(args.config, 'wb') as f:
            f.write(encrypted_data)
        
        # Save the salt to a separate file
        salt_file = os.path.join(os.path.dirname(args.config), CONFIG_SALT_FILE)
        with open(salt_file, 'wb') as f:
            f.write(salt)
        
        logger.info(f"Configuration file encrypted: {args.config}")
        print(f"Successfully encrypted configuration file: {args.config}")
        return
    
    # Create default configuration if requested
    if args.create_config:
        config.create_default_config(encrypt=args.encrypt_config)
        return
    
    # Test connection if requested
    if args.test_connection:
        test_share_connections(config)
        return
    
    # Handle the new sync-index-with-aws argument
    if args.sync_index_with_aws:
        backup_manager = BackupManager(config)
        try:
            backup_manager.sync_index_with_aws()
        finally:
            backup_manager.close()
        return
        
    # List index if requested
    if args.list_index:
        list_index(config, show_deleted=args.show_deleted, share_filter=args.share, 
                  export_path=args.export_csv, include_moved=args.show_moved, s3_only=args.s3_only)
        return
        
    # Generate deleted files report if requested
    if args.deleted_report:
        generate_deleted_report(config, args.report_path)
        return
        
    # Generate S3 delete script if requested
    if args.generate_delete_script:
        generate_s3_delete_script(config, args.script_path)
        return
    
    # Initialize database and build initial index if requested
    if args.initialize:
        backup_manager = BackupManager(config)
        try:
            backup_manager.build_initial_index()
        finally:
            backup_manager.close()
    
    # Run backup immediately if requested
    if args.run_now:
        run_scheduled_backup(config)
    
    # Set up scheduled backups if requested
    if args.schedule:
        logger.info(f"Setting up scheduled backups every {config.scan_interval} hours")
        
        # Schedule the job
        schedule.every(config.scan_interval).hours.do(run_scheduled_backup, config)
        
        # Run the scheduler
        try:
            while True:
                schedule.run_pending()
                time.sleep(60)  # Sleep for 1 minute
        except KeyboardInterrupt:
            logger.info("Backup scheduler stopped by user")


if __name__ == '__main__':
    main()
