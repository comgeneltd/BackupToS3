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
import io
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

# Initial basic logging configuration (will be replaced by setup_logging)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('s3_backup')

def setup_logging(config):
    """Set up logging with a new log file for each run based on date."""
    # Ensure log directory exists
    os.makedirs(config.log_path, exist_ok=True)
    
    # Create log filename with timestamp
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(config.log_path, f's3_backup_{timestamp}.log')
    
    # Create formatter
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Remove any existing handlers to avoid duplicates
    for hdlr in root_logger.handlers[:]:
        root_logger.removeHandler(hdlr)
    
    # Add file handler for the new log file
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)
    root_logger.addHandler(file_handler)
    
    # Add console handler
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    root_logger.addHandler(console)
    
    logger = logging.getLogger('s3_backup')
    logger.info(f"Logging to: {log_file}")
    return logger

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

def cleanup_old_logs(config):
    """Remove log files older than the configured retention period."""
    log_path = config.log_path
    retention_days = config.log_retention_days
    
    # Calculate cutoff date
    cutoff_time = time.time() - (retention_days * 24 * 3600)
    
    # Ensure log directory exists
    if not os.path.exists(log_path):
        logger.debug(f"Log directory {log_path} does not exist, nothing to clean up")
        return
    
    # Find and remove old log files
    count = 0
    for filename in os.listdir(log_path):
        if filename.startswith('s3_backup_') and filename.endswith('.log'):
            filepath = os.path.join(log_path, filename)
            if os.path.isfile(filepath) and os.path.getmtime(filepath) < cutoff_time:
                try:
                    os.remove(filepath)
                    count += 1
                except Exception as e:
                    logger.error(f"Failed to remove old log {filepath}: {e}")
    
    if count > 0:
        logger.info(f"Removed {count} log files older than {retention_days} days")

def cleanup_old_reports(config):
    """Remove report files older than the configured retention period."""
    report_path = config.report_path
    retention_days = config.report_retention_days
    
    # Calculate cutoff date
    cutoff_time = time.time() - (retention_days * 24 * 3600)
    
    # Ensure report directory exists
    if not os.path.exists(report_path):
        logger.debug(f"Report directory {report_path} does not exist, nothing to clean up")
        return
    
    # Find and remove old report files
    count = 0
    for filename in os.listdir(report_path):
        if filename.startswith('backup_report_') and filename.endswith('.csv'):
            filepath = os.path.join(report_path, filename)
            if os.path.isfile(filepath) and os.path.getmtime(filepath) < cutoff_time:
                try:
                    os.remove(filepath)
                    count += 1
                except Exception as e:
                    logger.error(f"Failed to remove old report {filepath}: {e}")
    
    if count > 0:
        logger.info(f"Removed {count} report files older than {retention_days} days")

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
        self.use_xxhash = False  # Default to not use xxhash for compatibility
        
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
        self.multipart_threshold = 8 * 1024 * 1024  # 8MB default
        self.multipart_max_concurrent = 4  # Default concurrent part uploads
        self.large_file_threshold = 1024 * 1024 * 1024  # 1GB default
        self.checksum_parallel_threshold = 100 * 1024 * 1024  # 100MB default
        self.checksum_parallel_processes = None  # Default to CPU count
        self.direct_upload_threshold = 500 * 1024 * 1024  # 500MB default - files larger than this use direct streaming
        self.aws_secret_key = ''
        self.aws_region = 'us-east-1'
        self.s3_bucket = ''
        self.checksum_retry_count = 3  # Default number of retries for checksum calculation
        self.s3_prefix = ''  # No prefix by default
        self.storage_class = 'STANDARD_IA'  # Default storage class
        self.db_path = 'backup_index.db'
        self.report_path = 'reports/'
        self.log_path = 'logs/'  # Directory for storing logs
        self.log_retention_days = 30  # Number of days to keep logs
        self.report_retention_days = 30  # Number of days to keep reports
        self.shares = []
        self.scan_interval = 24  # hours
        self.thread_count = 4
        
        # Email notification defaults
        self.email_enabled = False
        self.email_smtp_server = 'localhost'
        self.email_smtp_port = 25
        self.email_from = ''
        self.email_to = ''
        self.email_subject_prefix = 'S3 Tool'  # Changed as requested
        self.email_attach_report = False  # Whether to attach backup reports to emails
        self.email_max_attachment_size = 10 * 1024 * 1024  # 10MB default
        
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
                
                # Properly get storage_class and normalize it
                self.storage_class = self.config['AWS'].get('storage_class', 'STANDARD_IA').upper().replace(' ', '_')
                logger.debug(f"Loaded storage class from config: {self.storage_class}")
            
            # General Settings
            if 'General' in self.config:
                self.db_path = self.config['General'].get('db_path', 'backup_index.db')
                self.report_path = self.config['General'].get('report_path', 'reports/')
                self.log_path = self.config['General'].get('log_path', 'logs/')
                self.log_retention_days = int(self.config['General'].get('log_retention_days', '30'))
                self.report_retention_days = int(self.config['General'].get('report_retention_days', '30'))
                self.scan_interval = int(self.config['General'].get('scan_interval', '24'))
                self.thread_count = int(self.config['General'].get('thread_count', '4'))
                self.multipart_threshold = int(self.config['General'].get('multipart_threshold', str(8 * 1024 * 1024)))
                self.multipart_max_concurrent = int(self.config['General'].get('multipart_max_concurrent', '4'))
                self.large_file_threshold = int(self.config['General'].get('large_file_threshold', str(1024 * 1024 * 1024)))
                self.checksum_parallel_threshold = int(self.config['General'].get('checksum_parallel_threshold', str(100 * 1024 * 1024)))
                self.direct_upload_threshold = int(self.config['General'].get('direct_upload_threshold', str(500 * 1024 * 1024)))
                self.checksum_parallel_processes = self.config['General'].get('checksum_parallel_processes', None)
                if self.checksum_parallel_processes:
                    self.checksum_parallel_processes = int(self.checksum_parallel_processes)
                self.use_xxhash = self.config['General'].getboolean('use_xxhash', False)
                self.checksum_retry_count = int(self.config['General'].get('checksum_retry_count', '3'))
            
            # Email notification settings
            if 'Email' in self.config:
                self.email_enabled = self.config['Email'].getboolean('enabled', False)
                self.email_smtp_server = self.config['Email'].get('smtp_server', 'localhost')
                self.email_smtp_port = int(self.config['Email'].get('smtp_port', '25'))
                self.email_from = self.config['Email'].get('from', '')
                self.email_to = self.config['Email'].get('to', '')
                self.email_subject_prefix = self.config['Email'].get('subject_prefix', 'S3 Tool')
                self.email_attach_report = self.config['Email'].getboolean('attach_report', False)
                self.email_max_attachment_size = int(self.config['Email'].get('max_attachment_size', '10485760'))
            
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
            'log_path': 'logs/',
            'log_retention_days': '30',
            'report_retention_days': '30',
            'scan_interval': '24',
            'thread_count': '4',
            'multipart_threshold': '8388608',  # 8MB in bytes
            'multipart_max_concurrent': '4',    # Maximum concurrent part uploads
            'large_file_threshold': '1073741824',  # 1GB in bytes
            'checksum_parallel_threshold': '104857600',  # 100MB in bytes
            'direct_upload_threshold': '524288000',  # 500MB in bytes
            'checksum_parallel_processes': '',  # Empty means use CPU count
            'use_xxhash': 'false',  # Set to 'true' for faster checksums (requires xxhash package)
            'checksum_retry_count': '3'  # Number of retries for checksum calculation
        }
        
        self.config['Email'] = {
            'enabled': 'false',
            'smtp_server': 'localhost',
            'smtp_port': '25',
            'from': 'backup@example.com',
            'to': 'admin@example.com',
            'subject_prefix': 'S3 Tool',
            'attach_report': 'false',
            'max_attachment_size': '10485760'  # 10MB default
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
    
    def __init__(self, db_path, config=None):
        self.db_path = db_path
        self.config = config  # Store the config object
        self.conn = None
        self.lock = threading.RLock()  # Reentrant lock for thread safety
        self.initialize_db()
    
    def get_connection(self):
        """Get a thread-local database connection."""
        if not hasattr(threading.current_thread(), '_db_conn'):
            threading.current_thread()._db_conn = sqlite3.connect(self.db_path)
        return threading.current_thread()._db_conn
    
    def initialize_db(self):
        """Initialize the database and create tables if they don't exist."""
        try:
            with self.lock:
                self.conn = sqlite3.connect(self.db_path)
                cursor = self.conn.cursor()
                
                # Create files table with uploaded_to_s3 column
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
                    uploaded_to_s3 INTEGER DEFAULT 0,
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
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_name ON files (file_name)')  # Add index for file_name lookups
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_uploaded_to_s3 ON files (uploaded_to_s3)')  # Add index for uploaded_to_s3 lookups
                
                # Check for columns needing migration
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
                
                # If uploaded_to_s3 column is missing, add it
                if 'uploaded_to_s3' not in columns:
                    try:
                        logger.info("Adding uploaded_to_s3 column to files table")
                        cursor.execute("ALTER TABLE files ADD COLUMN uploaded_to_s3 INTEGER DEFAULT 0")
                        logger.info("All existing files will be marked as not confirmed in S3")
                        self.conn.commit()
                    except sqlite3.Error as e:
                        logger.error(f"Error adding uploaded_to_s3 column: {str(e)}")
                
                # If file_name column is missing, add it and populate from local_path
                if 'file_name' not in columns:
                    try:
                        logger.info("Adding file_name column to files table")
                        cursor.execute("ALTER TABLE files ADD COLUMN file_name TEXT")
                        
                        # Initialize file_name with basename from local_path
                        cursor.execute("""
                        UPDATE files SET file_name = 
                        CASE
                            WHEN instr(local_path, ':') > 0 
                            THEN substr(local_path, 
                                 instr(local_path, ':') + 1 + length(local_path) - 
                                 instr(reverse(local_path), '/') - instr(local_path, ':'))
                            ELSE substr(local_path, length(local_path) - instr(reverse(local_path), '/') + 1)
                        END
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
    
    def close(self):
        """Close the database connection."""
        with self.lock:
            if self.conn:
                self.conn.close()
                self.conn = None
    
    def add_file(self, local_path, s3_path, size, last_modified, checksum, previous_path=None, moved_in_s3=0, file_name=None, uploaded_to_s3=0):
        """Add or update a file in the index."""
        try:
            with self.lock:
                conn = self.get_connection()
                cursor = conn.cursor()
                now = datetime.datetime.now()
                
                # If file_name not provided, extract it from local_path
                if file_name is None:
                    file_path_part = local_path.split(':', 1)[1] if ':' in local_path else local_path
                    file_name = os.path.basename(file_path_part)
                
                cursor.execute('''
                INSERT INTO files (local_path, s3_path, size, last_modified, checksum, last_backup, previous_path, moved_in_s3, file_name, uploaded_to_s3)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(local_path) DO UPDATE SET
                    s3_path=excluded.s3_path,
                    size=excluded.size,
                    last_modified=excluded.last_modified,
                    checksum=excluded.checksum,
                    is_deleted=0,
                    last_backup=excluded.last_backup,
                    previous_path=excluded.previous_path,
                    moved_in_s3=excluded.moved_in_s3,
                    file_name=excluded.file_name,
                    uploaded_to_s3=excluded.uploaded_to_s3
                ''', (local_path, s3_path, size, last_modified, checksum, now, previous_path, moved_in_s3, file_name, uploaded_to_s3))
                
                conn.commit()
                return True
        except sqlite3.Error as e:
            logger.error(f"Error adding file to database: {str(e)}")
            return False
    
    def mark_deleted(self, local_path):
        """Mark a file as deleted in the local index."""
        try:
            with self.lock:
                conn = self.get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                UPDATE files SET is_deleted=1 WHERE local_path=?
                ''', (local_path,))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error as e:
            logger.error(f"Error marking file as deleted: {str(e)}")
            return False
    
    def get_file_by_path(self, local_path):
        """Get file information by local path."""
        try:
            with self.lock:
                conn = self.get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                SELECT id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup, file_name, previous_path, moved_in_s3, uploaded_to_s3
                FROM files WHERE local_path=?
                ''', (local_path,))
                return cursor.fetchone()
        except sqlite3.Error as e:
            logger.error(f"Error fetching file: {str(e)}")
            return None
    
    def get_file_by_checksum(self, checksum):
        """Get file information by checksum."""
        try:
            with self.lock:
                conn = self.get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                SELECT id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup, file_name, previous_path, moved_in_s3, uploaded_to_s3
                FROM files WHERE checksum=? AND is_deleted=0 LIMIT 1
                ''', (checksum,))
                return cursor.fetchone()
        except sqlite3.Error as e:
            logger.error(f"Error fetching file by checksum: {str(e)}")
            return None
    
    def get_all_files(self, include_deleted=False):
        """Get all files from the index."""
        try:
            with self.lock:
                conn = self.get_connection()
                cursor = conn.cursor()
                if include_deleted:
                    cursor.execute('''
                    SELECT id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup, file_name, previous_path, moved_in_s3, uploaded_to_s3
                    FROM files
                    ''')
                else:
                    cursor.execute('''
                    SELECT id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup, file_name, previous_path, moved_in_s3, uploaded_to_s3
                    FROM files WHERE is_deleted=0
                    ''')
                return cursor.fetchall()
        except sqlite3.Error as e:
            logger.error(f"Error fetching files: {str(e)}")
            return []
    
    def get_deleted_files(self):
        """Get all files marked as deleted."""
        try:
            with self.lock:
                conn = self.get_connection()
                cursor = conn.cursor()
                cursor.execute('''
                SELECT id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup, file_name
                FROM files WHERE is_deleted=1
                ''')
                return cursor.fetchall()
        except sqlite3.Error as e:
            logger.error(f"Error fetching deleted files: {str(e)}")
            return []
    
    def start_backup_run(self):
        """Start a new backup run and return its ID."""
        try:
            with self.lock:
                conn = self.get_connection()
                cursor = conn.cursor()
                now = datetime.datetime.now()
                cursor.execute('''
                INSERT INTO backup_runs (start_time, status)
                VALUES (?, 'RUNNING')
                ''', (now,))
                conn.commit()
                return cursor.lastrowid
        except sqlite3.Error as e:
            logger.error(f"Error starting backup run: {str(e)}")
            return None
    
    def finish_backup_run(self, run_id, status, files_processed, files_uploaded, bytes_uploaded, files_failed):
        """Mark a backup run as finished with statistics."""
        try:
            with self.lock:
                conn = self.get_connection()
                cursor = conn.cursor()
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
                conn.commit()
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
        
    def calculate_parallel_checksum(self, file_path, num_processes=None):
        """Calculate MD5 checksum using parallel processing for large files."""
        import multiprocessing
        
        if num_processes is None:
            num_processes = multiprocessing.cpu_count()
        
        file_size = os.path.getsize(file_path)
        chunk_size = max(file_size // num_processes, 5*1024*1024)  # At least 5MB chunks
        
        # Create chunks based on file size
        chunks = []
        for i in range(0, file_size, chunk_size):
            chunks.append((i, min(chunk_size, file_size - i)))
        
        # Function to calculate checksum for a chunk
        def chunk_checksum(start, size):
            md5 = hashlib.md5()
            with open(file_path, 'rb') as f:
                f.seek(start)
                chunk = f.read(size)
            md5.update(chunk)
            return md5.digest()
        
        # Process chunks in parallel
        with multiprocessing.Pool(processes=num_processes) as pool:
            results = pool.starmap(chunk_checksum, chunks)
        
        # Combine checksums
        final_md5 = hashlib.md5()
        for digest in results:
            final_md5.update(digest)
        
        return final_md5.hexdigest()
        
    def calculate_xxhash(self, file_path, chunk_size=8192):
        """Use xxHash64 instead of MD5 (5-10x faster)."""
        try:
            import xxhash
            
            # For local files
            if os.path.exists(file_path):
                xxh = xxhash.xxh64()
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(chunk_size), b''):
                        xxh.update(chunk)
                return xxh.hexdigest()
            
            # For SMB paths, use streaming approach
            elif hasattr(self, 'conn') and self.conn:
                try:
                    # Extract share info
                    if ':' in file_path:
                        share_name, share_path = self.extract_share_path(file_path)
                    else:
                        share_name = self.share_config['name']
                        share_path = file_path
                    
                    # Use a temp file in memory
                    import tempfile
                    temp_file = tempfile.SpooledTemporaryFile(max_size=10 * 1024 * 1024)
                    try:
                        self.conn.retrieveFile(share_name, share_path, temp_file)
                        temp_file.seek(0)
                        
                        xxh = xxhash.xxh64()
                        for chunk in iter(lambda: temp_file.read(chunk_size), b''):
                            xxh.update(chunk)
                        return xxh.hexdigest()
                    finally:
                        temp_file.close()
                except Exception as e:
                    logger.error(f"Error in xxhash for SMB file: {e}")
                    raise
            else:
                raise FileNotFoundError(f"File not found: {file_path}")
                
        except ImportError:
            logger.warning("xxhash module not installed. Falling back to MD5.")
            
            # For local files
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    return self.calculate_checksum(f)
            # For SMB paths
            else:
                return self.calculate_streaming_checksum(file_path)
    
    def extract_share_path(self, file_path):
        """Extract share name and relative path from a file path."""
        # Normalize file path: remove leading/trailing whitespace and ensure forward slashes
        if file_path:
            file_path = file_path.strip().replace('\\', '/')
        
        # Handle paths in format "sharename:/path/to/file.ext"
        parts = file_path.split(':', 1)
        if len(parts) == 2:
            return parts[0], parts[1]
        
        # For paths without colon, use the current SMB share name
        if hasattr(self, 'share_config') and self.share_config:
            # Use the actual SMB share name, not the local_name
            if 'name' in self.share_config:
                share_name = self.share_config['name']  # 'Share' instead of 'data'
                logger.debug(f"Using current SMB share '{share_name}' for file: {file_path}")
                
                # Make sure file_path doesn't start with a slash to avoid double slashes
                if file_path.startswith('/'):
                    file_path = file_path[1:]
                
                return share_name, file_path
        
        # If we get here, we couldn't determine the share
        raise ValueError(f"Invalid file path format: {file_path}")
    
    def get_smb_file_size(self, file_path):
        """Get file size for SMB path."""
        share_name, path = self.extract_share_path(file_path)
        try:
            file_info = self.conn.getAttributes(share_name, path)
            return file_info.file_size
        except Exception as e:
            logger.error(f"Error getting SMB file size: {str(e)}")
            raise
            
    def standard_checksum(self, file_path):
        """Standard (non-optimized) checksum calculation."""
        # For local files
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                return self.calculate_checksum(f)
        # For SMB shares
        else:
            return self.calculate_streaming_checksum(file_path)
            
    def fast_large_file_checksum(self, file_path):
        """Faster checksum calculation for very large files."""
        # Check if xxhash should be used (from config)
        config_allows_xxhash = False
        
        # Try to get config from db_manager if available
        if hasattr(self, 'db_manager') and hasattr(self.db_manager, 'config') and self.db_manager.config:
            config_allows_xxhash = getattr(self.db_manager.config, 'use_xxhash', False)
        
        # Special handling for SMB paths
        need_local_file = not os.path.exists(file_path)
        temp_path = None
        
        try:
            # For SMB paths, download to temp first
            if need_local_file and hasattr(self, 'conn') and self.conn:
                try:
                    # Determine the share name based on the path
                    if ':' in file_path:
                        share_name, share_path = self.extract_share_path(file_path)
                    else:
                        share_name = self.share_config['name']
                        share_path = file_path
                    
                    # Download to temp file
                    temp_path = self.get_temp_file(share_path, os.path.basename(share_path))
                    logger.debug(f"Downloaded {file_path} to {temp_path} for fast checksum")
                    file_path = temp_path
                except Exception as e:
                    logger.error(f"Error downloading file for fast checksum: {e}")
                    raise
            
            # First try xxHash for speed if allowed or not explicitly configured
            if config_allows_xxhash or config_allows_xxhash is None:
                try:
                    import xxhash
                    return self.calculate_xxhash(file_path)
                except ImportError:
                    logger.warning("xxhash module not available, falling back to parallel checksum")
            else:
                logger.debug("xxhash disabled in config, using parallel MD5")
                
            # Fall back to parallel method
            return self.calculate_parallel_checksum(file_path)
            
        finally:
            # Clean up temp file if we created one
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception as e:
                    logger.warning(f"Failed to clean up temp file {temp_path}: {e}")
            
    def parallel_checksum(self, file_path, num_processes=None):
        """Parallel implementation of checksum calculation."""
        
        # For local files
        if os.path.exists(file_path):
            return self.calculate_parallel_checksum(file_path, num_processes)
        
        # For SMB paths, download to temp first
        elif hasattr(self, 'conn') and self.conn:
            try:
                # Determine the share name based on the path
                if ':' in file_path:
                    share_name, share_path = self.extract_share_path(file_path)
                else:
                    share_name = self.share_config['name']
                    share_path = file_path
                
                # Download to temp file
                temp_path = self.get_temp_file(share_path, os.path.basename(share_path))
                logger.debug(f"Downloaded {file_path} to {temp_path} for parallel checksum")
                
                # Calculate checksum on the temp file
                try:
                    return self.calculate_parallel_checksum(temp_path, num_processes)
                finally:
                    # Clean up temp file
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
            except Exception as e:
                logger.error(f"Error in parallel checksum for SMB path: {e}")
                raise
        
        else:
            raise FileNotFoundError(f"File not found and no SMB connection available: {file_path}")
    
    def smart_checksum(self, file_path, retry_count=3, parallel=True):
        """Smart checksum with optimized handling for large files."""
        
        start_time = time.time()
        
        for attempt in range(retry_count):
            try:
                # Get file size first to determine strategy
                file_size = None
                
                # For SMB paths
                if hasattr(self, 'conn') and self.conn:
                    try:
                        # Extract share name and relative path
                        if ':' in file_path:
                            share_name, file_path_rel = self.extract_share_path(file_path)
                        else:
                            share_name = self.share_config['name']
                            file_path_rel = file_path
                        
                        # Get file attributes
                        file_attr = self.conn.getAttributes(share_name, file_path_rel)
                        file_size = file_attr.file_size
                        
                        # Get thresholds from config
                        partial_checksum_threshold = 500 * 1024 * 1024  # 500MB default
                        medium_file_threshold = 50 * 1024 * 1024  # 50MB default
                        
                        # Try to get config from db_manager if available
                        if hasattr(self, 'db_manager') and hasattr(self.db_manager, 'config') and self.db_manager.config:
                            config = self.db_manager.config
                            partial_checksum_threshold = getattr(config, 'partial_checksum_threshold', partial_checksum_threshold)
                            medium_file_threshold = getattr(config, 'medium_file_threshold', medium_file_threshold)
                        
                        # LARGE FILE STRATEGY (over 500MB)
                        if file_size > partial_checksum_threshold:
                            logger.info(f"Using smart partial checksum for large file: {file_path} ({format_size(file_size)})")
                            
                            # Variables for gathering partial content
                            file_parts = []
                            
                            # Sample beginning of file (first 256KB)
                            begin_buffer = io.BytesIO()
                            self.conn.retrieveFileFromOffset(share_name, file_path_rel, begin_buffer, 0, 262144)
                            begin_buffer.seek(0)
                            file_parts.append(begin_buffer.getvalue())
                            
                            # Sample middle of file (256KB from middle)
                            middle_offset = max(file_size // 2 - 131072, 262144)
                            middle_buffer = io.BytesIO()
                            self.conn.retrieveFileFromOffset(share_name, file_path_rel, middle_buffer, middle_offset, 262144)
                            middle_buffer.seek(0)
                            file_parts.append(middle_buffer.getvalue())
                            
                            # Sample end of file (last 256KB)
                            end_offset = max(file_size - 262144, middle_offset + 262144)
                            end_buffer = io.BytesIO()
                            self.conn.retrieveFileFromOffset(share_name, file_path_rel, end_buffer, end_offset, 262144)
                            end_buffer.seek(0)
                            file_parts.append(end_buffer.getvalue())
                            
                            # Calculate MD5 of the sampled parts
                            composite_md5 = hashlib.md5()
                            for part in file_parts:
                                composite_md5.update(part)
                            
                            # Create a composite fingerprint with metadata
                            fingerprint = f"partial-{file_size}-{file_attr.last_write_time}-{composite_md5.hexdigest()}"
                            logger.info(f"Generated partial checksum in {time.time() - start_time:.2f} seconds")
                            return fingerprint
                            
                        # MEDIUM FILE STRATEGY (50MB to 500MB) - use parallel checksumming
                        elif file_size > medium_file_threshold and parallel:
                            # Download file to temp and use parallel checksum
                            temp_path = self.get_temp_file(file_path_rel, os.path.basename(file_path_rel))
                            try:
                                return self.parallel_checksum(temp_path)
                            finally:
                                if os.path.exists(temp_path):
                                    os.unlink(temp_path)
                                    
                        # SMALL FILE STRATEGY - use standard checksumming
                        else:
                            return self.calculate_streaming_checksum(file_path)
                            
                    except Exception as e:
                        logger.error(f"Error in smart checksum: {e}")
                        raise
                        
                # For local files
                else:
                    # Determine which strategy based on file size
                    if os.path.exists(file_path):
                        file_size = os.path.getsize(file_path)
                    else:
                        raise FileNotFoundError(f"Local file not found: {file_path}")
                    
                    # Get thresholds from config
                    partial_checksum_threshold = 500 * 1024 * 1024  # 500MB default
                    medium_file_threshold = 50 * 1024 * 1024  # 50MB default
                    
                    # Try to get config from db_manager if available
                    if hasattr(self, 'db_manager') and hasattr(self.db_manager, 'config') and self.db_manager.config:
                        config = self.db_manager.config
                        partial_checksum_threshold = getattr(config, 'partial_checksum_threshold', partial_checksum_threshold)
                        medium_file_threshold = getattr(config, 'medium_file_threshold', medium_file_threshold)
                    
                    # Large file strategy
                    if file_size > partial_checksum_threshold:
                        logger.info(f"Using partial checksum for large local file: {file_path}")
                        
                        # Sample beginning, middle and end
                        with open(file_path, 'rb') as f:
                            # Read beginning
                            begin_data = f.read(262144)
                            
                            # Read middle
                            f.seek(max(file_size // 2 - 131072, 262144))
                            middle_data = f.read(262144)
                            
                            # Read end
                            f.seek(max(file_size - 262144, 0))
                            end_data = f.read(262144)
                        
                        # Combine into composite checksum
                        composite_md5 = hashlib.md5()
                        composite_md5.update(begin_data)
                        composite_md5.update(middle_data)
                        composite_md5.update(end_data)
                        
                        # Create fingerprint with metadata
                        mtime = os.path.getmtime(file_path)
                        fingerprint = f"partial-{file_size}-{mtime}-{composite_md5.hexdigest()}"
                        logger.info(f"Generated partial checksum in {time.time() - start_time:.2f} seconds")
                        return fingerprint
                    
                    # Medium files
                    elif file_size > medium_file_threshold and parallel:
                        return self.parallel_checksum(file_path)
                    
                    # Small files
                    else:
                        with open(file_path, 'rb') as f:
                            return self.calculate_checksum(f)
                
            except FileNotFoundError as e:
                if attempt == retry_count - 1:
                    logger.error(f"File not found after {retry_count} attempts: {file_path}")
                    raise
                else:
                    time.sleep(2)
                    logger.warning(f"Retrying checksum for file {file_path}, attempt {attempt+2}/{retry_count}")
                    
            except Exception as e:
                logger.error(f"Error calculating checksum for {file_path}: {str(e)}")
                if attempt == retry_count - 1:
                    raise
                time.sleep(2)
        
        raise RuntimeError(f"Failed to calculate checksum for {file_path} after {retry_count} attempts")
    
    def calculate_streaming_checksum(self, file_path):
        """Calculate MD5 checksum by streaming the file without saving to disk."""
        import tempfile
        md5 = hashlib.md5()
        file_obj = tempfile.SpooledTemporaryFile(max_size=10*1024*1024)  # 10MB in-memory buffer
        
        try:
            self.conn.retrieveFile(self.share_config['name'], file_path, file_obj)
            file_obj.seek(0)
            
            for chunk in iter(lambda: file_obj.read(8192), b''):
                md5.update(chunk)
                
            return md5.hexdigest()
        finally:
            file_obj.close()
    
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
                    
                    # Get the uploaded_to_s3 flag (0 = not uploaded, 1 = uploaded)
                    uploaded_to_s3 = 0
                    if existing_file and len(existing_file) >= 12:  # Make sure the field exists
                        uploaded_to_s3 = existing_file[11]
                        
                    # Only skip if file exists, hasn't changed AND has been uploaded to S3
                    if existing_file and int(existing_file[3]) == file_info.file_size and \
                       existing_file[4] == last_modified.isoformat() and uploaded_to_s3 == 1:
                        continue
                    
                    # For changed or new files, calculate checksum
                    try:
                        # Calculate checksum using the most efficient method based on file size with retries
                        # Get retry count from config if available
                        retry_count = 3  # Default value
                        
                        # Try to get config from db_manager if available
                        if hasattr(self.db_manager, 'config') and self.db_manager.config:
                            retry_count = getattr(self.db_manager.config, 'checksum_retry_count', retry_count)
                        checksum = self.smart_checksum(full_path, retry_count=retry_count)
                        
                        # Yield the file information
                        yield {
                            'local_path': local_path,
                            'share_path': full_path,
                            'size': file_info.file_size,
                            'last_modified': last_modified,
                            'checksum': checksum,
                            'share_config': self.share_config,
                            'file_name': file_name  # Add filename for proper comparison
                        }
                    except Exception as e:
                        logger.error(f"Error processing file {full_path}: {str(e)}")
        except Exception as e:
            logger.error(f"Error scanning directory {path}: {str(e)}")


class S3Manager:
    """Manager for S3 operations."""
    
    def __init__(self, config):
        self.config = config
        
        # Configure boto3 session with larger connection pool
        session = boto3.session.Session()
        
        # Create a client with custom connection pool config
        self.s3_client = session.client(
            's3',
            aws_access_key_id=config.aws_access_key,
            aws_secret_access_key=config.aws_secret_key,
            region_name=config.aws_region,
            config=boto3.session.Config(
                max_pool_connections=50,  # Increase from default of 10
                retries={'max_attempts': 3},
                connect_timeout=60,
                read_timeout=300  # 5 minutes for large file operations
            )
        )
    
    def upload_file(self, local_file_path, s3_key):
        """Upload a file to S3 storage with automatic multipart for large files."""
        try:
            # Configure thresholds
            file_size = os.path.getsize(local_file_path)
            multipart_threshold = self.config.multipart_threshold
            
            # Use the storage_class attribute from config
            storage_class = self.config.storage_class
            logger.debug(f"Using storage class for upload: {storage_class}")
            
            if file_size > multipart_threshold:
                logger.info(f"Using multipart upload for {local_file_path} ({format_size(file_size)})")
                return self._upload_multipart_concurrent(local_file_path, s3_key, file_size, storage_class)
            else:
                # Standard upload for smaller files
                extra_args = {
                    'StorageClass': storage_class
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
            # Add error details for better debugging
            if hasattr(e, 'response') and 'Error' in e.response:
                logger.error(f"Error details: {e.response['Error']}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error uploading {local_file_path}: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return False
            
    def _upload_part(self, part_number, data, bucket, key, upload_id):
        """Upload a single part of a multipart upload."""
        try:
            response = self.s3_client.upload_part(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                PartNumber=part_number,
                Body=data
            )
            return response['ETag']
        except Exception as e:
            logger.error(f"Error uploading part {part_number}: {str(e)}")
            raise
            
    def _upload_multipart_concurrent(self, local_file_path, s3_key, file_size, storage_class):
        """Perform a concurrent multipart upload for large files with intelligent part sizing."""
        # Calculate optimal part size based on file size
        # - Amazon S3 supports up to 10,000 parts
        # - Each part must be between 5MB and 5GB
        # - For optimal performance, aim for larger parts for very large files
        
        min_part_size = 5 * 1024 * 1024  # 5MB minimum
        part_size = max(min_part_size, file_size // 10000)  # Ensure we don't exceed part count
        
        # For very large files, use larger part sizes for better performance
        if file_size > 1024 * 1024 * 1024 * 10:  # 10GB
            part_size = max(part_size, 100 * 1024 * 1024)  # Use at least 100MB parts
        elif file_size > 1024 * 1024 * 1024:  # 1GB
            part_size = max(part_size, 50 * 1024 * 1024)  # Use at least 50MB parts
        
        # Round up to nearest MB for cleaner sizes
        part_size = ((part_size + (1024 * 1024) - 1) // (1024 * 1024)) * (1024 * 1024)
        
        logger.debug(f"Using part size of {format_size(part_size)} for {format_size(file_size)} file")
        
        upload_id = None
        
        try:
            # 1. Initiate multipart upload
            response = self.s3_client.create_multipart_upload(
                Bucket=self.config.s3_bucket,
                Key=s3_key,
                StorageClass=storage_class
            )
            upload_id = response['UploadId']
            
            logger.debug(f"Initiated multipart upload ID: {upload_id}")
            
            # 2. Upload parts concurrently
            parts = []
            total_parts = (file_size + part_size - 1) // part_size
            
            with ThreadPoolExecutor(max_workers=self.config.multipart_max_concurrent) as executor:
                futures = []
                
                with open(local_file_path, 'rb') as f:
                    part_number = 1
                    
                    while True:
                        data = f.read(part_size)
                        if not data:
                            break
                        
                        # Submit upload task
                        future = executor.submit(
                            self._upload_part,
                            part_number,
                            data,
                            self.config.s3_bucket,
                            s3_key,
                            upload_id
                        )
                        futures.append((part_number, future))
                        part_number += 1
                
                # Process results
                for part_number, future in sorted(futures):
                    try:
                        etag = future.result()
                        parts.append({
                            'PartNumber': part_number,
                            'ETag': etag
                        })
                        logger.debug(f"Completed part {part_number}/{total_parts} for {s3_key}")
                    except Exception as e:
                        logger.error(f"Failed to upload part {part_number}: {str(e)}")
                        raise
            
            # 3. Complete multipart upload
            self.s3_client.complete_multipart_upload(
                Bucket=self.config.s3_bucket,
                Key=s3_key,
                UploadId=upload_id,
                MultipartUpload={'Parts': parts}
            )
            
            logger.info(f"Successfully completed multipart upload for {local_file_path} to s3://{self.config.s3_bucket}/{s3_key}")
            return True
            
        except Exception as e:
            logger.error(f"Error in multipart upload for {local_file_path}: {str(e)}")
            
            # Attempt to abort the multipart upload
            if upload_id:
                try:
                    self.s3_client.abort_multipart_upload(
                        Bucket=self.config.s3_bucket,
                        Key=s3_key,
                        UploadId=upload_id
                    )
                    logger.info(f"Aborted failed multipart upload ID: {upload_id}")
                except Exception as abort_error:
                    logger.error(f"Failed to abort multipart upload: {str(abort_error)}")
                
            return False
    
    def copy_object(self, source_key, dest_key):
        """Copy an object within the same S3 bucket."""
        try:
            # Source must include the bucket name
            copy_source = {'Bucket': self.config.s3_bucket, 'Key': source_key}
            
            # Use the storage_class attribute directly
            storage_class = self.config.storage_class
            logger.debug(f"Using storage class for copy: {storage_class}")
            
            # Copy the object with the same storage class
            self.s3_client.copy_object(
                CopySource=copy_source,
                Bucket=self.config.s3_bucket,
                Key=dest_key,
                StorageClass=storage_class
            )
            
            logger.info(f"Successfully copied s3://{self.config.s3_bucket}/{source_key} to s3://{self.config.s3_bucket}/{dest_key}")
            return True
        except botocore.exceptions.ClientError as e:
            logger.error(f"Error copying S3 object {source_key} to {dest_key}: {str(e)}")
            if hasattr(e, 'response') and 'Error' in e.response:
                logger.error(f"Error details: {e.response['Error']}")
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
            
    def check_object_exists(self, s3_key):
        """Check if an object exists in S3."""
        try:
            self.s3_client.head_object(
                Bucket=self.config.s3_bucket,
                Key=s3_key
            )
            return True
        except botocore.exceptions.ClientError as e:
            # If a 404 error is returned, the object doesn't exist
            if e.response['Error']['Code'] == '404':
                return False
            else:
                logger.error(f"Error checking S3 object {s3_key}: {str(e)}")
                # For other errors, assume the object doesn't exist to be safe
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
        self.db_manager = DatabaseManager(config.db_path, config)  # Pass config to DatabaseManager
        self.s3_manager = S3Manager(config)
        self.scan_errors = []  # Track directory scan errors
        
        # Ensure report directory exists
        os.makedirs(config.report_path, exist_ok=True)
    
    def close(self):
        """Clean up resources."""
        self.db_manager.close()
    
    def scan_shares(self, skip_move_detection=False):
        """
        Scan all configured shares and update the index.
        
        Args:
            skip_move_detection: If True, skips detecting moved/renamed files (used during initial indexing)
        """
        files_scanned = 0
        files_changed = 0
        self.files_moved = 0  # Track moved files
        self.files_renamed = 0  # Track renamed files
        
        # Keep track of recently deleted files by checksum for rename detection
        recently_deleted = {}
        
        # Skip move/rename detection if requested (for initial indexing)
        if not skip_move_detection:
            # First, look for deleted files and add them to our tracking dictionary
            for share_config in self.config.shares:
                scanner = ShareScanner(share_config, self.db_manager)
                try:
                    if scanner.connect():
                        # Get all non-deleted files for this share
                        with self.db_manager.lock:
                            conn = self.db_manager.get_connection()
                            cursor = conn.cursor()
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
                    
                    # During initial indexing, skip move/rename detection to avoid S3 operations
                    if skip_move_detection:
                        files_changed += 1
                        yield file_info, s3_key
                        continue
                    
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
                            # Get original file name and new file name
                            old_path = checksum_match[1]
                            old_name = checksum_match[8] if len(checksum_match) > 8 and checksum_match[8] else os.path.basename(old_path.split(':', 1)[1] if ':' in old_path else old_path)
                            new_name = file_info['file_name']
                            
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
                                                logger.info(f"Original file still exists at: {old_path}")
                                            except:
                                                old_file_exists = False
                                                logger.info(f"Original file no longer exists at: {old_path}")
                                    finally:
                                        old_scanner.disconnect()
                            
                            # Only consider it a move/rename if:
                            # 1. The file no longer exists in the old location, AND
                            # 2. The filename matches the old filename
                            if not old_file_exists and old_name == new_name:
                                logger.info(f"Detected true moved file: {old_path} -> {file_info['local_path']}")
                                logger.info(f"S3 path: {checksum_match[2]} -> {s3_key}")
                                
                                # Get existing record to check if it's already been moved in S3
                                with self.db_manager.lock:
                                    conn = self.db_manager.get_connection()
                                    cursor = conn.cursor()
                                    cursor.execute('''
                                    SELECT moved_in_s3 FROM files WHERE local_path=?
                                    ''', (file_info['local_path'],))
                                    result = cursor.fetchone()
                                    already_moved = result and result[0] == 1
                                
                                # This is a true moved file - update S3 to match if not already moved
                                old_s3_path = checksum_match[2]
                                new_s3_path = s3_key
                                
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
                                    moved_in_s3=moved_in_s3_flag,
                                    file_name=file_info['file_name']
                                )
                                
                                self.files_moved += 1
                                continue
                            else:
                                # This is a new file that happens to have the same content as another file
                                # Treat as a new file and upload it
                                logger.info(f"Found duplicate file with same content but not moved: {file_info['local_path']}")
                                logger.info(f"Original file: {old_path}, New file: {file_info['local_path']}")
                                files_changed += 1
                                yield file_info, s3_key
                                continue
                    
                    # If file changed or is new or hasn't been uploaded to S3, mark it for upload
                    uploaded_to_s3 = 0
                    if existing_file and len(existing_file) >= 12:  # Make sure the field exists
                        uploaded_to_s3 = existing_file[11]
                    
                    if not existing_file or existing_file[5] != file_info['checksum'] or uploaded_to_s3 == 0:
                        logger.info(f"File needs upload: {file_info['local_path']} (New: {not existing_file}, Changed: {existing_file and existing_file[5] != file_info['checksum']}, Not uploaded: {uploaded_to_s3 == 0})")
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
        """Build initial index from Windows shares only without uploading or accessing S3."""
        logger.info("Building initial index from Windows shares only (not accessing S3)...")
        
        # Initialize counters
        files_indexed = 0
        
        # Use our modified scan_shares method with skip_move_detection=True to avoid S3 operations
        for file_info, s3_key in self.scan_shares(skip_move_detection=True):
            # Add file to database as a new entry (no previous_path)
            # Explicitly set uploaded_to_s3=0 to indicate not uploaded
            self.db_manager.add_file(
                local_path=file_info['local_path'],
                s3_path=s3_key,
                size=file_info['size'],
                last_modified=file_info['last_modified'].isoformat(),
                checksum=file_info['checksum'],
                previous_path=None,
                moved_in_s3=0,
                file_name=file_info.get('file_name'),
                uploaded_to_s3=0  # Mark as not uploaded
            )
            
            files_indexed += 1
            
            if files_indexed % 1000 == 0:
                logger.info(f"Indexed {files_indexed} files so far")
        
        logger.info(f"Indexed {files_indexed} files from Windows shares")
        logger.info("Initial index building completed without accessing S3")
        logger.info("Run --run-now or --run-now-verify to upload files to S3")
    
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
                            moved_in_s3=0,
                            file_name=file_info['file_name']
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
                            moved_in_s3=0,
                            file_name=file_info['file_name']
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
        with self.db_manager.lock:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
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
            
            conn.commit()
        
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
                
                # Use a thread-safe connection
                with self.db_manager.lock:
                    conn = self.db_manager.get_connection()
                    cursor = conn.cursor()
                    
                    # Files only in S3
                    cursor.execute(
                        "SELECT local_path, s3_path, size, last_modified FROM files WHERE checksum='s3_only'"
                    )
                    s3_only_files = cursor.fetchall()
                    
                    # Prepare query for new files
                    new_files_by_share = {}
                    for share_name, stats in share_stats.items():
                        if stats['new'] > 0:
                            cursor.execute(
                                "SELECT local_path, size, last_modified FROM files WHERE local_path LIKE ? AND checksum != 's3_only' AND checksum != 's3_indexed'",
                                (f"{share_name}:%",)
                            )
                            new_files_by_share[share_name] = cursor.fetchall()
                
                # Now write the results outside the lock (to minimize lock time)
                for row in s3_only_files:
                    local_path, s3_path, size, last_modified = row
                    share_name = local_path.split(':', 1)[0]
                    file_path = local_path.split(':', 1)[1] if ':' in local_path else local_path
                    writer.writerow(['S3 Only', share_name, file_path, size, last_modified])
                
                # New files that need to be uploaded
                for share_name, new_files in new_files_by_share.items():
                    for row in new_files:
                        local_path, size, last_modified = row
                        file_path = local_path.split(':', 1)[1] if ':' in local_path else local_path
                        writer.writerow(['To Upload', share_name, file_path, size, last_modified])
            
            logger.info(f"Detailed report saved to {report_file}")
        except Exception as e:
            logger.error(f"Error writing report: {str(e)}")
        
        logger.info("Index synchronization completed")
    
    def direct_stream_to_s3(self, scanner, share_path, s3_key, file_size):
        """Stream a file directly from SMB to S3 without local storage."""
        # Initialize multipart upload
        response = self.s3_manager.s3_client.create_multipart_upload(
            Bucket=self.config.s3_bucket,
            Key=s3_key,
            StorageClass=self.config.storage_class
        )
        upload_id = response['UploadId']
        
        try:
            # Calculate optimal part size (min 5MB, aim for reasonable number of parts)
            part_size = max(5 * 1024 * 1024, min(100 * 1024 * 1024, file_size // 10))
            
            # Stream in chunks directly to S3
            parts = []
            part_number = 1
            offset = 0
            
            while offset < file_size:
                current_part_size = min(part_size, file_size - offset)
                
                # Create a memory buffer for this chunk
                buffer = io.BytesIO()
                
                # Read this chunk from SMB
                scanner.conn.retrieveFileFromOffset(
                    scanner.share_config['name'], 
                    share_path, 
                    buffer, 
                    offset, 
                    current_part_size
                )
                buffer.seek(0)
                
                # Upload this part to S3
                response = self.s3_manager.s3_client.upload_part(
                    Bucket=self.config.s3_bucket,
                    Key=s3_key,
                    UploadId=upload_id,
                    PartNumber=part_number,
                    Body=buffer.getvalue()
                )
                
                # Save the ETag
                parts.append({
                    'PartNumber': part_number,
                    'ETag': response['ETag']
                })
                
                # Move to next part
                part_number += 1
                offset += current_part_size
                logger.info(f"Uploaded part {part_number-1} of {share_path} ({format_size(current_part_size)})")
            
            # Complete the multipart upload
            self.s3_manager.s3_client.complete_multipart_upload(
                Bucket=self.config.s3_bucket,
                Key=s3_key,
                UploadId=upload_id,
                MultipartUpload={'Parts': parts}
            )
            
            return True
        except Exception as e:
            logger.error(f"Error in direct streaming upload: {str(e)}")
            # Abort the multipart upload
            try:
                self.s3_manager.s3_client.abort_multipart_upload(
                    Bucket=self.config.s3_bucket,
                    Key=s3_key,
                    UploadId=upload_id
                )
            except Exception as abort_error:
                logger.error(f"Failed to abort multipart upload: {str(abort_error)}")
            return False
    
    def smart_process_large_file(self, file_info, s3_key):
        """Optimized method for large files that skips redundant transfers."""
        share_path = file_info['share_path']
        share_config = file_info['share_config']
        
        # 1. Check if file exists in database with same size and modification time
        existing_file = self.db_manager.get_file_by_path(file_info['local_path'])
        if existing_file and existing_file[3] == file_info['size'] and \
           existing_file[4] == file_info['last_modified'].isoformat():
            # File hasn't changed - if it's already in S3, we're done
            # Check if the uploaded_to_s3 field exists and is set to 1
            uploaded_to_s3 = 0
            if existing_file and len(existing_file) >= 12:  # Make sure the field exists
                uploaded_to_s3 = existing_file[11]
                
            if uploaded_to_s3 == 1:
                logger.info(f"Large file unchanged and already in S3, skipping: {file_info['local_path']}")
                return True
        
        # 2. For large files (>500MB by default), use a partial checksum approach
        direct_upload_threshold = getattr(self.config, 'direct_upload_threshold', 500 * 1024 * 1024)
        if file_info['size'] > direct_upload_threshold:
            logger.info(f"Using partial checksum for large file: {share_path} ({format_size(file_info['size'])})")
            
            # Connect to share if needed
            scanner = ShareScanner(share_config, self.db_manager)
            if not scanner.connect():
                logger.error(f"Failed to connect to share {share_config['name']}")
                return False
            
            try:
                # Just stream directly to S3 without local temp storage
                # This is the key optimization - we're skipping the download-then-upload pattern
                success = self.direct_stream_to_s3(scanner, share_path, s3_key, file_info['size'])
                
                if success:
                    # Generate a simple checksum just for tracking (not for deduplication)
                    # We're using size + mtime as the effective "checksum" for very large files
                    simple_checksum = f"size_{file_info['size']}_mtime_{file_info['last_modified'].timestamp()}"
                    
                    # Update database with this file as uploaded
                    self.db_manager.add_file(
                        local_path=file_info['local_path'],
                        s3_path=s3_key,
                        size=file_info['size'],
                        last_modified=file_info['last_modified'].isoformat(),
                        checksum=simple_checksum,
                        previous_path=None,
                        moved_in_s3=0,
                        file_name=file_info.get('file_name', os.path.basename(share_path)),
                        uploaded_to_s3=1
                    )
                    return True
                
                return False
            finally:
                scanner.disconnect()
        
        # For smaller files, use the regular method
        return self.regular_upload_process(file_info, s3_key)
    
    def regular_upload_process(self, file_info, s3_key):
        """Regular upload process for normal sized files."""
        # Initialize variables
        temp_path = None
        scanner = None
        
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
                
                try:
                    # Upload to S3
                    success = self.s3_manager.upload_file(temp_path, s3_key)
                    
                    if success:
                        # Update the database - mark as uploaded to S3
                        self.db_manager.add_file(
                            local_path=file_info['local_path'],
                            s3_path=s3_key,
                            size=file_info['size'],
                            last_modified=file_info['last_modified'].isoformat(),
                            checksum=file_info['checksum'],
                            previous_path=None,
                            moved_in_s3=0,
                            file_name=file_info.get('file_name', os.path.basename(share_path)),
                            uploaded_to_s3=1  # Mark as uploaded
                        )
                        return True
                    return False
                finally:
                    # Clean up temp file
                    if os.path.exists(temp_path):
                        try:
                            os.unlink(temp_path)
                        except Exception as e:
                            logger.warning(f"Failed to remove temp file {temp_path}: {e}")
            finally:
                scanner.disconnect()
        except Exception as e:
            logger.error(f"Error uploading {file_info['local_path']}: {str(e)}")
            return False
    
    def upload_file_to_s3(self, file_info, s3_key):
        """Upload a file to S3 and update the index."""
        # Use the smart method which will handle both large and small files optimally
        return self.smart_process_large_file(file_info, s3_key)
    def verify_and_upload_missing(self):
        """
        Verify files in the index exist in S3 and upload any missing files.
        This is useful when the index database exists but files might not have been uploaded.
        """
        logger.info("Starting verification of index against S3 objects...")
        
        # Start tracking the backup run
        run_id = self.db_manager.start_backup_run()
        
        # Initialize counters
        files_processed = 0
        files_uploaded = 0
        bytes_uploaded = 0
        files_failed = 0
        
        # Prepare success/failure records for reporting
        success_records = []
        failure_records = []
        
        # Get all non-deleted files from the database
        all_files = self.db_manager.get_all_files(include_deleted=False)
        total_files = len(all_files)
        logger.info(f"Found {total_files} files in the index to verify")
        
        # Create a thread pool for parallel uploads
        with ThreadPoolExecutor(max_workers=self.config.thread_count) as executor:
            # Dictionary to track futures
            future_to_file = {}
            
            # Check each file in the index
            for file_record in all_files:
                file_id, local_path, s3_path, size, last_modified, checksum, is_deleted, last_backup, *_ = file_record
                files_processed += 1
                
                # Skip deleted files
                if is_deleted:
                    continue
                
                # Get uploaded_to_s3 flag if it exists
                uploaded_to_s3 = 0
                if len(file_record) >= 12:  # Make sure the uploaded_to_s3 field exists
                    uploaded_to_s3 = file_record[11]
                
                # Check if file exists in S3 or hasn't been marked as uploaded
                if not self.s3_manager.check_object_exists(s3_path) or uploaded_to_s3 == 0:
                    logger.info(f"File in index but not in S3: {local_path} -> {s3_path}")
                    
                    # Parse the local path to get share name and path
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
                    
                    # Create file_info object for upload
                    scanner = ShareScanner(share_config, self.db_manager)
                    try:
                        if scanner.connect():
                            try:
                                # Download to temp file for checksum calculation
                                temp_path = scanner.get_temp_file(file_path, os.path.basename(file_path))
                                
                                # Verify checksum matches what's in the database
                                with open(temp_path, 'rb') as file_obj:
                                    actual_checksum = scanner.calculate_checksum(file_obj)
                                
                                # If checksum has changed, update the database
                                if actual_checksum != checksum:
                                    logger.info(f"File checksum changed: {local_path}")
                                    checksum = actual_checksum
                                
                                # Create file_info for uploading
                                file_name = os.path.basename(file_path)
                                file_info = {
                                    'local_path': local_path,
                                    'share_path': file_path,
                                    'size': size,
                                    'last_modified': datetime.datetime.fromisoformat(last_modified),
                                    'checksum': checksum,
                                    'share_config': share_config,
                                    'file_name': file_name
                                }
                                
                                # Submit for upload
                                future = executor.submit(self.upload_file_to_s3, file_info, s3_path)
                                future_to_file[future] = (file_info, s3_path, temp_path)
                                
                            except Exception as e:
                                logger.error(f"Error processing file {file_path}: {str(e)}")
                                # Add to failure records
                                failure_records.append({
                                    'name': os.path.basename(file_path),
                                    'local_path': local_path,
                                    's3_path': s3_path,
                                    'size': size,
                                    'error': f"Error accessing file: {str(e)}"
                                })
                                files_failed += 1
                    finally:
                        scanner.disconnect()
                
                # Log progress every 100 files
                if files_processed % 100 == 0:
                    logger.info(f"Verified {files_processed}/{total_files} files")
            
            # Process completed uploads
            for future in future_to_file:
                file_info, s3_key, temp_path = future_to_file[future]
                
                try:
                    # Remove temp file regardless of upload success
                    if os.path.exists(temp_path):
                        os.unlink(temp_path)
                    
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
        
        # Update backup run status
        status = 'COMPLETED' if files_failed == 0 else 'COMPLETED_WITH_ERRORS'
        self.db_manager.finish_backup_run(
            run_id, status, files_processed, files_uploaded, bytes_uploaded, files_failed
        )
        
        # Generate report
        self.generate_report(success_records, failure_records)
        
        # Add run details
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        details = f"""
VERIFICATION SUMMARY ({now})
=======================
Files verified: {files_processed}
Files missing in S3: {len(future_to_file)}
Files successfully uploaded: {files_uploaded} ({format_size(bytes_uploaded)})
Files failed: {files_failed}
Status: {status}
        """
        
        logger.info(details)
        print(details)
        
        # Send email notification if enabled
        if self.config.email_enabled:
            self.send_email(
                subject=f"Verification Summary - {status}",
                body=details
            )
    
    def run_backup(self):
        """Run a full backup process and update index database."""
        logger.info("Starting backup process")
        
        # Clean up old logs and reports first
        cleanup_old_logs(self.config)
        cleanup_old_reports(self.config)
        
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
                
                # Don't update the database yet - we'll do it after successful upload
                # This prevents the file from being marked as backed up until it's actually uploaded
            
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
        
        # Generate report and save path for email attachment
        report_file = self.generate_report(success_records, failure_records)
        
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
                body=details,
                report_file=report_file
            )
    
    def send_email(self, subject, body, report_file=None):
        """Send an email notification with optional report attachment."""
        if not self.config.email_enabled:
            return
        
        # Verify email configuration
        if not self.config.email_from or not self.config.email_to:
            logger.warning("Email notification enabled but missing from/to address. Skipping notification.")
            return
            
        try:
            # Create the email message
            msg = EmailMessage()
            # Use subject_prefix only if it's not empty
            prefix = f"{self.config.email_subject_prefix} " if self.config.email_subject_prefix else ""
            msg['Subject'] = f"{prefix}{subject}"
            msg['From'] = self.config.email_from
            msg['To'] = self.config.email_to
            msg.set_content(body)
            
            # Attach report if enabled and file exists
            if self.config.email_attach_report and report_file and os.path.exists(report_file):
                # Check file size
                file_size = os.path.getsize(report_file)
                if file_size <= self.config.email_max_attachment_size:
                    # Get MIME type based on file extension
                    mime_type = 'text/csv' if report_file.endswith('.csv') else 'text/plain'
                    
                    # Read the file and attach it
                    with open(report_file, 'rb') as f:
                        file_data = f.read()
                        msg.add_attachment(file_data, 
                                           maintype='text',
                                           subtype=mime_type.split('/')[1],
                                           filename=os.path.basename(report_file))
                    logger.info(f"Attached report {report_file} to email notification")
                else:
                    logger.warning(f"Report file {report_file} exceeds max attachment size ({format_size(file_size)} > {format_size(self.config.email_max_attachment_size)})")
                    # Add note to email body
                    msg.set_content(body + f"\n\nNote: Backup report was not attached because it exceeds size limit ({format_size(file_size)}).")
            
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
        report_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        report_file = os.path.join(self.config.report_path, f'backup_report_{timestamp}.csv')
        
        # Combine records and add status
        all_records = []
        for record in success_records:
            record['status'] = 'SUCCESS'
            record['error_type'] = ''
            record['error'] = ''
            record['backup_date'] = report_date
            # Convert size to GB
            record['size_gb'] = f"{record['size'] / (1024**3):.3f}"
            # Remove the size in bytes as requested
            if 'size' in record:
                del record['size']
            all_records.append(record)
        
        for record in failure_records:
            record['status'] = 'FAILURE'
            record['error_type'] = 'UPLOAD_ERROR'
            record['backup_date'] = report_date
            # Convert size to GB if size exists
            if 'size' in record and record['size']:
                record['size_gb'] = f"{record['size'] / (1024**3):.3f}"
                del record['size']
            else:
                record['size_gb'] = "0.000"
            all_records.append(record)
            
        # Add scan errors
        for error in self.scan_errors:
            # Create a record format compatible with the other records
            share_name = error['share_config']['local_name']
            error_record = {
                'name': os.path.basename(error['path']),
                'local_path': f"{share_name}:{error['path']}",
                's3_path': '',
                'size_gb': '0.000',
                'status': 'FAILURE',
                'error': error['message'],
                'error_type': 'SCAN_ERROR',
                'backup_date': report_date
            }
            all_records.append(error_record)
        
        # Write to CSV
        try:
            # Define all possible fields
            fieldnames = [
                'backup_date',
                'name',             # Filename
                'local_path',       # Full local path
                's3_path',          # Path in S3
                'size_gb',          # Size in GB
                'status',           # SUCCESS/FAILURE
                'error_type',       # Error category if applicable
                'error'             # Error details if applicable
            ]
            
            # Create report directory if it doesn't exist
            os.makedirs(os.path.dirname(report_file), exist_ok=True)
            
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
            return report_file
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return None


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
    parser.add_argument('--run-now-verify', action='store_true', 
                        help='Run backup with S3 verification (uploads files in index that are missing from S3)')
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
    
    # Set up logging
    logger = setup_logging(config)
    
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
    
    # Run backup with verification if requested
    if args.run_now_verify:
        backup_manager = BackupManager(config)
        try:
            backup_manager.verify_and_upload_missing()
        finally:
            backup_manager.close()
    
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