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
                    
                    # If file exists in DB and hasn't changed, skip checksum calculation
                    if existing_file and int(existing_file[3]) == file_info.file_size and \
                       existing_file[4] == last_modified.isoformat():
                        continue
                    
                    # For changed or new files, calculate checksum
                    try:
                        # Calculate checksum by streaming the file (no temp file needed)
                        checksum = self.calculate_streaming_checksum(full_path)
                        
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
