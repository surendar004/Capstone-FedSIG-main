"""
File Monitor for FedSIG+ ThreatNet Client
Real-time file system monitoring using Watchdog
"""

import os
import hashlib
from typing import List, Callable, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from src.common.logger import setup_logger


class FileMonitorHandler(FileSystemEventHandler):
    """Handles file system events"""
    
    def __init__(self, callback: Callable, extensions: List[str], max_size_mb: int):
        """
        Initialize handler
        
        Args:
            callback: Function to call on file detection
            extensions: List of file extensions to monitor
            max_size_mb: Maximum file size in MB
        """
        super().__init__()
        self.callback = callback
        self.extensions = [ext.lower() for ext in extensions]
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.logger = setup_logger('FileMonitorHandler')
    
    def _should_scan(self, file_path: str) -> bool:
        """Check if file should be scanned"""
        try:
            # Check if file exists
            if not os.path.exists(file_path) or not os.path.isfile(file_path):
                return False
            
            # Check extension
            _, ext = os.path.splitext(file_path)
            if self.extensions and ext.lower() not in self.extensions:
                return False
            
            # Check size
            size = os.path.getsize(file_path)
            if size > self.max_size_bytes:
                self.logger.debug(f"⏭️ Skipping large file: {file_path} ({size} bytes)")
                return False
            
            return True
        
        except Exception as e:
            self.logger.error(f"❌ Error checking file {file_path}: {e}")
            return False
    
    def on_created(self, event: FileSystemEvent):
        """Handle file creation"""
        if not event.is_directory and self._should_scan(event.src_path):
            self.logger.debug(f"📁 New file detected: {event.src_path}")
            self.callback(event.src_path, 'created')
    
    def on_modified(self, event: FileSystemEvent):
        """Handle file modification"""
        if not event.is_directory and self._should_scan(event.src_path):
            self.logger.debug(f"📝 File modified: {event.src_path}")
            self.callback(event.src_path, 'modified')
    
    def on_moved(self, event: FileSystemEvent):
        """Handle file move/rename"""
        if not event.is_directory and self._should_scan(event.dest_path):
            self.logger.debug(f"📦 File moved: {event.dest_path}")
            self.callback(event.dest_path, 'moved')


class FileMonitor:
    """File system monitor for threat detection"""
    
    def __init__(self, directories: List[str], callback: Callable,
                 extensions: Optional[List[str]] = None,
                 max_size_mb: int = 100,
                 recursive: bool = True):
        """
        Initialize File Monitor
        
        Args:
            directories: List of directories to monitor
            callback: Function to call when file is detected
            extensions: List of file extensions to monitor (None = all)
            max_size_mb: Maximum file size in MB
            recursive: Monitor subdirectories
        """
        self.directories = directories
        self.callback = callback
        self.extensions = extensions or []
        self.max_size_mb = max_size_mb
        self.recursive = recursive
        
        self.logger = setup_logger('FileMonitor')
        self.observer = Observer()
        self.handler = FileMonitorHandler(self._on_file_event, self.extensions, max_size_mb)
        
        self._setup_monitors()
    
    def _setup_monitors(self):
        """Setup directory monitors"""
        for directory in self.directories:
            # Create directory if it doesn't exist
            os.makedirs(directory, exist_ok=True)
            
            # Schedule monitoring
            self.observer.schedule(self.handler, directory, recursive=self.recursive)
            self.logger.info(f"👁️ Monitoring: {directory} (recursive={self.recursive})")
    
    def _on_file_event(self, file_path: str, event_type: str):
        """Handle file event"""
        try:
            # Calculate file hash
            file_hash = self.calculate_hash(file_path)
            file_size = os.path.getsize(file_path)
            
            # Call user callback
            self.callback(file_path, file_hash, file_size, event_type)
        
        except Exception as e:
            self.logger.error(f"❌ Error processing file {file_path}: {e}")
    
    @staticmethod
    def calculate_hash(file_path: str, algorithm: str = 'sha256') -> str:
        """
        Calculate file hash
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (sha256, md5, sha1)
        
        Returns:
            Hex digest of file hash
        """
        hash_func = getattr(hashlib, algorithm)()
        
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            raise Exception(f"Failed to hash file: {e}")
    
    def start(self):
        """Start monitoring"""
        self.observer.start()
        self.logger.info("✅ File monitoring started")
    
    def stop(self):
        """Stop monitoring"""
        self.observer.stop()
        self.observer.join()
        self.logger.info("🛑 File monitoring stopped")
    
    def is_running(self) -> bool:
        """Check if monitor is running"""
        return self.observer.is_alive()