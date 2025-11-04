"""
Enhanced Client for FedSIG+ ThreatNet
Complete threat detection with IOC database, YARA scanning, and real-time sync
"""

import sys
import os
import time
import socket
import platform
import uuid
import argparse
from typing import Optional, Dict, List
from datetime import datetime

import socketio

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.common.models_enhanced import IOC, ClientProfile, DetectionEvent, ThreatIntel
from src.common.logger import setup_logger
from src.common.config import ClientConfig
from src.common.constants import IOC_TYPES, THREAT_LEVELS

from src.client.file_monitor import FileMonitor
from src.client.yara_scanner import YARAScanner
from src.client.ioc_database import IOCDatabase


class EnhancedClient:
    """Enhanced federated threat detection client with IOC management"""
    
    def __init__(self, config: ClientConfig):
        """Initialize Enhanced Client"""
        self.config = config
        self.client_id = config.client_id or str(uuid.uuid4())
        
        # Setup logger
        self.logger = setup_logger(
            f'Client-{self.client_id[:8]}',
            log_file=f'logs/client_{self.client_id[:8]}.log'
        )
        
        # Client profile
        self.profile = ClientProfile(
            client_id=self.client_id,
            hostname=socket.gethostname(),
            ip_address=self._get_ip_address(),
            platform=platform.system(),
            has_yara=config.enable_yara,
            watch_directories=config.watch_directories
        )
        
        # Initialize components
        self.ioc_db = IOCDatabase(config.local_db_path)
        self.yara_scanner = None
        if config.enable_yara:
            self.yara_scanner = YARAScanner(config.yara_rules_paths)
        
        self.file_monitor = None
        
        # Socket.IO client
        self.sio = socketio.Client(reconnection=True, reconnection_attempts=0)
        self._setup_socket_handlers()
        
        # State
        self.connected = False
        self.running = False
        
        self.logger.info(f"✅ Enhanced Client initialized: {self.client_id[:8]}")
    
    def _get_ip_address(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def _setup_socket_handlers(self):
        """Setup Socket.IO event handlers"""
        
        @self.sio.on('connect')
        def on_connect():
            self.logger.info(f"🔌 Connected to server: {self.config.server_url}")
            self.connected = True
            self._register()
        
        @self.sio.on('disconnect')
        def on_disconnect():
            self.logger.warning("⚠️ Disconnected from server")
            self.connected = False
        
        @self.sio.on('registered')
        def on_registered(data):
            self.logger.info(f"✅ Registered with coordinator")
            self.logger.info(f"   Trust Score: {data.get('trust_score', 0.5):.2f}")
            
            # Initial sync
            if self.config.auto_sync:
                self._sync_intelligence()
        
        @self.sio.on('ioc_broadcast')
        def on_ioc_broadcast(data):
            """Receive new verified IOC from coordinator"""
            try:
                intel = ThreatIntel.from_dict(data)
                self.logger.info(f"📥 Received verified IOC: {intel.ioc.ioc_id[:8]}... "
                               f"[{intel.ioc.threat_level}]")
                
                # Add to local database
                self.ioc_db.add_threat_intel(intel)
            
            except Exception as e:
                self.logger.error(f"❌ Error processing IOC broadcast: {e}")
        
        @self.sio.on('trust_update')
        def on_trust_update(data):
            """Receive trust score update"""
            new_score = data.get('trust_score', 0.5)
            self.logger.info(f"📊 Trust score updated: {new_score:.2f}")
        
        @self.sio.on('intel_update')
        def on_intel_update(data):
            """Receive intelligence update"""
            self.logger.debug(f"📬 Intelligence update received")
        
        @self.sio.on('error')
        def on_error(data):
            self.logger.error(f"❌ Server error: {data.get('message')}")
    
    def _register(self):
        """Register client with coordinator"""
        self.sio.emit('client_register', self.profile.to_dict())
    
    def connect(self) -> bool:
        """Connect to coordinator server"""
        try:
            self.logger.info(f"🔌 Connecting to {self.config.server_url}...")
            self.sio.connect(self.config.server_url)
            time.sleep(1)  # Wait for registration
            return True
        except Exception as e:
            self.logger.error(f"❌ Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from server"""
        if self.connected:
            self.sio.disconnect()
            self.logger.info("👋 Disconnected from server")
    
    def _sync_intelligence(self):
        """Sync intelligence from coordinator"""
        try:
            self.logger.info("🔄 Syncing intelligence...")
            self.sio.emit('sync_request', {'client_id': self.client_id})
        except Exception as e:
            self.logger.error(f"❌ Sync failed: {e}")
    
    def start_monitoring(self):
        """Start file system monitoring"""
        if not self.config.watch_directories:
            self.logger.warning("⚠️ No watch directories configured")
            return
        
        self.file_monitor = FileMonitor(
            directories=self.config.watch_directories,
            callback=self._on_file_detected,
            extensions=self.config.scan_extensions,
            max_size_mb=self.config.max_file_size_mb,
            recursive=self.config.recursive_scan
        )
        
        self.file_monitor.start()
        self.logger.info("👁️ File monitoring started")
    
    def stop_monitoring(self):
        """Stop file system monitoring"""
        if self.file_monitor:
            self.file_monitor.stop()
            self.logger.info("🛑 File monitoring stopped")
    
    def _on_file_detected(self, file_path: str, file_hash: str, file_size: int, event_type: str):
        """Handle detected file"""
        self.logger.info(f"🔍 Scanning file: {file_path} ({event_type})")
        
        # Create detection event
        detection = DetectionEvent(
            client_id=self.client_id,
            file_path=file_path,
            file_hash=file_hash,
            file_size=file_size
        )
        
        # Check against local IOC database first
        matched_ioc = self.ioc_db.check_file_hash(file_hash)
        if matched_ioc:
            detection.threat_detected = True
            detection.threat_level = matched_ioc.threat_level
            detection.detection_type = 'ioc_match'
            detection.matched_iocs.append(matched_ioc.ioc_id)
            detection.action = 'blocked'
            
            self.logger.warning(f"🚨 IOC MATCH: {file_path}")
            self.logger.warning(f"   Hash: {file_hash}")
            self.logger.warning(f"   Threat Level: {matched_ioc.threat_level}")
            
            # Record match
            self.ioc_db.record_match(matched_ioc.ioc_id, file_path, file_hash, 'blocked')
            
            # Report detection
            self._report_detection(detection)
            return
        
        # YARA scan if enabled
        if self.yara_scanner:
            is_threat, matched_rules, threat_level = self.yara_scanner.scan_file(file_path)
            
            if is_threat:
                detection.threat_detected = True
                detection.threat_level = threat_level
                detection.detection_type = 'yara'
                detection.matched_rules = matched_rules
                detection.action = 'quarantined'
                
                self.logger.warning(f"🚨 YARA DETECTION: {file_path}")
                self.logger.warning(f"   Rules: {', '.join(matched_rules)}")
                self.logger.warning(f"   Threat Level: {threat_level}")
                
                # Create and report IOC
                ioc = self._create_ioc_from_detection(detection)
                self._report_ioc(ioc)
                
                # Add to local database
                self.ioc_db.add_ioc(ioc)
                
                return
        
        # No threat detected
        self.logger.debug(f"✅ Clean: {file_path}")
    
    def _create_ioc_from_detection(self, detection: DetectionEvent) -> IOC:
        """Create IOC from detection event"""
        ioc = IOC(
            ioc_id=IOC.generate_ioc_id(IOC_TYPES['FILE_HASH'], detection.file_hash),
            ioc_type=IOC_TYPES['FILE_HASH'],
            value=detection.file_hash,
            threat_level=detection.threat_level,
            source_client=self.client_id,
            metadata={
                'file_path': os.path.basename(detection.file_path),
                'file_size': detection.file_size,
                'matched_rules': detection.matched_rules,
                'detection_type': detection.detection_type,
                'platform': self.profile.platform
            }
        )
        return ioc
    
    def _report_ioc(self, ioc: IOC):
        """Report IOC to coordinator"""
        if not self.connected:
            self.logger.warning("⚠️ Not connected - IOC not reported")
            return
        
        try:
            self.sio.emit('ioc_report', ioc.to_dict())
            self.logger.info(f"📤 Reported IOC: {ioc.ioc_id[:8]}... [{ioc.threat_level}]")
            self.profile.iocs_reported += 1
        except Exception as e:
            self.logger.error(f"❌ Failed to report IOC: {e}")
    
    def _report_detection(self, detection: DetectionEvent):
        """Report detection event to coordinator"""
        if not self.connected:
            return
        
        try:
            self.sio.emit('detection_event', detection.to_dict())
            self.profile.detections_local += 1
        except Exception as e:
            self.logger.error(f"❌ Failed to report detection: {e}")
    
    def send_heartbeat(self):
        """Send heartbeat to server"""
        if self.connected:
            try:
                self.sio.emit('client_heartbeat', {
                    'client_id': self.client_id,
                    'timestamp': datetime.now().isoformat(),
                    'status': self.profile.status,
                    'iocs_reported': self.profile.iocs_reported,
                    'detections_local': self.profile.detections_local
                })
            except Exception as e:
                self.logger.error(f"❌ Heartbeat failed: {e}")
    
    def run(self):
        """Main run loop"""
        self.running = True
        
        try:
            # Start monitoring if configured
            if self.config.watch_directories:
                self.start_monitoring()
            
            self.logger.info("🏃 Client running... (Press Ctrl+C to stop)")
            
            # Main loop
            heartbeat_counter = 0
            sync_counter = 0
            
            while self.running:
                time.sleep(1)
                
                # Heartbeat
                heartbeat_counter += 1
                if heartbeat_counter >= self.config.heartbeat_interval:
                    self.send_heartbeat()
                    heartbeat_counter = 0
                
                # Periodic sync
                if self.config.auto_sync:
                    sync_counter += 1
                    if sync_counter >= self.config.sync_interval:
                        self._sync_intelligence()
                        sync_counter = 0
        
        except KeyboardInterrupt:
            self.logger.info("\n⚠️ Received shutdown signal")
        
        finally:
            self.shutdown()
    
    def shutdown(self):
        """Cleanup and shutdown"""
        self.logger.info("🛑 Shutting down client...")
        self.running = False
        self.stop_monitoring()
        self.disconnect()
        self.logger.info("👋 Client shutdown complete")
    
    def print_statistics(self):
        """Print client statistics"""
        stats = self.ioc_db.get_statistics()
        
        print("\n" + "="*60)
        print("CLIENT STATISTICS")
        print("="*60)
        print(f"Client ID:        {self.client_id[:16]}...")
        print(f"Hostname:         {self.profile.hostname}")
        print(f"Connected:        {'Yes' if self.connected else 'No'}")
        print(f"\nLocal IOC Database:")
        print(f"  Total IOCs:     {stats['total_iocs']}")
        print(f"  Verified:       {stats['verified_iocs']}")
        print(f"  Local:          {stats['local_iocs']}")
        print(f"  Matches:        {stats['total_matches']}")
        print(f"\nActivity:")
        print(f"  IOCs Reported:  {self.profile.iocs_reported}")
        print(f"  Detections:     {self.profile.detections_local}")
        print("="*60 + "\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='FedSIG+ ThreatNet Enhanced Client')
    parser.add_argument('--config', default='configs/client_config.yaml',
                       help='Path to configuration file')
    parser.add_argument('--server', help='Server URL (overrides config)')
    parser.add_argument('--watch-dir', action='append', dest='watch_dirs',
                       help='Directory to monitor (can be specified multiple times)')
    parser.add_argument('--stats', action='store_true',
                       help='Print statistics and exit')
    
    args = parser.parse_args()
    
    # Load configuration
    config = ClientConfig.from_yaml(args.config)
    
    # Override with command line arguments
    if args.server:
        config.server_url = args.server
    if args.watch_dirs:
        config.watch_directories = args.watch_dirs
    
    # Initialize client
    client = EnhancedClient(config)
    
    # Print statistics mode
    if args.stats:
        client.print_statistics()
        return 0
    
    # Connect to server
    if not client.connect():
        print("❌ Failed to connect to server")
        return 1
    
    # Run client
    try:
        client.run()
    except Exception as e:
        client.logger.error(f"❌ Fatal error: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())