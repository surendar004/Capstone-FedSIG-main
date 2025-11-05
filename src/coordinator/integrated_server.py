"""
Integrated Server for FedSIG+ ThreatNet
Central coordinator with IOC aggregation and trust management
"""

import sys
import os
from datetime import datetime
from typing import Dict, List
import argparse

from flask import Flask, render_template
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.common.models_enhanced import IOC, ThreatIntel, ClientProfile, DetectionEvent, SystemStats
from src.common.logger import setup_logger
from src.common.config import ServerConfig, ensure_directories
from src.common.constants import CLIENT_STATUS

from src.coordinator.trust_manager import TrustManager
from src.coordinator.intel_aggregator import IntelAggregator
from src.coordinator.api_routes import setup_api_routes


class IntegratedServer:
    """Federated threat intelligence coordination server"""
    
    def __init__(self, config: ServerConfig):
        """Initialize Integrated Server"""
        self.config = config
        self.logger = setup_logger('IntegratedServer', log_file='logs/server.log')
        
        # Ensure directories exist
        ensure_directories()
        
        # Initialize Flask app
        self.app = Flask(__name__,
                        template_folder='../../dashboard/templates',
                        static_folder='../../dashboard/static')
        self.app.config['SECRET_KEY'] = config.secret_key
        CORS(self.app)
        
        # Initialize SocketIO
        self.socketio = SocketIO(self.app, cors_allowed_origins="*", async_mode='eventlet')
        
        # Initialize core components
        self.trust_manager = TrustManager(
            initial_trust=config.initial_trust,
            max_trust=config.max_trust,
            min_trust=config.min_trust,
            decay_rate=config.trust_decay_rate
        )
        
        self.intel_aggregator = IntelAggregator(
            db_path=config.db_path,
            consensus_threshold=config.consensus_threshold,
            consensus_trust_avg=config.consensus_trust_avg
        )
        
        # State
        self.clients: Dict[str, ClientProfile] = {}
        self.detection_feed: List[DetectionEvent] = []
        
        # Setup routes and handlers
        self._setup_routes()
        self._setup_socket_handlers()
        setup_api_routes(self.app, self)
        
        self.logger.info("✅ Integrated Server initialized")
    
    def _setup_routes(self):
        """Setup HTTP routes"""
        
        @self.app.route('/')
        def dashboard():
            """Serve dashboard"""
            return render_template('dashboard.html')
    
    def _setup_socket_handlers(self):
        """Setup Socket.IO event handlers"""
        
        @self.socketio.on('client_register')
        def handle_register(data):
            """Handle client registration"""
            try:
                profile = ClientProfile.from_dict(data)
                client_id = profile.client_id
                
                # Initialize trust score
                self.trust_manager.initialize_client(client_id)
                trust_score = self.trust_manager.get_trust_score(client_id)
                
                # Store client profile
                self.clients[client_id] = profile
                
                self.logger.info(f"✅ Client registered: {client_id[:8]} ({profile.hostname})")
                
                # Send registration confirmation
                emit('registered', {
                    'client_id': client_id,
                    'trust_score': trust_score,
                    'status': 'registered'
                })
                
                # Broadcast to dashboard
                self.socketio.emit('client_update', {
                    'action': 'connected',
                    'client': profile.to_dict()
                }, namespace='/dashboard')
            
            except Exception as e:
                self.logger.error(f"❌ Registration error: {e}")
                emit('error', {'message': str(e)})
        
        @self.socketio.on('client_heartbeat')
        def handle_heartbeat(data):
            """Handle client heartbeat"""
            client_id = data.get('client_id')
            
            if client_id in self.clients:
                self.clients[client_id].last_heartbeat = datetime.now().isoformat()
                self.clients[client_id].status = data.get('status', CLIENT_STATUS['ONLINE'])
                self.clients[client_id].iocs_reported = data.get('iocs_reported', 0)
                self.clients[client_id].detections_local = data.get('detections_local', 0)
        
        @self.socketio.on('ioc_report')
        def handle_ioc_report(data):
            """Handle IOC report from client"""
            try:
                ioc = IOC.from_dict(data)
                client_id = ioc.source_client
                
                if client_id not in self.clients:
                    self.logger.warning(f"⚠️ IOC from unregistered client: {client_id[:8]}")
                    return
                
                # Get client trust score
                trust_score = self.trust_manager.get_trust_score(client_id)
                
                # Process through aggregator
                intel = self.intel_aggregator.report_ioc(ioc, client_id, trust_score)
                
                # Update client stats
                self.clients[client_id].iocs_reported += 1
                
                if intel:
                    # IOC verified - update trust and broadcast
                    self.trust_manager.update_trust(client_id, validated=True)
                    self.clients[client_id].iocs_verified += 1
                    
                    self.broadcast_ioc(intel)
                    
                    self.logger.info(f"✅ IOC verified and broadcast: {ioc.ioc_id[:8]}...")
                    
                    # Notify dashboard
                    self.socketio.emit('ioc_verified', {
                        'ioc': intel.to_dict(),
                        'timestamp': datetime.now().isoformat()
                    }, namespace='/dashboard')
                
                else:
                    self.logger.debug(f"📊 IOC pending: {ioc.ioc_id[:8]}... (needs consensus)")
            
            except Exception as e:
                self.logger.error(f"❌ Error processing IOC report: {e}")
        
        @self.socketio.on('detection_event')
        def handle_detection(data):
            """Handle detection event from client"""
            try:
                detection = DetectionEvent.from_dict(data)
                
                # Add to feed
                self.detection_feed.append(detection)
                if len(self.detection_feed) > 1000:
                    self.detection_feed = self.detection_feed[-1000:]
                
                # Broadcast to dashboard
                self.socketio.emit('new_detection', {
                    'detection': detection.to_dict()
                }, namespace='/dashboard')
                
                if detection.threat_detected:
                    self.logger.info(f"🚨 Detection: {detection.file_path} [{detection.threat_level}]")
            
            except Exception as e:
                self.logger.error(f"❌ Error processing detection: {e}")
        
        @self.socketio.on('sync_request')
        def handle_sync_request(data):
            """Handle intelligence sync request"""
            client_id = data.get('client_id')
            
            if client_id not in self.clients:
                return
            
            # Get all verified IOCs
            verified_iocs = self.intel_aggregator.get_all_iocs(status='verified')
            
            # Send to client
            emit('sync_response', {
                'iocs': [intel.to_dict() for intel in verified_iocs],
                'count': len(verified_iocs),
                'timestamp': datetime.now().isoformat()
            })
            
            self.logger.info(f"🔄 Synced {len(verified_iocs)} IOCs to {client_id[:8]}")
        
        @self.socketio.on('disconnect')
        def handle_disconnect():
            """Handle client disconnection"""
            # Find client by session
            for client_id, profile in self.clients.items():
                # Mark as offline (simple approach)
                profile.status = CLIENT_STATUS['OFFLINE']
                
                self.socketio.emit('client_update', {
                    'action': 'disconnected',
                    'client_id': client_id
                }, namespace='/dashboard')
        
        # Dashboard namespace handlers
        @self.socketio.on('connect', namespace='/dashboard')
        def handle_dashboard_connect():
            """Handle dashboard connection"""
            self.logger.info("📊 Dashboard connected")
            
            # Send initial state
            emit('initial_state', {
                'clients': [c.to_dict() for c in self.clients.values()],
                'iocs': [i.to_dict() for i in self.intel_aggregator.get_all_iocs(status='verified')[-50:]],
                'detections': [d.to_dict() for d in self.detection_feed[-50:]],
                'stats': self.get_system_stats().to_dict()
            }, namespace='/dashboard')
    
    def broadcast_ioc(self, intel: ThreatIntel):
        """Broadcast verified IOC to all clients"""
        self.socketio.emit('ioc_broadcast', intel.to_dict())
        self.logger.info(f"📡 Broadcast IOC to all clients: {intel.ioc.ioc_id[:8]}...")
    
    def get_system_stats(self) -> SystemStats:
        """Generate system statistics"""
        online_clients = sum(1 for c in self.clients.values() 
                           if c.status == CLIENT_STATUS['ONLINE'])
        
        intel_stats = self.intel_aggregator.get_statistics()
        trust_scores = self.trust_manager.get_all_trust_scores()
        
        avg_trust = sum(s.trust_score for s in trust_scores) / len(trust_scores) if trust_scores else 0.5
        high_trust = sum(1 for s in trust_scores if s.trust_score >= 0.7)
        low_trust = sum(1 for s in trust_scores if s.trust_score < 0.4)
        
        # Count detections today
        today = datetime.now().date()
        detections_today = sum(1 for d in self.detection_feed 
                              if datetime.fromisoformat(d.timestamp).date() == today)
        
        return SystemStats(
            total_clients=len(self.clients),
            online_clients=online_clients,
            offline_clients=len(self.clients) - online_clients,
            total_iocs=intel_stats['total_iocs'],
            verified_iocs=intel_stats['verified_iocs'],
            pending_iocs=intel_stats['pending_iocs'],
            critical_iocs=intel_stats['threat_distribution'].get('critical', 0),
            total_detections=len(self.detection_feed),
            detections_today=detections_today,
            average_trust=avg_trust,
            high_trust_clients=high_trust,
            low_trust_clients=low_trust
        )
    
    def run(self, host: str = None, port: int = None, debug: bool = None):
        """Run the server"""
        host = host or self.config.host
        port = port or self.config.port
        debug = debug if debug is not None else self.config.debug
        
        self.logger.info(f"🚀 Starting FedSIG+ ThreatNet Server")
        self.logger.info(f"   Host: {host}:{port}")
        self.logger.info(f"   Dashboard: http://{host}:{port}")
        
        self.socketio.run(self.app, host=host, port=port, debug=debug)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description='FedSIG+ ThreatNet Server')
    parser.add_argument('--config', default='configs/server_config.yaml',
                       help='Path to configuration file')
    parser.add_argument('--host', help='Host address (overrides config)')
    parser.add_argument('--port', type=int, help='Port number (overrides config)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    # Load configuration
    config = ServerConfig.from_yaml(args.config)
    
    # Initialize server
    server = IntegratedServer(config)
    
    # Run server
    server.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()