"""
System Constants for FedSIG+ ThreatNet
"""

# IOC Types
IOC_TYPES = {
    'FILE_HASH': 'file_hash',
    'IP_ADDRESS': 'ip_address',
    'DOMAIN': 'domain',
    'URL': 'url',
    'FILE_SIGNATURE': 'file_signature',
    'BEHAVIOR': 'behavior_pattern',
    'REGISTRY_KEY': 'registry_key',
    'PROCESS_NAME': 'process_name'
}

# Threat Levels
THREAT_LEVELS = {
    'CRITICAL': 'critical',
    'HIGH': 'high',
    'MEDIUM': 'medium',
    'LOW': 'low',
    'INFO': 'info'
}

# Client Status
CLIENT_STATUS = {
    'ONLINE': 'online',
    'OFFLINE': 'offline',
    'SCANNING': 'scanning',
    'SYNCING': 'syncing',
    'IDLE': 'idle',
    'ERROR': 'error'
}

# Intelligence Status
INTEL_STATUS = {
    'PENDING': 'pending',
    'VERIFIED': 'verified',
    'REJECTED': 'rejected',
    'EXPIRED': 'expired'
}

# Trust Score Weights (Formula: 0.4×accuracy + 0.3×contribution + 0.2×responsiveness + 0.1×decay)
DEFAULT_TRUST_WEIGHTS = {
    'accuracy': 0.4,
    'contribution': 0.3,
    'responsiveness': 0.2,
    'decay': 0.1
}

# System Limits
MAX_CLIENTS = 100
MAX_IOCS_PER_CLIENT = 10000
MAX_FILE_SIZE_MB = 100
MAX_SCAN_DEPTH = 5

# Timeouts (seconds)
CLIENT_TIMEOUT = 30
SCAN_TIMEOUT = 30
SYNC_INTERVAL = 300
HEARTBEAT_INTERVAL = 5

# Consensus Parameters
MIN_CONSENSUS_CLIENTS = 2
MIN_CONSENSUS_TRUST = 0.6
IOC_EXPIRY_DAYS = 30

# WebSocket Events
WEBSOCKET_EVENTS = {
    'CLIENT_REGISTER': 'client_register',
    'CLIENT_HEARTBEAT': 'client_heartbeat',
    'IOC_REPORT': 'ioc_report',
    'IOC_BROADCAST': 'ioc_broadcast',
    'DETECTION_EVENT': 'detection_event',
    'TRUST_UPDATE': 'trust_update',
    'SYSTEM_UPDATE': 'system_update',
    'INTEL_UPDATE': 'intel_update',
    'SYNC_REQUEST': 'sync_request',
    'SYNC_RESPONSE': 'sync_response'
}

# API Endpoints
API_ENDPOINTS = {
    'STATUS': '/api/status',
    'CLIENTS': '/api/clients',
    'IOCS': '/api/iocs',
    'TRUST': '/api/trust_scores',
    'DETECTIONS': '/api/detections',
    'INTEL': '/api/intel',
    'REPORT_THREAT': '/api/report_threat',
    'SYNC_INTEL': '/api/sync_intel'
}

# File Extensions to Monitor
MONITORED_EXTENSIONS = [
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.sh', 
    '.py', '.jar', '.js', '.vbs', '.scr', '.com',
    '.msi', '.app', '.dmg', '.pkg', '.deb', '.rpm'
]

# Dashboard Colors
DASHBOARD_COLORS = {
    'critical': '#ff4757',
    'high': '#ff6348',
    'medium': '#ffa502',
    'low': '#26de81',
    'info': '#5352ed',
    'online': '#26de81',
    'offline': '#ff4757',
    'pending': '#ffa502',
    'verified': '#26de81'
}

# Log Formats
LOG_FORMAT = '%(asctime)s | %(name)s | %(levelname)s | %(message)s'
LOG_DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# Database Tables
DB_TABLES = {
    'IOCS': 'iocs',
    'DETECTIONS': 'detections',
    'TRUST_HISTORY': 'trust_history',
    'INTEL_LOG': 'intel_log'
}

# Version Info
VERSION = "2.0.0"
BUILD_DATE = "2024-01-01"
PROJECT_NAME = "FedSIG+ ThreatNet"
PROJECT_DESC = "Federated Threat Intelligence Learning & Sharing System"