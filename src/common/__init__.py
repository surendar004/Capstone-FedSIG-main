"""
FedSIG+ ThreatNet Common Module
Shared utilities and models
"""

from .models_enhanced import (
    IOC,
    ThreatIntel,
    TrustScore,
    ClientProfile,
    DetectionEvent,
    SystemStats,
    IntelUpdate,
    WebSocketMessage
)

from .config import (
    ServerConfig,
    ClientConfig,
    DashboardConfig,
    ensure_directories,
    generate_default_configs
)

from .logger import setup_logger, get_log_file_path

from .constants import (
    IOC_TYPES,
    THREAT_LEVELS,
    CLIENT_STATUS,
    INTEL_STATUS,
    DEFAULT_TRUST_WEIGHTS
)

__version__ = "2.0.0"
__author__ = "FedSIG+ ThreatNet Team"

__all__ = [
    # Models
    'IOC',
    'ThreatIntel',
    'TrustScore',
    'ClientProfile',
    'DetectionEvent',
    'SystemStats',
    'IntelUpdate',
    'WebSocketMessage',
    
    # Config
    'ServerConfig',
    'ClientConfig',
    'DashboardConfig',
    'ensure_directories',
    'generate_default_configs',
    
    # Logger
    'setup_logger',
    'get_log_file_path',
    
    # Constants
    'IOC_TYPES',
    'THREAT_LEVELS',
    'CLIENT_STATUS',
    'INTEL_STATUS',
    'DEFAULT_TRUST_WEIGHTS',
]