"""
Configuration Management for FedSIG+ ThreatNet
"""

import os
import yaml
from dataclasses import dataclass, field, asdict
from typing import List, Dict


@dataclass
class ServerConfig:
    """Server configuration"""
    host: str = '0.0.0.0'
    port: int = 5000
    debug: bool = False
    secret_key: str = 'change-this-in-production'
    
    # Database
    db_path: str = 'data/intel/global_iocs.db'
    
    # Trust parameters
    initial_trust: float = 0.5
    max_trust: float = 1.0
    min_trust: float = 0.1
    trust_decay_rate: float = 0.95
    
    # Consensus parameters
    consensus_threshold: int = 2
    consensus_trust_avg: float = 0.6
    
    # Timeouts
    client_timeout: int = 30
    sync_interval: int = 300
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_yaml(cls, yaml_path: str) -> 'ServerConfig':
        """Load configuration from YAML file"""
        if not os.path.exists(yaml_path):
            return cls()
        
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        
        return cls(**data.get('server', {}))


@dataclass
class ClientConfig:
    """Client configuration"""
    client_id: str = ''
    server_url: str = 'http://localhost:5000'
    
    # Monitoring
    watch_directories: List[str] = field(default_factory=list)
    scan_extensions: List[str] = field(default_factory=lambda: [
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.sh'
    ])
    max_file_size_mb: int = 100
    recursive_scan: bool = True
    
    # Database
    local_db_path: str = 'data/client/local_iocs.db'
    
    # YARA
    yara_rules_paths: List[str] = field(default_factory=lambda: ['rules/yara_rules.yar'])
    enable_yara: bool = True
    
    # Sync
    sync_interval: int = 300
    heartbeat_interval: int = 5
    auto_sync: bool = True
    
    def to_dict(self) -> Dict:
        return asdict(self)
    
    @classmethod
    def from_yaml(cls, yaml_path: str) -> 'ClientConfig':
        """Load configuration from YAML file"""
        if not os.path.exists(yaml_path):
            return cls()
        
        with open(yaml_path, 'r') as f:
            data = yaml.safe_load(f)
        
        return cls(**data.get('client', {}))


@dataclass
class DashboardConfig:
    """Dashboard configuration"""
    refresh_interval: int = 5
    max_detections_display: int = 50
    max_clients_display: int = 100
    
    # Chart settings
    timeline_minutes: int = 10
    enable_realtime_charts: bool = True
    
    def to_dict(self) -> Dict:
        return asdict(self)


def ensure_directories():
    """Ensure all required directories exist"""
    directories = [
        'data/intel',
        'data/client',
        'logs',
        'rules',
        'configs',
        'dashboard/templates',
        'dashboard/static/css',
        'dashboard/static/js'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)


def generate_default_configs():
    """Generate default configuration files"""
    ensure_directories()
    
    # Server config
    server_config = {
        'server': ServerConfig().to_dict()
    }
    
    with open('configs/server_config.yaml', 'w') as f:
        yaml.dump(server_config, f, default_flow_style=False)
    
    # Client config
    client_config = {
        'client': ClientConfig().to_dict()
    }
    
    with open('configs/client_config.yaml', 'w') as f:
        yaml.dump(client_config, f, default_flow_style=False)
    
    # Dashboard config
    dashboard_config = {
        'dashboard': DashboardConfig().to_dict()
    }
    
    with open('configs/dashboard_config.yaml', 'w') as f:
        yaml.dump(dashboard_config, f, default_flow_style=False)
    
    print("✅ Generated default configuration files in configs/")