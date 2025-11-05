#!/usr/bin/env python3
"""
FedSIG+ ThreatNet - Enhanced Setup Script
Complete environment preparation and validation
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'


class FedSIGSetup:
    """Complete setup and environment preparation"""
    
    def __init__(self):
        self.project_root = Path.cwd()
        self.errors = []
        self.warnings = []
    
    def print_banner(self):
        """Print setup banner"""
        banner = f"""{Colors.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║       {Colors.BOLD}FedSIG+ ThreatNet - Enhanced Setup{Colors.END}{Colors.CYAN}                    ║
║                                                              ║
║       Complete Environment Preparation & Validation          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}
        """
        print(banner)
    
    def create_directory_structure(self):
        """Create complete directory structure"""
        print(f"\n{Colors.BLUE}[1/10] Creating directory structure...{Colors.END}")
        
        directories = [
            # Source directories
            'src/common',
            'src/coordinator',
            'src/client',
            
            # Dashboard directories
            'dashboard/templates',
            'dashboard/components',
            'dashboard/static/css',
            'dashboard/static/js',
            
            # Configuration
            'config',
            
            # Rules
            'rules',
            
            # Examples
            'examples',
            
            # Tests
            'tests',
            
            # Data (runtime)
            'data/intel',
            'data/client',
            
            # Logs (runtime)
            'logs'
        ]
        
        for directory in directories:
            path = self.project_root / directory
            path.mkdir(parents=True, exist_ok=True)
            print(f"{Colors.GREEN}  ✓ {directory}{Colors.END}")
        
        print(f"{Colors.GREEN}✓ Directory structure created{Colors.END}")
    
    def create_init_files(self):
        """Create Python package __init__.py files"""
        print(f"\n{Colors.BLUE}[2/10] Creating package files...{Colors.END}")
        
        init_files = {
            'src/__init__.py': '"""FedSIG+ ThreatNet Core Package"""',
            'src/common/__init__.py': '''"""Common utilities and models"""
from .models_enhanced import IOC, ThreatIntel, TrustScore, ClientProfile
from .config import ServerConfig, ClientConfig
from .logger import setup_logger

__all__ = ['IOC', 'ThreatIntel', 'TrustScore', 'ClientProfile', 
           'ServerConfig', 'ClientConfig', 'setup_logger']
''',
            'src/coordinator/__init__.py': '''"""Coordinator server components"""
from .trust_manager import TrustManager
from .intel_aggregator import IntelAggregator
from .integrated_server import IntegratedServer

__all__ = ['TrustManager', 'IntelAggregator', 'IntegratedServer']
''',
            'src/client/__init__.py': '''"""Client components"""
from .enhanced_client import EnhancedClient
from .file_monitor import FileMonitor
from .yara_scanner import YARAScanner
from .ioc_database import IOCDatabase

__all__ = ['EnhancedClient', 'FileMonitor', 'YARAScanner', 'IOCDatabase']
'''
        }
        
        for file_path, content in init_files.items():
            full_path = self.project_root / file_path
            with open(full_path, 'w') as f:
                f.write(content)
            print(f"{Colors.GREEN}  ✓ {file_path}{Colors.END}")
        
        print(f"{Colors.GREEN}✓ Package files created{Colors.END}")
    
    def create_gitignore(self):
        """Create .gitignore file"""
        print(f"\n{Colors.BLUE}[3/10] Creating .gitignore...{Colors.END}")
        
        gitignore_content = '''# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
*.egg-info/
dist/
build/
*.egg

# Virtual Environment
venv/
env/
ENV/
.venv

# IDEs
.vscode/
.idea/
*.swp
*.swo
*~

# OS
.DS_Store
Thumbs.db
.directory

# Application Data
data/
logs/
*.db
*.log

# Configuration (keep examples)
config/*_config.yaml
!config/*_config.yaml.example

# Testing
.pytest_cache/
.coverage
htmlcov/
.tox/

# Documentation builds
docs/_build/

# Temporary files
*.tmp
*.bak
.~lock.*
'''
        
        with open(self.project_root / '.gitignore', 'w') as f:
            f.write(gitignore_content)
        
        print(f"{Colors.GREEN}✓ .gitignore created{Colors.END}")
    
    def check_python_version(self):
        """Verify Python version"""
        print(f"\n{Colors.BLUE}[4/10] Checking Python version...{Colors.END}")
        
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            self.errors.append(f"Python 3.8+ required (found {version.major}.{version.minor})")
            print(f"{Colors.RED}  ✗ Python 3.8+ required{Colors.END}")
            return False
        
        print(f"{Colors.GREEN}  ✓ Python {version.major}.{version.minor}.{version.micro}{Colors.END}")
        return True
    
    def check_dependencies(self):
        """Check required packages"""
        print(f"\n{Colors.BLUE}[5/10] Checking dependencies...{Colors.END}")
        
        required = [
            'flask',
            'flask_socketio',
            'flask_cors',
            'socketio',
            'eventlet',
            'numpy',
            'yaml',
            'watchdog'
        ]
        
        missing = []
        for package in required:
            try:
                __import__(package)
                print(f"{Colors.GREEN}  ✓ {package}{Colors.END}")
            except ImportError:
                print(f"{Colors.YELLOW}  ⚠ {package} (missing){Colors.END}")
                missing.append(package)
        
        if missing:
            self.warnings.append(f"Missing packages: {', '.join(missing)}")
            print(f"\n{Colors.YELLOW}Install with: pip install -r requirements.txt{Colors.END}")
        else:
            print(f"{Colors.GREEN}✓ All dependencies satisfied{Colors.END}")
        
        return len(missing) == 0
    
    def generate_sample_configs(self):
        """Generate sample configuration files"""
        print(f"\n{Colors.BLUE}[6/10] Generating sample configurations...{Colors.END}")
        
        # Server config
        server_config = '''# FedSIG+ ThreatNet - Server Configuration

server:
  host: '0.0.0.0'
  port: 5000
  debug: false
  secret_key: 'CHANGE_THIS_IN_PRODUCTION'
  
  # Database
  db_path: 'data/intel/global_iocs.db'
  
  # Trust Management
  initial_trust: 0.5
  max_trust: 1.0
  min_trust: 0.1
  trust_decay_rate: 0.95
  decay_interval_hours: 24
  
  # Consensus
  consensus_threshold: 2
  consensus_trust_avg: 0.6
  
  # Performance
  max_clients: 100
  client_timeout: 30
  sync_interval: 300
'''
        
        # Client config
        client_config = '''# FedSIG+ ThreatNet - Client Configuration

client:
  server_url: 'http://localhost:5000'
  client_id: ''  # Auto-generated if empty
  
  # Monitoring
  watch_directories:
    - '/tmp/watch1'
  
  scan_extensions:
    - '.exe'
    - '.dll'
    - '.bat'
    - '.cmd'
    - '.ps1'
    - '.sh'
  
  max_file_size_mb: 100
  recursive_scan: true
  
  # Database
  local_db_path: 'data/client/local_iocs.db'
  
  # YARA
  yara_rules_paths:
    - 'rules/yara_rules.yar'
    - 'rules/custom_rules.yar'
  enable_yara: true
  
  # Synchronization
  sync_interval: 300
  heartbeat_interval: 5
  auto_sync: true
'''
        
        # Dashboard config
        dashboard_config = '''# FedSIG+ ThreatNet - Dashboard Configuration

dashboard:
  refresh_interval: 5
  max_detections_display: 50
  max_clients_display: 100
  
  # Charts
  timeline_minutes: 10
  enable_realtime_charts: true
  
  # Filters
  default_ioc_filter: 'all'  # all, verified, pending
  default_threat_level: 'all'  # all, critical, high, medium, low
'''
        
        configs = {
            'config/server_config.yaml': server_config,
            'config/client_config.yaml': client_config,
            'config/dashboard_config.yaml': dashboard_config
        }
        
        for file_path, content in configs.items():
            full_path = self.project_root / file_path
            if not full_path.exists():
                with open(full_path, 'w') as f:
                    f.write(content)
                print(f"{Colors.GREEN}  ✓ {file_path}{Colors.END}")
            else:
                print(f"{Colors.YELLOW}  ⚠ {file_path} (exists, skipped){Colors.END}")
        
        print(f"{Colors.GREEN}✓ Sample configurations generated{Colors.END}")
    
    def create_sample_yara_rules(self):
        """Create sample YARA rules"""
        print(f"\n{Colors.BLUE}[7/10] Creating sample YARA rules...{Colors.END}")
        
        yara_rules = '''/*
    FedSIG+ ThreatNet - Default YARA Rules
*/

rule Test_EICAR {
    meta:
        description = "EICAR test file"
        threat_level = "low"
        author = "FedSIG+ ThreatNet"
    
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    
    condition:
        $eicar
}

rule Suspicious_Executable {
    meta:
        description = "Suspicious executable patterns"
        threat_level = "medium"
        author = "FedSIG+ ThreatNet"
    
    strings:
        $mz = "MZ"
        $malware1 = "malware" nocase
        $malware2 = "virus" nocase
        $malware3 = "trojan" nocase
    
    condition:
        $mz at 0 and any of ($malware*)
}
'''
        
        custom_rules = '''/*
    FedSIG+ ThreatNet - Custom YARA Rules
    Add your custom detection rules here
*/

rule Custom_Threat {
    meta:
        description = "Custom threat detection rule"
        threat_level = "medium"
        author = "Your Name"
    
    strings:
        $pattern1 = "custom_threat_pattern"
    
    condition:
        $pattern1
}
'''
        
        rules = {
            'rules/yara_rules.yar': yara_rules,
            'rules/custom_rules.yar': custom_rules
        }
        
        for file_path, content in rules.items():
            full_path = self.project_root / file_path
            if not full_path.exists():
                with open(full_path, 'w') as f:
                    f.write(content)
                print(f"{Colors.GREEN}  ✓ {file_path}{Colors.END}")
            else:
                print(f"{Colors.YELLOW}  ⚠ {file_path} (exists, skipped){Colors.END}")
        
        print(f"{Colors.GREEN}✓ YARA rules created{Colors.END}")
    
    def create_threat_patterns(self):
        """Create threat patterns JSON"""
        print(f"\n{Colors.BLUE}[8/10] Creating threat patterns...{Colors.END}")
        
        patterns = '''{
  "patterns": [
    {
      "name": "Ransomware_Pattern",
      "ioc_type": "behavior_pattern",
      "indicators": [
        "mass_file_encryption",
        "bitcoin_payment_request",
        "file_extension_change"
      ],
      "threat_level": "critical"
    },
    {
      "name": "Keylogger_Pattern",
      "ioc_type": "behavior_pattern",
      "indicators": [
        "keyboard_hook",
        "keystroke_logging",
        "data_exfiltration"
      ],
      "threat_level": "high"
    },
    {
      "name": "C2_Communication",
      "ioc_type": "network_pattern",
      "indicators": [
        "suspicious_dns_query",
        "encrypted_traffic",
        "beaconing_behavior"
      ],
      "threat_level": "high"
    }
  ]
}
'''
        
        file_path = self.project_root / 'rules/threat_patterns.json'
        if not file_path.exists():
            with open(file_path, 'w') as f:
                f.write(patterns)
            print(f"{Colors.GREEN}  ✓ rules/threat_patterns.json{Colors.END}")
        else:
            print(f"{Colors.YELLOW}  ⚠ rules/threat_patterns.json (exists, skipped){Colors.END}")
        
        print(f"{Colors.GREEN}✓ Threat patterns created{Colors.END}")
    
    def verify_file_structure(self):
        """Verify all required files exist"""
        print(f"\n{Colors.BLUE}[9/10] Verifying file structure...{Colors.END}")
        
        required_files = [
            'src/common/models_enhanced.py',
            'src/common/config.py',
            'src/common/logger.py',
            'src/common/constants.py',
            'src/coordinator/integrated_server.py',
            'src/coordinator/trust_manager.py',
            'src/coordinator/intel_aggregator.py',
            'src/coordinator/api_routes.py',
            'src/client/enhanced_client.py',
            'src/client/file_monitor.py',
            'src/client/yara_scanner.py',
            'src/client/ioc_database.py',
            'dashboard/templates/dashboard.html',
            'requirements.txt',
            'launch_fedsig_system.py'
        ]
        
        missing = []
        for file_path in required_files:
            full_path = self.project_root / file_path
            if full_path.exists():
                print(f"{Colors.GREEN}  ✓ {file_path}{Colors.END}")
            else:
                print(f"{Colors.RED}  ✗ {file_path} (missing){Colors.END}")
                missing.append(file_path)
        
        if missing:
            self.errors.append(f"Missing required files: {len(missing)}")
            print(f"\n{Colors.RED}⚠ {len(missing)} required files missing{Colors.END}")
            print(f"{Colors.YELLOW}Copy files from artifacts or repository{Colors.END}")
        else:
            print(f"{Colors.GREEN}✓ All required files present{Colors.END}")
        
        return len(missing) == 0
    
    def print_summary(self):
        """Print setup summary"""
        print(f"\n{Colors.BLUE}[10/10] Setup Summary{Colors.END}\n")
        
        if not self.errors:
            print(f"{Colors.GREEN}✅ Setup completed successfully!{Colors.END}\n")
            
            print(f"{Colors.BOLD}Next steps:{Colors.END}")
            print(f"1. Install dependencies: {Colors.CYAN}pip install -r requirements.txt{Colors.END}")
            print(f"2. Review configurations in config/")
            print(f"3. Launch system: {Colors.CYAN}python launch_fedsig_system.py{Colors.END}")
            print(f"4. Access dashboard: {Colors.CYAN}http://localhost:5000{Colors.END}\n")
        else:
            print(f"{Colors.YELLOW}⚠ Setup completed with issues:{Colors.END}\n")
            
            if self.errors:
                print(f"{Colors.RED}Errors:{Colors.END}")
                for error in self.errors:
                    print(f"  - {error}")
                print()
            
            if self.warnings:
                print(f"{Colors.YELLOW}Warnings:{Colors.END}")
                for warning in self.warnings:
                    print(f"  - {warning}")
                print()
        
        print(f"{Colors.BLUE}{'='*60}{Colors.END}\n")
    
    def run(self):
        """Run complete setup"""
        self.print_banner()
        
        self.create_directory_structure()
        self.create_init_files()
        self.create_gitignore()
        self.check_python_version()
        self.check_dependencies()
        self.generate_sample_configs()
        self.create_sample_yara_rules()
        self.create_threat_patterns()
        self.verify_file_structure()
        self.print_summary()
        
        return 0 if not self.errors else 1


def main():
    """Main entry point"""
    setup = FedSIGSetup()
    return setup.run()


if __name__ == '__main__':
    sys.exit(main())