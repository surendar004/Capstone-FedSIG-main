#!/usr/bin/env python3
"""
FedSIG+ ThreatNet Enhanced - Automated Setup Script
Creates complete directory structure and configuration files
"""

import os
import sys
from pathlib import Path

def print_header():
    print("=" * 70)
    print("  FedSIG+ ThreatNet Enhanced - Automated Setup")
    print("=" * 70)
    print()

def create_directories():
    """Create all required directories"""
    directories = [
        'src/common',
        'src/coordinator',
        'src/client',
        'dashboard/templates',
        'dashboard/static/js',
        'dashboard/static/css',
        'configs',
        'rules',
        'data/intel',
        'data/client',
        'logs',
        'examples',
        'tests'
    ]
    
    print("📁 Creating directory structure...")
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"  ✓ {directory}/")
    print()

def create_init_files():
    """Create __init__.py files"""
    init_files = {
        'src/__init__.py': '"""FedSIG+ ThreatNet Package"""',
        'src/common/__init__.py': '''"""
FedSIG+ ThreatNet Common Module
"""
from .models_enhanced import IOC, ThreatIntel, TrustScore, ClientProfile
from .config import ServerConfig, ClientConfig, ensure_directories
from .logger import setup_logger
from .constants import IOC_TYPES, THREAT_LEVELS

__all__ = [
    'IOC', 'ThreatIntel', 'TrustScore', 'ClientProfile',
    'ServerConfig', 'ClientConfig', 'ensure_directories',
    'setup_logger', 'IOC_TYPES', 'THREAT_LEVELS'
]
''',
        'src/coordinator/__init__.py': '''"""
FedSIG+ ThreatNet Coordinator Module
"""
from .trust_manager import TrustManager
from .intel_aggregator import IntelAggregator
from .integrated_server import IntegratedServer

__all__ = ['TrustManager', 'IntelAggregator', 'IntegratedServer']
''',
        'src/client/__init__.py': '''"""
FedSIG+ ThreatNet Client Module
"""
from .enhanced_client import EnhancedClient
from .file_monitor import FileMonitor
from .yara_scanner import YARAScanner
from .ioc_database import IOCDatabase

__all__ = ['EnhancedClient', 'FileMonitor', 'YARAScanner', 'IOCDatabase']
'''
    }
    
    print("📝 Creating __init__.py files...")
    for file_path, content in init_files.items():
        with open(file_path, 'w') as f:
            f.write(content)
        print(f"  ✓ {file_path}")
    print()

def create_gitignore():
    """Create .gitignore file"""
    gitignore_content = '''# Python
__pycache__/
*.py[cod]
*$py.class
*.so
.Python
*.egg-info/
dist/
build/

# Virtual Environment
venv/
env/
ENV/

# IDEs
.vscode/
.idea/
*.swp

# OS
.DS_Store
Thumbs.db

# Application
data/
logs/
*.db
*.log

# Configs (keep templates only)
configs/*config.yaml
!configs/*config.yaml.example
'''
    
    print("🔒 Creating .gitignore...")
    with open('.gitignore', 'w') as f:
        f.write(gitignore_content)
    print("  ✓ .gitignore")
    print()

def create_readme_snippet():
    """Create README snippet for artifact files"""
    readme = '''# FedSIG+ ThreatNet Enhanced

## 🚀 Quick Start

### 1. Run Setup
```bash
python setup_enhanced.py
```

### 2. Copy Artifact Files

Copy these files from the artifacts to their locations:

**Core Files:**
- models_enhanced.py → src/common/
- config.py → src/common/
- logger.py → src/common/
- constants.py → src/common/
- trust_manager.py → src/coordinator/
- intel_aggregator.py → src/coordinator/
- api_routes.py → src/coordinator/
- integrated_server.py → src/coordinator/
- enhanced_client.py → src/client/
- file_monitor.py → src/client/
- yara_scanner.py → src/client/
- ioc_database.py → src/client/

**Config & Rules:**
- yara_rules.yar → rules/

**Dashboard:**
- dashboard.html → dashboard/templates/

**Root:**
- requirements.txt → ./
- launch_fedsig_system.py → ./

### 3. Install & Generate Configs
```bash
pip install -r requirements.txt
python -c "from src.common.config import generate_default_configs; generate_default_configs()"
```

### 4. Launch
```bash
# Server
python src/coordinator/integrated_server.py

# Client (new terminal)
python src/client/enhanced_client.py --watch-dir /tmp/watch1
```

### 5. Access Dashboard
```
http://localhost:5000
```

## 📚 Documentation

See COMPLETE_DEPLOYMENT.md for full instructions.
'''
    
    print("📖 Creating README snippet...")
    with open('SETUP_INSTRUCTIONS.txt', 'w') as f:
        f.write(readme)
    print("  ✓ SETUP_INSTRUCTIONS.txt")
    print()

def create_requirements():
    """Create requirements.txt"""
    requirements = '''# FedSIG+ ThreatNet Enhanced - Dependencies

# Core Framework
Flask==3.0.0
Flask-SocketIO==5.3.5
Flask-CORS==4.0.0
python-socketio==5.10.0
python-engineio==4.8.0
eventlet==0.33.3

# Data & Configuration
numpy==1.24.3
pyyaml==6.0.1

# File System Monitoring
watchdog==3.0.0

# Optional: YARA (uncomment if needed)
# yara-python==4.3.1

# Development (optional)
# pytest==7.4.3
# pytest-cov==4.1.0
'''
    
    print("📦 Creating requirements.txt...")
    with open('requirements.txt', 'w') as f:
        f.write(requirements)
    print("  ✓ requirements.txt")
    print()

def print_next_steps():
    """Print next steps for user"""
    instructions = """
╔══════════════════════════════════════════════════════════════╗
║                  Setup Complete! 🎉                          ║
╚══════════════════════════════════════════════════════════════╝

✅ Directory structure created
✅ __init__.py files created
✅ requirements.txt created
✅ .gitignore created

📋 NEXT STEPS:

1. Copy artifact files to their locations
   (See SETUP_INSTRUCTIONS.txt for complete list)

2. Install dependencies:
   pip install -r requirements.txt

3. Generate configurations:
   python -c "from src.common.config import generate_default_configs; generate_default_configs()"

4. Copy these specific artifacts:
   
   FROM CURRENT SESSION (Enhanced Version):
   ✓ src/common/models_enhanced.py
   ✓ src/common/config.py
   ✓ src/common/logger.py
   ✓ src/common/constants.py
   ✓ src/coordinator/intel_aggregator.py
   ✓ src/coordinator/api_routes.py
   ✓ src/coordinator/integrated_server.py
   ✓ src/client/enhanced_client.py
   ✓ src/client/file_monitor.py
   ✓ src/client/yara_scanner.py
   ✓ src/client/ioc_database.py
   ✓ rules/yara_rules.yar
   
   FROM EARLIER SESSION (Basic Version):
   ✓ src/coordinator/trust_manager.py
   ✓ dashboard/templates/dashboard.html
   ✓ launch_fedsig_system.py (optional)

5. Launch the system:
   # Terminal 1:
   python src/coordinator/integrated_server.py
   
   # Terminal 2:
   python src/client/enhanced_client.py --watch-dir /tmp/watch1

6. Access dashboard:
   http://localhost:5000

📚 For detailed instructions, see:
   - SETUP_INSTRUCTIONS.txt
   - COMPLETE_DEPLOYMENT.md (from artifacts)

⚠️  IMPORTANT: Don't forget to copy all artifact files listed above!
    """
    print(instructions)

def main():
    """Main setup function"""
    print_header()
    
    # Confirm
    response = input("This will create the directory structure. Continue? (y/n): ").strip().lower()
    if response not in ['y', 'yes']:
        print("Setup cancelled.")
        return
    
    print()
    
    # Run setup steps
    create_directories()
    create_init_files()
    create_gitignore()
    create_requirements()
    create_readme_snippet()
    
    # Print next steps
    print_next_steps()

if __name__ == '__main__':
    main()