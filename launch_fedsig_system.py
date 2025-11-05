#!/usr/bin/env python3
"""
FedSIG+ ThreatNet - Complete System Launcher
Automated deployment with dependency checking, configuration, and monitoring
"""

import os
import sys
import subprocess
import time
import webbrowser
import platform
import signal
from pathlib import Path
from typing import List, Optional

# ANSI Colors
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class FedSIGLauncher:
    """Complete system launcher with health checks"""
    
    def __init__(self):
        self.processes = []
        self.server_process = None
        self.client_processes = []
        
    def print_banner(self):
        """Print FedSIG+ banner"""
        banner = f"""{Colors.CYAN}
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║     {Colors.BOLD}███████╗███████╗██████╗ ███████╗██╗ ██████╗ ██╗    {Colors.END}{Colors.CYAN}      ║
║     {Colors.BOLD}██╔════╝██╔════╝██╔══██╗██╔════╝██║██╔════╝ ██║    {Colors.END}{Colors.CYAN}      ║
║     {Colors.BOLD}█████╗  █████╗  ██║  ██║███████╗██║██║  ███╗███████╗{Colors.END}{Colors.CYAN}      ║
║     {Colors.BOLD}██╔══╝  ██╔══╝  ██║  ██║╚════██║██║██║   ██║╚════██║{Colors.END}{Colors.CYAN}      ║
║     {Colors.BOLD}██║     ███████╗██████╔╝███████║██║╚██████╔╝     ██║{Colors.END}{Colors.CYAN}      ║
║     {Colors.BOLD}╚═╝     ╚══════╝╚═════╝ ╚══════╝╚═╝ ╚═════╝      ╚═╝{Colors.END}{Colors.CYAN}      ║
║                                                                ║
║        {Colors.BOLD}Federated Cyber Threat Intelligence Platform v2.0{Colors.END}{Colors.CYAN}      ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝{Colors.END}
        """
        print(banner)
    
    def check_python_version(self) -> bool:
        """Check Python version"""
        print(f"\n{Colors.BLUE}[1/8] Checking Python version...{Colors.END}")
        
        version = sys.version_info
        if version.major < 3 or (version.major == 3 and version.minor < 8):
            print(f"{Colors.RED}✗ Python 3.8+ required. Current: {version.major}.{version.minor}{Colors.END}")
            return False
        
        print(f"{Colors.GREEN}✓ Python {version.major}.{version.minor}.{version.micro}{Colors.END}")
        return True
    
    def check_dependencies(self) -> bool:
        """Check required Python packages"""
        print(f"\n{Colors.BLUE}[2/8] Checking dependencies...{Colors.END}")
        
        required = {
            'flask': 'Flask',
            'flask_socketio': 'Flask-SocketIO',
            'flask_cors': 'Flask-CORS',
            'socketio': 'python-socketio',
            'eventlet': 'eventlet',
            'numpy': 'numpy',
            'yaml': 'PyYAML',
            'watchdog': 'watchdog'
        }
        
        missing = []
        for module, package in required.items():
            try:
                __import__(module)
                print(f"{Colors.GREEN}  ✓ {package}{Colors.END}")
            except ImportError:
                print(f"{Colors.RED}  ✗ {package}{Colors.END}")
                missing.append(package)
        
        if missing:
            print(f"\n{Colors.YELLOW}⚠ Missing packages. Install with:{Colors.END}")
            print(f"{Colors.BOLD}pip install -r requirements.txt{Colors.END}\n")
            return False
        
        print(f"{Colors.GREEN}✓ All dependencies satisfied{Colors.END}")
        return True
    
    def check_file_structure(self) -> bool:
        """Verify required files exist"""
        print(f"\n{Colors.BLUE}[3/8] Checking file structure...{Colors.END}")
        
        required_files = [
            'src/common/models_enhanced.py',
            'src/common/config.py',
            'src/common/logger.py',
            'src/coordinator/integrated_server.py',
            'src/coordinator/trust_manager.py',
            'src/coordinator/intel_aggregator.py',
            'src/client/enhanced_client.py',
            'dashboard/templates/dashboard.html'
        ]
        
        missing = []
        for file_path in required_files:
            if os.path.exists(file_path):
                print(f"{Colors.GREEN}  ✓ {file_path}{Colors.END}")
            else:
                print(f"{Colors.RED}  ✗ {file_path}{Colors.END}")
                missing.append(file_path)
        
        if missing:
            print(f"\n{Colors.RED}✗ Missing required files{Colors.END}")
            return False
        
        print(f"{Colors.GREEN}✓ All required files present{Colors.END}")
        return True
    
    def ensure_directories(self) -> bool:
        """Create necessary directories"""
        print(f"\n{Colors.BLUE}[4/8] Creating directories...{Colors.END}")
        
        directories = [
            'data/intel',
            'data/client',
            'logs',
            'configs',
            'rules'
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            print(f"{Colors.GREEN}  ✓ {directory}/{Colors.END}")
        
        print(f"{Colors.GREEN}✓ Directories ready{Colors.END}")
        return True
    
    def create_init_files(self) -> bool:
        """Create __init__.py files"""
        print(f"\n{Colors.BLUE}[5/8] Creating package files...{Colors.END}")
        
        init_files = [
            'src/__init__.py',
            'src/common/__init__.py',
            'src/coordinator/__init__.py',
            'src/client/__init__.py'
        ]
        
        for init_file in init_files:
            if not os.path.exists(init_file):
                Path(init_file).touch()
                print(f"{Colors.GREEN}  ✓ Created {init_file}{Colors.END}")
            else:
                print(f"{Colors.GREEN}  ✓ {init_file} exists{Colors.END}")
        
        print(f"{Colors.GREEN}✓ Package structure ready{Colors.END}")
        return True
    
    def generate_configs(self) -> bool:
        """Generate configuration files if missing"""
        print(f"\n{Colors.BLUE}[6/8] Checking configurations...{Colors.END}")
        
        try:
            sys.path.insert(0, os.getcwd())
            from src.common.config import generate_default_configs
            
            if not os.path.exists('configs/server_config.yaml'):
                generate_default_configs()
                print(f"{Colors.GREEN}  ✓ Generated default configurations{Colors.END}")
            else:
                print(f"{Colors.GREEN}  ✓ Configurations exist{Colors.END}")
            
            return True
        except Exception as e:
            print(f"{Colors.YELLOW}  ⚠ Config generation skipped: {e}{Colors.END}")
            return True  # Non-critical
    
    def check_ports(self) -> bool:
        """Check if required ports are available"""
        print(f"\n{Colors.BLUE}[7/8] Checking ports...{Colors.END}")
        
        import socket
        
        def is_port_available(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind(('', port))
                sock.close()
                return True
            except:
                return False
        
        if not is_port_available(5000):
            print(f"{Colors.YELLOW}  ⚠ Port 5000 in use - server may fail to start{Colors.END}")
            print(f"    Kill existing process or use: --port <other_port>")
            return True  # Warning only
        
        print(f"{Colors.GREEN}  ✓ Port 5000 available{Colors.END}")
        return True
    
    def start_server(self, port: int = 5000, debug: bool = False) -> Optional[subprocess.Popen]:
        """Start coordinator server"""
        print(f"\n{Colors.BLUE}[8/8] Starting FedSIG+ Server...{Colors.END}")
        
        cmd = [sys.executable, 'src/coordinator/integrated_server.py', '--port', str(port)]
        if debug:
            cmd.append('--debug')
        
        try:
            if platform.system() == 'Windows':
                process = subprocess.Popen(
                    cmd,
                    creationflags=subprocess.CREATE_NEW_CONSOLE
                )
            else:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            
            self.server_process = process
            print(f"{Colors.GREEN}✓ Server starting (PID: {process.pid})...{Colors.END}")
            
            # Wait for server initialization
            print(f"{Colors.YELLOW}⏳ Waiting for server initialization...{Colors.END}")
            time.sleep(3)
            
            # Check if still running
            if process.poll() is None:
                print(f"{Colors.GREEN}✓ Server running successfully{Colors.END}")
                return process
            else:
                print(f"{Colors.RED}✗ Server failed to start{Colors.END}")
                return None
        
        except Exception as e:
            print(f"{Colors.RED}✗ Failed to start server: {e}{Colors.END}")
            return None
    
    def open_dashboard(self, port: int = 5000):
        """Open dashboard in browser"""
        url = f'http://localhost:{port}'
        print(f"\n{Colors.GREEN}🌐 Opening dashboard: {url}{Colors.END}")
        
        try:
            webbrowser.open(url)
        except Exception as e:
            print(f"{Colors.YELLOW}⚠ Could not open browser automatically: {e}{Colors.END}")
            print(f"   Please open manually: {url}")
    
    def print_instructions(self, port: int = 5000):
        """Print usage instructions"""
        instructions = f"""
{Colors.CYAN}╔══════════════════════════════════════════════════════════════╗
║                   {Colors.BOLD}System Started Successfully!{Colors.END}{Colors.CYAN}                ║
╚══════════════════════════════════════════════════════════════╝{Colors.END}

{Colors.GREEN}✅ Server Status:{Colors.END} Running on http://localhost:{port}
{Colors.GREEN}✅ Dashboard:{Colors.END} http://localhost:{port}

{Colors.BOLD}📋 Start Federated Clients:{Colors.END}

{Colors.CYAN}Option 1: Monitor a directory{Colors.END}
{Colors.BOLD}python src/client/enhanced_client.py --watch-dir /path/to/monitor{Colors.END}

{Colors.CYAN}Option 2: Interactive mode{Colors.END}
{Colors.BOLD}python src/client/enhanced_client.py --interactive{Colors.END}

{Colors.CYAN}Option 3: With custom server{Colors.END}
{Colors.BOLD}python src/client/enhanced_client.py --server http://localhost:{port}{Colors.END}

{Colors.BOLD}📊 Example: Start 2 Clients{Colors.END}

{Colors.CYAN}Terminal 2:{Colors.END}
python src/client/enhanced_client.py --watch-dir /tmp/watch1

{Colors.CYAN}Terminal 3:{Colors.END}
python src/client/enhanced_client.py --watch-dir /tmp/watch2

{Colors.BOLD}🧪 Test Threat Detection:{Colors.END}

mkdir -p /tmp/watch1
echo "test malware" > /tmp/watch1/suspicious.exe

{Colors.BOLD}📚 API Endpoints:{Colors.END}

{Colors.GREEN}GET{Colors.END}  /api/status          - System status
{Colors.GREEN}GET{Colors.END}  /api/clients         - Connected clients
{Colors.GREEN}GET{Colors.END}  /api/iocs            - IOC intelligence
{Colors.GREEN}GET{Colors.END}  /api/trust_scores    - Trust scores
{Colors.GREEN}POST{Colors.END} /api/report_threat   - Report threat

{Colors.YELLOW}⚠️  Press Ctrl+C to stop the server{Colors.END}
        """
        print(instructions)
    
    def cleanup(self):
        """Cleanup processes on exit"""
        print(f"\n\n{Colors.YELLOW}🛑 Shutting down FedSIG+ ThreatNet...{Colors.END}")
        
        if self.server_process:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
                print(f"{Colors.GREEN}✓ Server stopped{Colors.END}")
            except:
                self.server_process.kill()
                print(f"{Colors.YELLOW}⚠ Server force killed{Colors.END}")
        
        print(f"{Colors.GREEN}✓ Cleanup complete{Colors.END}\n")
    
    def run(self, port: int = 5000, debug: bool = False, no_browser: bool = False):
        """Main launcher routine"""
        self.print_banner()
        
        # Run all checks
        if not self.check_python_version():
            return 1
        
        if not self.check_dependencies():
            return 1
        
        if not self.check_file_structure():
            return 1
        
        if not self.ensure_directories():
            return 1
        
        if not self.create_init_files():
            return 1
        
        self.generate_configs()
        self.check_ports()
        
        # Start server
        if not self.start_server(port, debug):
            print(f"\n{Colors.RED}❌ Failed to start server{Colors.END}")
            return 1
        
        # Open dashboard
        if not no_browser:
            self.open_dashboard(port)
        
        # Print instructions
        self.print_instructions(port)
        
        # Keep running
        try:
            print(f"\n{Colors.GREEN}🏃 System running... (Press Ctrl+C to stop){Colors.END}\n")
            
            # Monitor server
            while True:
                time.sleep(1)
                if self.server_process and self.server_process.poll() is not None:
                    print(f"\n{Colors.RED}❌ Server crashed unexpectedly{Colors.END}")
                    return 1
        
        except KeyboardInterrupt:
            self.cleanup()
            return 0


def main():
    """Entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='FedSIG+ ThreatNet System Launcher',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--port', type=int, default=5000,
                       help='Server port (default: 5000)')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug mode')
    parser.add_argument('--no-browser', action='store_true',
                       help='Do not open browser automatically')
    
    args = parser.parse_args()
    
    # Setup signal handler
    launcher = FedSIGLauncher()
    
    def signal_handler(sig, frame):
        launcher.cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)
    
    # Run launcher
    return launcher.run(args.port, args.debug, args.no_browser)


if __name__ == '__main__':
    sys.exit(main())