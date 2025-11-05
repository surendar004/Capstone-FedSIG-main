#!/usr/bin/env python3
"""
FedSIG+ ThreatNet - Threat Simulator
Creates test threat files for system demonstration and testing
"""

import os
import sys
import time
import hashlib
import random
import argparse
from pathlib import Path
from datetime import datetime

# ANSI colors
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'


class ThreatSimulator:
    """Generates realistic threat scenarios for testing"""
    
    # Threat patterns
    THREAT_TYPES = {
        'ransomware': {
            'extensions': ['.exe', '.dll', '.encrypted'],
            'content_patterns': [
                b'ENCRYPT_ALL_FILES',
                b'BITCOIN_PAYMENT_REQUIRED',
                b'YOUR_FILES_ENCRYPTED'
            ],
            'threat_level': 'critical'
        },
        'trojan': {
            'extensions': ['.exe', '.scr', '.com'],
            'content_patterns': [
                b'BACKDOOR_INSTALLED',
                b'REMOTE_ACCESS_ENABLED',
                b'KEYLOGGER_ACTIVE'
            ],
            'threat_level': 'high'
        },
        'virus': {
            'extensions': ['.exe', '.bat', '.vbs'],
            'content_patterns': [
                b'VIRUS_SIGNATURE_V1',
                b'REPLICATE_TO_SYSTEM',
                b'INJECT_PROCESS'
            ],
            'threat_level': 'high'
        },
        'malware': {
            'extensions': ['.exe', '.dll', '.js'],
            'content_patterns': [
                b'MALICIOUS_CODE_DETECTED',
                b'EXPLOIT_PAYLOAD',
                b'SHELLCODE_INJECTION'
            ],
            'threat_level': 'medium'
        },
        'suspicious': {
            'extensions': ['.ps1', '.cmd', '.bat'],
            'content_patterns': [
                b'OBFUSCATED_SCRIPT',
                b'DOWNLOAD_EXECUTE',
                b'DISABLE_ANTIVIRUS'
            ],
            'threat_level': 'medium'
        }
    }
    
    def __init__(self, output_dir: str = '/tmp/threat_sim'):
        """Initialize simulator"""
        self.output_dir = output_dir
        self.created_files = []
        
        # Create output directory
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        print(f"{Colors.BLUE}🧪 Threat Simulator initialized{Colors.END}")
        print(f"Output directory: {output_dir}\n")
    
    def generate_threat_file(self, threat_type: str, filename: str = None) -> str:
        """
        Generate a single threat file
        
        Args:
            threat_type: Type of threat (ransomware, trojan, etc.)
            filename: Custom filename (optional)
        
        Returns:
            Path to created file
        """
        if threat_type not in self.THREAT_TYPES:
            print(f"{Colors.RED}Unknown threat type: {threat_type}{Colors.END}")
            return None
        
        threat_config = self.THREAT_TYPES[threat_type]
        
        # Generate filename
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            extension = random.choice(threat_config['extensions'])
            filename = f"{threat_type}_{timestamp}{extension}"
        
        filepath = os.path.join(self.output_dir, filename)
        
        # Generate content with threat patterns
        content = self._generate_threat_content(threat_config)
        
        # Write file
        with open(filepath, 'wb') as f:
            f.write(content)
        
        # Calculate hash
        file_hash = hashlib.sha256(content).hexdigest()
        
        self.created_files.append({
            'path': filepath,
            'type': threat_type,
            'hash': file_hash,
            'level': threat_config['threat_level'],
            'size': len(content)
        })
        
        print(f"{Colors.RED}🚨 Created threat file:{Colors.END}")
        print(f"  Type: {threat_type}")
        print(f"  File: {filepath}")
        print(f"  Hash: {file_hash[:16]}...")
        print(f"  Level: {threat_config['threat_level']}")
        print(f"  Size: {len(content)} bytes\n")
        
        return filepath
    
    def _generate_threat_content(self, threat_config: dict) -> bytes:
        """Generate realistic threat file content"""
        content = b''
        
        # Add MZ header (Windows executable)
        content += b'MZ\x90\x00\x03\x00\x00\x00'
        
        # Add random padding
        content += os.urandom(100)
        
        # Add threat patterns
        for pattern in threat_config['content_patterns']:
            content += pattern + b'\x00' * 10
        
        # Add more random data
        content += os.urandom(200)
        
        # Add malware keywords
        keywords = [
            b'malware', b'virus', b'trojan', b'ransomware',
            b'backdoor', b'keylog', b'exploit', b'payload'
        ]
        content += b' '.join(random.sample(keywords, 3))
        
        # Final padding
        content += os.urandom(100)
        
        return content
    
    def generate_scenario(self, scenario: str, count: int = 5):
        """
        Generate a complete threat scenario
        
        Args:
            scenario: Scenario name
            count: Number of files to generate
        """
        print(f"{Colors.YELLOW}📋 Generating scenario: {scenario}{Colors.END}\n")
        
        scenarios = {
            'ransomware_outbreak': ['ransomware'] * count,
            'apt_attack': ['trojan', 'backdoor', 'malware'] * (count // 3),
            'mixed_threats': ['ransomware', 'trojan', 'virus', 'malware', 'suspicious'] * (count // 5),
            'slow_infection': ['suspicious', 'malware', 'trojan']
        }
        
        if scenario not in scenarios:
            print(f"{Colors.RED}Unknown scenario: {scenario}{Colors.END}")
            return
        
        threat_sequence = scenarios[scenario][:count]
        
        for i, threat_type in enumerate(threat_sequence, 1):
            print(f"{Colors.BLUE}[{i}/{len(threat_sequence)}]{Colors.END}")
            self.generate_threat_file(threat_type)
            
            # Delay between threats (realistic timing)
            if i < len(threat_sequence):
                delay = random.uniform(1, 3)
                print(f"⏱️  Waiting {delay:.1f}s before next threat...\n")
                time.sleep(delay)
        
        print(f"{Colors.GREEN}✅ Scenario complete: {len(threat_sequence)} threats generated{Colors.END}\n")
    
    def generate_batch(self, count: int = 10, threat_types: list = None):
        """Generate multiple random threats"""
        print(f"{Colors.YELLOW}📦 Generating batch: {count} threats{Colors.END}\n")
        
        if not threat_types:
            threat_types = list(self.THREAT_TYPES.keys())
        
        for i in range(count):
            threat_type = random.choice(threat_types)
            print(f"{Colors.BLUE}[{i+1}/{count}]{Colors.END}")
            self.generate_threat_file(threat_type)
            
            if i < count - 1:
                time.sleep(random.uniform(0.5, 2))
        
        print(f"{Colors.GREEN}✅ Batch complete: {count} threats generated{Colors.END}\n")
    
    def create_clean_files(self, count: int = 3):
        """Create clean (non-threat) files for testing false positive handling"""
        print(f"{Colors.GREEN}📄 Creating {count} clean files{Colors.END}\n")
        
        for i in range(count):
            filename = f"clean_file_{i+1}.txt"
            filepath = os.path.join(self.output_dir, filename)
            
            content = f"This is a clean file #{i+1}\nNo malware here!\nCreated: {datetime.now()}\n"
            
            with open(filepath, 'w') as f:
                f.write(content)
            
            print(f"✅ Created clean file: {filepath}")
        
        print()
    
    def cleanup(self):
        """Remove all generated threat files"""
        print(f"{Colors.YELLOW}🧹 Cleaning up generated files...{Colors.END}")
        
        for file_info in self.created_files:
            try:
                os.remove(file_info['path'])
                print(f"  ✓ Removed: {file_info['path']}")
            except Exception as e:
                print(f"  ✗ Error removing {file_info['path']}: {e}")
        
        self.created_files = []
        print(f"{Colors.GREEN}✅ Cleanup complete{Colors.END}\n")
    
    def print_summary(self):
        """Print summary of generated threats"""
        if not self.created_files:
            print(f"{Colors.YELLOW}No threats generated yet{Colors.END}")
            return
        
        print(f"\n{Colors.BLUE}{'='*60}{Colors.END}")
        print(f"{Colors.BLUE}THREAT GENERATION SUMMARY{Colors.END}")
        print(f"{Colors.BLUE}{'='*60}{Colors.END}\n")
        
        print(f"Total threats: {len(self.created_files)}")
        print(f"Output directory: {self.output_dir}\n")
        
        # Count by type
        type_counts = {}
        level_counts = {}
        
        for file_info in self.created_files:
            type_counts[file_info['type']] = type_counts.get(file_info['type'], 0) + 1
            level_counts[file_info['level']] = level_counts.get(file_info['level'], 0) + 1
        
        print("By Type:")
        for threat_type, count in sorted(type_counts.items()):
            print(f"  {threat_type}: {count}")
        
        print("\nBy Threat Level:")
        for level, count in sorted(level_counts.items()):
            print(f"  {level}: {count}")
        
        print(f"\n{Colors.BLUE}{'='*60}{Colors.END}\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='FedSIG+ ThreatNet Threat Simulator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate single threat
  python threat_simulator.py --type ransomware

  # Generate scenario
  python threat_simulator.py --scenario ransomware_outbreak --count 10

  # Generate mixed batch
  python threat_simulator.py --batch 20

  # Custom output directory
  python threat_simulator.py --output /tmp/my_threats --batch 5
        """
    )
    
    parser.add_argument('--output', default='/tmp/threat_sim',
                       help='Output directory for generated threats')
    parser.add_argument('--type', choices=list(ThreatSimulator.THREAT_TYPES.keys()),
                       help='Generate single threat of specified type')
    parser.add_argument('--scenario', 
                       choices=['ransomware_outbreak', 'apt_attack', 'mixed_threats', 'slow_infection'],
                       help='Generate predefined threat scenario')
    parser.add_argument('--batch', type=int,
                       help='Generate random batch of N threats')
    parser.add_argument('--count', type=int, default=5,
                       help='Number of threats for scenario (default: 5)')
    parser.add_argument('--clean', type=int,
                       help='Generate N clean files (for false positive testing)')
    parser.add_argument('--cleanup', action='store_true',
                       help='Clean up generated files')
    parser.add_argument('--list', action='store_true',
                       help='List available threat types and scenarios')
    
    args = parser.parse_args()
    
    # List available options
    if args.list:
        print("\n📋 Available Threat Types:")
        for threat_type, config in ThreatSimulator.THREAT_TYPES.items():
            print(f"  - {threat_type} (level: {config['threat_level']})")
        
        print("\n📋 Available Scenarios:")
        scenarios = ['ransomware_outbreak', 'apt_attack', 'mixed_threats', 'slow_infection']
        for scenario in scenarios:
            print(f"  - {scenario}")
        print()
        return 0
    
    # Initialize simulator
    simulator = ThreatSimulator(args.output)
    
    # Execute requested action
    if args.type:
        simulator.generate_threat_file(args.type)
    
    elif args.scenario:
        simulator.generate_scenario(args.scenario, args.count)
    
    elif args.batch:
        simulator.generate_batch(args.batch)
    
    elif args.clean:
        simulator.create_clean_files(args.clean)
    
    elif args.cleanup:
        simulator.cleanup()
    
    else:
        # Interactive mode
        print(f"{Colors.YELLOW}Interactive mode{Colors.END}")
        print("Commands: type <name> | scenario <name> | batch <n> | clean | exit\n")
        
        while True:
            try:
                cmd = input("> ").strip().split()
                
                if not cmd:
                    continue
                
                if cmd[0] == 'type' and len(cmd) > 1:
                    simulator.generate_threat_file(cmd[1])
                
                elif cmd[0] == 'scenario' and len(cmd) > 1:
                    count = int(cmd[2]) if len(cmd) > 2 else 5
                    simulator.generate_scenario(cmd[1], count)
                
                elif cmd[0] == 'batch' and len(cmd) > 1:
                    simulator.generate_batch(int(cmd[1]))
                
                elif cmd[0] == 'clean':
                    simulator.create_clean_files(3)
                
                elif cmd[0] in ['exit', 'quit']:
                    break
                
                else:
                    print(f"{Colors.RED}Unknown command{Colors.END}")
            
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"{Colors.RED}Error: {e}{Colors.END}")
    
    # Print summary
    simulator.print_summary()
    
    return 0


if __name__ == '__main__':
    sys.exit(main())