"""
YARA Scanner for FedSIG+ ThreatNet Client
Pattern-based threat detection using YARA rules
"""

import os
from typing import List, Dict, Optional, Tuple

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

from src.common.logger import setup_logger
from src.common.constants import THREAT_LEVELS


class YARAScanner:
    """YARA-based threat scanner"""
    
    def __init__(self, rules_paths: List[str]):
        """
        Initialize YARA Scanner
        
        Args:
            rules_paths: List of paths to YARA rule files
        """
        self.rules_paths = rules_paths
        self.logger = setup_logger('YARAScanner')
        self.rules = None
        
        if not YARA_AVAILABLE:
            self.logger.warning("⚠️ YARA not available - using fallback detection")
        else:
            self._load_rules()
    
    def _load_rules(self):
        """Load YARA rules from files"""
        if not YARA_AVAILABLE:
            return
        
        try:
            # Combine all rule files
            rule_sources = {}
            
            for idx, rules_path in enumerate(self.rules_paths):
                if os.path.exists(rules_path):
                    with open(rules_path, 'r') as f:
                        rule_sources[f'rules_{idx}'] = f.read()
                    self.logger.info(f"📋 Loaded rules from: {rules_path}")
                else:
                    self.logger.warning(f"⚠️ Rules file not found: {rules_path}")
            
            if rule_sources:
                self.rules = yara.compile(sources=rule_sources)
                self.logger.info(f"✅ YARA rules compiled successfully")
            else:
                self.logger.warning("⚠️ No YARA rules loaded")
        
        except Exception as e:
            self.logger.error(f"❌ Error loading YARA rules: {e}")
            self.rules = None
    
    def scan_file(self, file_path: str, timeout: int = 30) -> Tuple[bool, List[str], str]:
        """
        Scan a file for threats
        
        Args:
            file_path: Path to file to scan
            timeout: Scan timeout in seconds
        
        Returns:
            Tuple of (is_threat, matched_rules, threat_level)
        """
        if YARA_AVAILABLE and self.rules:
            return self._yara_scan(file_path, timeout)
        else:
            return self._fallback_scan(file_path)
    
    def _yara_scan(self, file_path: str, timeout: int) -> Tuple[bool, List[str], str]:
        """Scan using YARA rules"""
        try:
            matches = self.rules.match(filepath=file_path, timeout=timeout)
            
            if not matches:
                return False, [], THREAT_LEVELS['INFO']
            
            # Extract matched rules and determine threat level
            matched_rules = []
            max_threat_level = THREAT_LEVELS['LOW']
            
            for match in matches:
                matched_rules.append(match.rule)
                
                # Get threat level from metadata
                threat_level = match.meta.get('threat_level', 'low')
                
                # Determine highest threat level
                if threat_level == 'critical':
                    max_threat_level = THREAT_LEVELS['CRITICAL']
                elif threat_level == 'high' and max_threat_level != THREAT_LEVELS['CRITICAL']:
                    max_threat_level = THREAT_LEVELS['HIGH']
                elif threat_level == 'medium' and max_threat_level not in [THREAT_LEVELS['CRITICAL'], THREAT_LEVELS['HIGH']]:
                    max_threat_level = THREAT_LEVELS['MEDIUM']
            
            self.logger.warning(f"🚨 Threat detected: {file_path} [{max_threat_level}]")
            self.logger.info(f"   Matched rules: {', '.join(matched_rules)}")
            
            return True, matched_rules, max_threat_level
        
        except Exception as e:
            self.logger.error(f"❌ YARA scan error for {file_path}: {e}")
            return False, [], THREAT_LEVELS['INFO']
    
    def _fallback_scan(self, file_path: str) -> Tuple[bool, List[str], str]:
        """Fallback scanning without YARA"""
        try:
            # Check file extension
            suspicious_extensions = [
                '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', 
                '.js', '.scr', '.com', '.pif', '.msi'
            ]
            
            _, ext = os.path.splitext(file_path)
            ext_lower = ext.lower()
            
            if ext_lower in suspicious_extensions:
                # Read file content (first 1KB)
                with open(file_path, 'rb') as f:
                    content = f.read(1024)
                
                # Check for suspicious patterns
                suspicious_patterns = [
                    b'malware', b'virus', b'trojan', b'backdoor',
                    b'keylog', b'ransomware', b'exploit', b'shellcode'
                ]
                
                found_patterns = []
                for pattern in suspicious_patterns:
                    if pattern in content.lower():
                        found_patterns.append(pattern.decode('utf-8'))
                
                if found_patterns:
                    self.logger.warning(f"⚠️ Suspicious patterns in {file_path}: {found_patterns}")
                    return True, ['fallback_detection'], THREAT_LEVELS['MEDIUM']
                
                # Suspicious extension but no patterns
                self.logger.info(f"ℹ️ Suspicious extension: {file_path}")
                return True, ['suspicious_extension'], THREAT_LEVELS['LOW']
            
            return False, [], THREAT_LEVELS['INFO']
        
        except Exception as e:
            self.logger.error(f"❌ Fallback scan error for {file_path}: {e}")
            return False, [], THREAT_LEVELS['INFO']
    
    def reload_rules(self):
        """Reload YARA rules"""
        if YARA_AVAILABLE:
            self._load_rules()
            self.logger.info("🔄 YARA rules reloaded")
    
    def get_rule_count(self) -> int:
        """Get number of loaded rules"""
        if not YARA_AVAILABLE or not self.rules:
            return 0
        # Note: yara-python doesn't expose rule count directly
        return len(self.rules_paths)