"""
Intelligence Aggregator for FedSIG+ ThreatNet
Collects, validates, and shares IOCs using trust-weighted consensus
"""

import os
import json
import sqlite3
from typing import Dict, List, Optional, Set
from datetime import datetime, timedelta
from collections import defaultdict

from src.common.models_enhanced import IOC, ThreatIntel
from src.common.logger import setup_logger
from src.common.constants import INTEL_STATUS, MIN_CONSENSUS_CLIENTS, MIN_CONSENSUS_TRUST


class IntelAggregator:
    """Aggregates and validates threat intelligence from multiple clients"""
    
    def __init__(self, db_path: str = "data/intel/global_iocs.db",
                 consensus_threshold: int = MIN_CONSENSUS_CLIENTS,
                 consensus_trust_avg: float = MIN_CONSENSUS_TRUST):
        """
        Initialize Intelligence Aggregator
        
        Args:
            db_path: Path to global IOC database
            consensus_threshold: Minimum clients needed to verify IOC
            consensus_trust_avg: Minimum average trust for consensus
        """
        self.db_path = db_path
        self.consensus_threshold = consensus_threshold
        self.consensus_trust_avg = consensus_trust_avg
        self.logger = setup_logger('IntelAggregator', log_file='logs/intel_aggregator.log')
        
        # In-memory cache
        self.ioc_cache: Dict[str, ThreatIntel] = {}
        self.pending_iocs: Dict[str, List[tuple]] = defaultdict(list)  # ioc_id -> [(client_id, trust)]
        
        # Initialize database
        self._init_database()
        self._load_cache()
        
        self.logger.info(f"✅ IntelAggregator initialized (consensus: {consensus_threshold} clients, trust: {consensus_trust_avg})")
    
    def _init_database(self):
        """Initialize SQLite database for IOCs"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create IOCs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                ioc_id TEXT PRIMARY KEY,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                source_client TEXT NOT NULL,
                verified_by TEXT,
                trust_weight REAL DEFAULT 0.0,
                status TEXT DEFAULT 'pending',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                detection_count INTEGER DEFAULT 1,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create detections log table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS detection_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_id TEXT,
                client_id TEXT,
                timestamp TEXT,
                action TEXT,
                FOREIGN KEY (ioc_id) REFERENCES iocs(ioc_id)
            )
        ''')
        
        # Create index for faster queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_status ON iocs(status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_level ON iocs(threat_level)')
        
        conn.commit()
        conn.close()
        
        self.logger.info("📊 Database initialized")
    
    def _load_cache(self):
        """Load verified IOCs into memory cache"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM iocs WHERE status = 'verified'")
        rows = cursor.fetchall()
        
        for row in rows:
            ioc_id = row[0]
            ioc = IOC(
                ioc_id=row[0],
                ioc_type=row[1],
                value=row[2],
                threat_level=row[3],
                source_client=row[4],
                metadata=json.loads(row[11]) if row[11] else {}
            )
            
            intel = ThreatIntel(
                ioc=ioc,
                verified_by=json.loads(row[5]) if row[5] else [],
                trust_weight=row[6],
                status=row[7],
                first_seen=row[8],
                last_seen=row[9],
                detection_count=row[10]
            )
            
            self.ioc_cache[ioc_id] = intel
        
        conn.close()
        self.logger.info(f"📦 Loaded {len(self.ioc_cache)} verified IOCs into cache")
    
    def report_ioc(self, ioc: IOC, client_id: str, trust_score: float) -> Optional[ThreatIntel]:
        """
        Report a new IOC from a client
        
        Args:
            ioc: IOC object
            client_id: Reporting client ID
            trust_score: Client's trust score
        
        Returns:
            ThreatIntel if verified, None if pending
        """
        ioc_id = ioc.ioc_id
        
        # Check if already verified
        if ioc_id in self.ioc_cache:
            self.logger.debug(f"IOC {ioc_id} already verified")
            self._update_detection_count(ioc_id, client_id)
            return self.ioc_cache[ioc_id]
        
        # Add to pending votes
        self.pending_iocs[ioc_id].append((client_id, trust_score))
        
        # Check for consensus
        votes = self.pending_iocs[ioc_id]
        num_votes = len(votes)
        avg_trust = sum(trust for _, trust in votes) / num_votes if num_votes > 0 else 0.0
        
        self.logger.info(f"📊 IOC {ioc_id[:8]}... reported by {client_id} "
                        f"(votes: {num_votes}/{self.consensus_threshold}, avg_trust: {avg_trust:.2f})")
        
        # Verify if consensus reached
        if num_votes >= self.consensus_threshold and avg_trust >= self.consensus_trust_avg:
            intel = self._verify_ioc(ioc, votes)
            self.logger.info(f"✅ IOC {ioc_id[:8]}... VERIFIED (consensus reached)")
            return intel
        
        # Save as pending
        self._save_pending_ioc(ioc, votes)
        return None
    
    def _verify_ioc(self, ioc: IOC, votes: List[tuple]) -> ThreatIntel:
        """Verify an IOC and add to global database"""
        verified_by = [client_id for client_id, _ in votes]
        trust_weight = sum(trust for _, trust in votes) / len(votes)
        
        intel = ThreatIntel(
            ioc=ioc,
            verified_by=verified_by,
            trust_weight=trust_weight,
            status=INTEL_STATUS['VERIFIED'],
            detection_count=len(votes)
        )
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO iocs 
            (ioc_id, ioc_type, value, threat_level, source_client, verified_by, 
             trust_weight, status, first_seen, last_seen, detection_count, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ioc.ioc_id,
            ioc.ioc_type,
            ioc.value,
            ioc.threat_level,
            ioc.source_client,
            json.dumps(verified_by),
            trust_weight,
            INTEL_STATUS['VERIFIED'],
            intel.first_seen,
            intel.last_seen,
            len(votes),
            json.dumps(ioc.metadata)
        ))
        
        conn.commit()
        conn.close()
        
        # Add to cache
        self.ioc_cache[ioc.ioc_id] = intel
        
        # Remove from pending
        if ioc.ioc_id in self.pending_iocs:
            del self.pending_iocs[ioc.ioc_id]
        
        return intel
    
    def _save_pending_ioc(self, ioc: IOC, votes: List[tuple]):
        """Save pending IOC to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        verified_by = [client_id for client_id, _ in votes]
        trust_weight = sum(trust for _, trust in votes) / len(votes) if votes else 0.0
        
        cursor.execute('''
            INSERT OR REPLACE INTO iocs 
            (ioc_id, ioc_type, value, threat_level, source_client, verified_by, 
             trust_weight, status, first_seen, last_seen, detection_count, metadata)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            ioc.ioc_id,
            ioc.ioc_type,
            ioc.value,
            ioc.threat_level,
            ioc.source_client,
            json.dumps(verified_by),
            trust_weight,
            INTEL_STATUS['PENDING'],
            datetime.now().isoformat(),
            datetime.now().isoformat(),
            len(votes),
            json.dumps(ioc.metadata)
        ))
        
        conn.commit()
        conn.close()
    
    def _update_detection_count(self, ioc_id: str, client_id: str):
        """Update detection count for existing IOC"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE iocs 
            SET detection_count = detection_count + 1,
                last_seen = ?
            WHERE ioc_id = ?
        ''', (datetime.now().isoformat(), ioc_id))
        
        # Log detection
        cursor.execute('''
            INSERT INTO detection_log (ioc_id, client_id, timestamp, action)
            VALUES (?, ?, ?, ?)
        ''', (ioc_id, client_id, datetime.now().isoformat(), 'reported'))
        
        conn.commit()
        conn.close()
        
        # Update cache
        if ioc_id in self.ioc_cache:
            self.ioc_cache[ioc_id].detection_count += 1
            self.ioc_cache[ioc_id].last_seen = datetime.now().isoformat()
    
    def get_all_iocs(self, status: Optional[str] = None) -> List[ThreatIntel]:
        """Get all IOCs, optionally filtered by status"""
        if status == INTEL_STATUS['VERIFIED']:
            return list(self.ioc_cache.values())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if status:
            cursor.execute("SELECT * FROM iocs WHERE status = ?", (status,))
        else:
            cursor.execute("SELECT * FROM iocs")
        
        rows = cursor.fetchall()
        conn.close()
        
        intels = []
        for row in rows:
            ioc = IOC(
                ioc_id=row[0],
                ioc_type=row[1],
                value=row[2],
                threat_level=row[3],
                source_client=row[4],
                metadata=json.loads(row[11]) if row[11] else {}
            )
            
            intel = ThreatIntel(
                ioc=ioc,
                verified_by=json.loads(row[5]) if row[5] else [],
                trust_weight=row[6],
                status=row[7],
                first_seen=row[8],
                last_seen=row[9],
                detection_count=row[10]
            )
            intels.append(intel)
        
        return intels
    
    def get_ioc_by_id(self, ioc_id: str) -> Optional[ThreatIntel]:
        """Get specific IOC by ID"""
        if ioc_id in self.ioc_cache:
            return self.ioc_cache[ioc_id]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM iocs WHERE ioc_id = ?", (ioc_id,))
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        ioc = IOC(
            ioc_id=row[0],
            ioc_type=row[1],
            value=row[2],
            threat_level=row[3],
            source_client=row[4],
            metadata=json.loads(row[11]) if row[11] else {}
        )
        
        return ThreatIntel(
            ioc=ioc,
            verified_by=json.loads(row[5]) if row[5] else [],
            trust_weight=row[6],
            status=row[7],
            first_seen=row[8],
            last_seen=row[9],
            detection_count=row[10]
        )
    
    def get_statistics(self) -> Dict:
        """Get intelligence statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Count by status
        cursor.execute("SELECT status, COUNT(*) FROM iocs GROUP BY status")
        status_counts = dict(cursor.fetchall())
        
        # Count by threat level
        cursor.execute("SELECT threat_level, COUNT(*) FROM iocs WHERE status='verified' GROUP BY threat_level")
        threat_counts = dict(cursor.fetchall())
        
        # Count by type
        cursor.execute("SELECT ioc_type, COUNT(*) FROM iocs WHERE status='verified' GROUP BY ioc_type")
        type_counts = dict(cursor.fetchall())
        
        conn.close()
        
        return {
            'total_iocs': sum(status_counts.values()),
            'verified_iocs': status_counts.get(INTEL_STATUS['VERIFIED'], 0),
            'pending_iocs': status_counts.get(INTEL_STATUS['PENDING'], 0),
            'rejected_iocs': status_counts.get(INTEL_STATUS['REJECTED'], 0),
            'threat_distribution': threat_counts,
            'type_distribution': type_counts,
            'consensus_threshold': self.consensus_threshold,
            'consensus_trust_avg': self.consensus_trust_avg
        }
    
    def cleanup_expired_iocs(self, expiry_days: int = 30):
        """Remove expired IOCs from database"""
        expiry_date = datetime.now() - timedelta(days=expiry_days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE iocs 
            SET status = ?
            WHERE last_seen < ? AND status = ?
        ''', (INTEL_STATUS['EXPIRED'], expiry_date.isoformat(), INTEL_STATUS['VERIFIED']))
        
        expired_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        if expired_count > 0:
            self.logger.info(f"🧹 Marked {expired_count} IOCs as expired")
            self._load_cache()  # Reload cache
        
        return expired_count