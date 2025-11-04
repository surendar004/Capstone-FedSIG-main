"""
IOC Database for FedSIG+ ThreatNet Client
Local SQLite database for storing and querying IOCs
"""

import os
import json
import sqlite3
from typing import List, Optional, Dict
from datetime import datetime

from src.common.models_enhanced import IOC, ThreatIntel
from src.common.logger import setup_logger


class IOCDatabase:
    """Local IOC database for client"""
    
    def __init__(self, db_path: str):
        """
        Initialize IOC Database
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = db_path
        self.logger = setup_logger('IOCDatabase')
        
        # Create directory if needed
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Initialize database
        self._init_database()
        
        self.logger.info(f"✅ IOC Database initialized: {db_path}")
    
    def _init_database(self):
        """Initialize SQLite database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create IOCs table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                ioc_id TEXT PRIMARY KEY,
                ioc_type TEXT NOT NULL,
                value TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                source TEXT,
                verified BOOLEAN DEFAULT 0,
                trust_weight REAL DEFAULT 0.0,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                match_count INTEGER DEFAULT 0,
                metadata TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create matches table (for tracking when IOCs are matched locally)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ioc_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_id TEXT,
                file_path TEXT,
                file_hash TEXT,
                matched_at TEXT,
                action_taken TEXT,
                FOREIGN KEY (ioc_id) REFERENCES iocs(ioc_id)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_ioc_type ON iocs(ioc_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_level ON iocs(threat_level)')
        
        conn.commit()
        conn.close()
        
        self.logger.debug("📊 Database schema initialized")
    
    def add_ioc(self, ioc: IOC, verified: bool = False, trust_weight: float = 0.0):
        """Add or update an IOC in the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO iocs 
                (ioc_id, ioc_type, value, threat_level, source, verified, trust_weight, 
                 first_seen, last_seen, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                ioc.ioc_id,
                ioc.ioc_type,
                ioc.value,
                ioc.threat_level,
                ioc.source_client,
                verified,
                trust_weight,
                ioc.timestamp,
                datetime.now().isoformat(),
                json.dumps(ioc.metadata)
            ))
            
            conn.commit()
            self.logger.debug(f"➕ Added IOC: {ioc.ioc_id[:8]}... ({ioc.ioc_type})")
        
        except Exception as e:
            self.logger.error(f"❌ Error adding IOC: {e}")
            conn.rollback()
        
        finally:
            conn.close()
    
    def add_threat_intel(self, intel: ThreatIntel):
        """Add verified threat intelligence from coordinator"""
        self.add_ioc(intel.ioc, verified=True, trust_weight=intel.trust_weight)
    
    def check_ioc(self, ioc_type: str, value: str) -> Optional[IOC]:
        """Check if an IOC exists in the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM iocs 
            WHERE ioc_type = ? AND value = ?
        ''', (ioc_type, value))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return None
        
        return IOC(
            ioc_id=row[0],
            ioc_type=row[1],
            value=row[2],
            threat_level=row[3],
            source_client=row[4],
            timestamp=row[7],
            metadata=json.loads(row[10]) if row[10] else {}
        )
    
    def check_file_hash(self, file_hash: str) -> Optional[IOC]:
        """Check if a file hash is in the IOC database"""
        return self.check_ioc('file_hash', file_hash)
    
    def record_match(self, ioc_id: str, file_path: str, file_hash: str, action: str = 'blocked'):
        """Record when an IOC is matched"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Insert match record
            cursor.execute('''
                INSERT INTO ioc_matches (ioc_id, file_path, file_hash, matched_at, action_taken)
                VALUES (?, ?, ?, ?, ?)
            ''', (ioc_id, file_path, file_hash, datetime.now().isoformat(), action))
            
            # Update IOC match count
            cursor.execute('''
                UPDATE iocs 
                SET match_count = match_count + 1,
                    last_seen = ?
                WHERE ioc_id = ?
            ''', (datetime.now().isoformat(), ioc_id))
            
            conn.commit()
            self.logger.info(f"🎯 IOC match recorded: {ioc_id[:8]}... → {file_path}")
        
        except Exception as e:
            self.logger.error(f"❌ Error recording match: {e}")
            conn.rollback()
        
        finally:
            conn.close()
    
    def get_all_iocs(self, verified_only: bool = False) -> List[IOC]:
        """Get all IOCs from database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if verified_only:
            cursor.execute("SELECT * FROM iocs WHERE verified = 1")
        else:
            cursor.execute("SELECT * FROM iocs")
        
        rows = cursor.fetchall()
        conn.close()
        
        iocs = []
        for row in rows:
            ioc = IOC(
                ioc_id=row[0],
                ioc_type=row[1],
                value=row[2],
                threat_level=row[3],
                source_client=row[4],
                timestamp=row[7],
                metadata=json.loads(row[10]) if row[10] else {}
            )
            iocs.append(ioc)
        
        return iocs
    
    def get_statistics(self) -> Dict:
        """Get database statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total IOCs
        cursor.execute("SELECT COUNT(*) FROM iocs")
        total_iocs = cursor.fetchone()[0]
        
        # Verified IOCs
        cursor.execute("SELECT COUNT(*) FROM iocs WHERE verified = 1")
        verified_iocs = cursor.fetchone()[0]
        
        # IOCs by type
        cursor.execute("SELECT ioc_type, COUNT(*) FROM iocs GROUP BY ioc_type")
        type_counts = dict(cursor.fetchall())
        
        # IOCs by threat level
        cursor.execute("SELECT threat_level, COUNT(*) FROM iocs GROUP BY threat_level")
        threat_counts = dict(cursor.fetchall())
        
        # Total matches
        cursor.execute("SELECT COUNT(*) FROM ioc_matches")
        total_matches = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_iocs': total_iocs,
            'verified_iocs': verified_iocs,
            'local_iocs': total_iocs - verified_iocs,
            'type_distribution': type_counts,
            'threat_distribution': threat_counts,
            'total_matches': total_matches
        }
    
    def sync_from_coordinator(self, intel_list: List[ThreatIntel]):
        """Sync IOCs from coordinator"""
        added = 0
        updated = 0
        
        for intel in intel_list:
            existing = self.check_ioc(intel.ioc.ioc_type, intel.ioc.value)
            
            if existing:
                updated += 1
            else:
                added += 1
            
            self.add_threat_intel(intel)
        
        self.logger.info(f"🔄 Synced intelligence: {added} added, {updated} updated")
        return added, updated
    
    def cleanup_old_iocs(self, days: int = 30):
        """Remove old, unverified IOCs"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cutoff_date = (datetime.now() - datetime.timedelta(days=days)).isoformat()
        
        cursor.execute('''
            DELETE FROM iocs 
            WHERE verified = 0 AND last_seen < ?
        ''', (cutoff_date,))
        
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        
        if deleted > 0:
            self.logger.info(f"🧹 Cleaned up {deleted} old IOCs")
        
        return deleted
    
    def export_iocs(self, output_path: str):
        """Export IOCs to JSON file"""
        iocs = self.get_all_iocs()
        
        data = {
            'exported_at': datetime.now().isoformat(),
            'total_iocs': len(iocs),
            'iocs': [ioc.to_dict() for ioc in iocs]
        }
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        self.logger.info(f"📤 Exported {len(iocs)} IOCs to {output_path}")