"""
Trust Manager for FedSIG+ ThreatNet
Manages dynamic trust scores with decay, history tracking, and reputation analysis
"""

import json
import sqlite3
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict

from src.common.models_enhanced import TrustScore
from src.common.logger import setup_logger


class TrustManager:
    """
    Advanced trust management system with:
    - Dynamic trust scoring
    - Time-based decay
    - Historical tracking
    - Reputation analysis
    - False positive detection
    """
    
    def __init__(self, 
                 db_path: str = "data/intel/trust_scores.db",
                 initial_trust: float = 0.5,
                 max_trust: float = 1.0,
                 min_trust: float = 0.1,
                 decay_rate: float = 0.95,
                 decay_interval_hours: int = 24):
        """
        Initialize Trust Manager
        
        Args:
            db_path: Path to trust database
            initial_trust: Starting trust score for new clients
            max_trust: Maximum achievable trust score
            min_trust: Minimum trust score threshold
            decay_rate: Trust decay multiplier (0-1)
            decay_interval_hours: Hours between decay applications
        """
        self.db_path = db_path
        self.initial_trust = initial_trust
        self.max_trust = max_trust
        self.min_trust = min_trust
        self.decay_rate = decay_rate
        self.decay_interval = timedelta(hours=decay_interval_hours)
        
        self.logger = setup_logger('TrustManager', log_file='logs/trust_manager.log')
        
        # In-memory cache for fast access
        self.trust_cache: Dict[str, TrustScore] = {}
        self.last_decay: Dict[str, datetime] = {}
        
        # Trust calculation weights
        self.weights = {
            'accuracy': 0.4,
            'contribution': 0.3,
            'responsiveness': 0.2,
            'consistency': 0.1
        }
        
        # Initialize database
        self._init_database()
        self._load_cache()
        
        self.logger.info(f"✅ Trust Manager initialized (initial: {initial_trust}, decay: {decay_rate})")
    
    def _init_database(self):
        """Initialize SQLite database for trust scores"""
        import os
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Trust scores table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS trust_scores (
                client_id TEXT PRIMARY KEY,
                trust_score REAL NOT NULL,
                accuracy_rate REAL DEFAULT 0.0,
                contribution_count INTEGER DEFAULT 0,
                false_positive_count INTEGER DEFAULT 0,
                total_reports INTEGER DEFAULT 0,
                verified_reports INTEGER DEFAULT 0,
                rejected_reports INTEGER DEFAULT 0,
                response_time_avg REAL DEFAULT 0.0,
                last_updated TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        
        # Trust history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS trust_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL,
                trust_score REAL NOT NULL,
                event_type TEXT NOT NULL,
                reason TEXT,
                timestamp TEXT NOT NULL,
                FOREIGN KEY (client_id) REFERENCES trust_scores(client_id)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_client_id ON trust_history(client_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON trust_history(timestamp)')
        
        conn.commit()
        conn.close()
        
        self.logger.debug("📊 Trust database initialized")
    
    def _load_cache(self):
        """Load trust scores into memory cache"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM trust_scores")
        rows = cursor.fetchall()
        
        for row in rows:
            trust_score = TrustScore(
                client_id=row[0],
                trust_score=row[1],
                accuracy_rate=row[2],
                contribution_count=row[3],
                false_positive_count=row[4],
                total_reports=row[5],
                verified_reports=row[6],
                rejected_reports=row[7],
                response_time_avg=row[8],
                last_updated=row[9]
            )
            self.trust_cache[row[0]] = trust_score
            self.last_decay[row[0]] = datetime.fromisoformat(row[9])
        
        conn.close()
        self.logger.info(f"📦 Loaded {len(self.trust_cache)} trust scores into cache")
    
    def initialize_client(self, client_id: str) -> float:
        """
        Initialize trust score for new client
        
        Args:
            client_id: Unique client identifier
            
        Returns:
            Initial trust score
        """
        if client_id in self.trust_cache:
            return self.trust_cache[client_id].trust_score
        
        now = datetime.now().isoformat()
        trust_score = TrustScore(
            client_id=client_id,
            trust_score=self.initial_trust,
            last_updated=now
        )
        
        # Save to database
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO trust_scores 
            (client_id, trust_score, last_updated, created_at)
            VALUES (?, ?, ?, ?)
        ''', (client_id, self.initial_trust, now, now))
        
        # Log initial trust
        cursor.execute('''
            INSERT INTO trust_history (client_id, trust_score, event_type, reason, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (client_id, self.initial_trust, 'initialized', 'New client registration', now))
        
        conn.commit()
        conn.close()
        
        # Cache
        self.trust_cache[client_id] = trust_score
        self.last_decay[client_id] = datetime.now()
        
        self.logger.info(f"🆕 Initialized client {client_id[:8]} with trust {self.initial_trust}")
        
        return self.initial_trust
    
    def get_trust_score(self, client_id: str) -> float:
        """Get current trust score for client"""
        if client_id not in self.trust_cache:
            return self.initialize_client(client_id)
        
        # Apply time-based decay
        self._apply_decay(client_id)
        
        return self.trust_cache[client_id].trust_score
    
    def get_trust_score_obj(self, client_id: str) -> Optional[TrustScore]:
        """Get full TrustScore object for client"""
        if client_id not in self.trust_cache:
            self.initialize_client(client_id)
        
        self._apply_decay(client_id)
        return self.trust_cache[client_id]
    
    def update_trust(self, client_id: str, verified: bool, 
                    response_time: Optional[float] = None) -> float:
        """
        Update trust score based on report validation
        
        Args:
            client_id: Client identifier
            verified: Whether report was verified
            response_time: Response time in seconds
            
        Returns:
            New trust score
        """
        if client_id not in self.trust_cache:
            self.initialize_client(client_id)
        
        score = self.trust_cache[client_id]
        old_trust = score.trust_score
        
        # Update metrics
        score.total_reports += 1
        if verified:
            score.verified_reports += 1
        else:
            score.rejected_reports += 1
            score.false_positive_count += 1
        
        # Update accuracy
        score.calculate_accuracy()
        
        # Update response time (exponential moving average)
        if response_time is not None:
            if score.response_time_avg == 0:
                score.response_time_avg = response_time
            else:
                score.response_time_avg = 0.7 * score.response_time_avg + 0.3 * response_time
        
        # Calculate new trust score
        new_trust = self._calculate_trust_score(score, verified)
        score.trust_score = max(self.min_trust, min(self.max_trust, new_trust))
        score.last_updated = datetime.now().isoformat()
        
        # Save to database
        self._save_trust_score(score)
        
        # Log trust change
        event_type = 'increased' if score.trust_score > old_trust else 'decreased'
        reason = f"Report {'verified' if verified else 'rejected'}"
        self._log_trust_event(client_id, score.trust_score, event_type, reason)
        
        self.logger.info(
            f"{'✅' if verified else '❌'} {client_id[:8]} trust: "
            f"{old_trust:.3f} → {score.trust_score:.3f} "
            f"(accuracy: {score.accuracy_rate:.2%})"
        )
        
        return score.trust_score
    
    def _calculate_trust_score(self, score: TrustScore, verified: bool) -> float:
        """Calculate new trust score using weighted formula"""
        # Accuracy component
        accuracy_component = score.accuracy_rate * self.weights['accuracy']
        
        # Contribution component (normalized by log scale)
        import math
        contribution_component = min(1.0, math.log1p(score.contribution_count) / 5) * self.weights['contribution']
        
        # Responsiveness component (inverse of response time, normalized)
        if score.response_time_avg > 0:
            responsiveness = max(0, 1.0 - (score.response_time_avg / 60))  # 60s baseline
        else:
            responsiveness = 0.5
        responsiveness_component = responsiveness * self.weights['responsiveness']
        
        # Consistency component (inverse of false positive rate)
        if score.total_reports > 0:
            false_positive_rate = score.false_positive_count / score.total_reports
            consistency = 1.0 - false_positive_rate
        else:
            consistency = 0.5
        consistency_component = consistency * self.weights['consistency']
        
        # Calculate base trust
        base_trust = (
            accuracy_component +
            contribution_component +
            responsiveness_component +
            consistency_component
        )
        
        # Apply immediate adjustment based on current report
        if verified:
            adjustment = 0.05  # Small boost for correct report
        else:
            adjustment = -0.1  # Larger penalty for false positive
        
        return base_trust + adjustment
    
    def _apply_decay(self, client_id: str):
        """Apply time-based trust decay"""
        if client_id not in self.last_decay:
            self.last_decay[client_id] = datetime.now()
            return
        
        now = datetime.now()
        elapsed = now - self.last_decay[client_id]
        
        if elapsed >= self.decay_interval:
            score = self.trust_cache[client_id]
            old_trust = score.trust_score
            
            # Calculate decay periods
            periods = int(elapsed / self.decay_interval)
            
            # Apply decay towards initial trust
            decay_factor = self.decay_rate ** periods
            score.trust_score = (
                score.trust_score * decay_factor +
                self.initial_trust * (1 - decay_factor)
            )
            
            score.trust_score = max(self.min_trust, score.trust_score)
            score.last_updated = now.isoformat()
            
            self.last_decay[client_id] = now
            
            if abs(old_trust - score.trust_score) > 0.01:
                self._save_trust_score(score)
                self._log_trust_event(client_id, score.trust_score, 'decayed', 
                                     f'Time-based decay after {periods} period(s)')
                
                self.logger.debug(
                    f"⏱️ {client_id[:8]} trust decayed: "
                    f"{old_trust:.3f} → {score.trust_score:.3f}"
                )
    
    def _save_trust_score(self, score: TrustScore):
        """Save trust score to database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO trust_scores 
            (client_id, trust_score, accuracy_rate, contribution_count, 
             false_positive_count, total_reports, verified_reports, 
             rejected_reports, response_time_avg, last_updated, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
                    COALESCE((SELECT created_at FROM trust_scores WHERE client_id = ?), ?))
        ''', (
            score.client_id, score.trust_score, score.accuracy_rate,
            score.contribution_count, score.false_positive_count,
            score.total_reports, score.verified_reports, score.rejected_reports,
            score.response_time_avg, score.last_updated,
            score.client_id, score.last_updated
        ))
        
        conn.commit()
        conn.close()
    
    def _log_trust_event(self, client_id: str, trust_score: float, 
                        event_type: str, reason: str):
        """Log trust score change to history"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO trust_history (client_id, trust_score, event_type, reason, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (client_id, trust_score, event_type, reason, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
    
    def get_all_trust_scores(self) -> List[TrustScore]:
        """Get all trust scores"""
        # Apply decay to all
        for client_id in list(self.trust_cache.keys()):
            self._apply_decay(client_id)
        
        return list(self.trust_cache.values())
    
    def get_trust_history(self, client_id: str, limit: int = 50) -> List[Dict]:
        """Get trust score history for client"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT trust_score, event_type, reason, timestamp
            FROM trust_history
            WHERE client_id = ?
            ORDER BY timestamp DESC
            LIMIT ?
        ''', (client_id, limit))
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                'trust_score': row[0],
                'event_type': row[1],
                'reason': row[2],
                'timestamp': row[3]
            }
            for row in rows
        ]
    
    def get_statistics(self) -> Dict:
        """Get trust system statistics"""
        scores = self.get_all_trust_scores()
        
        if not scores:
            return {
                'total_clients': 0,
                'average_trust': self.initial_trust,
                'high_trust_count': 0,
                'medium_trust_count': 0,
                'low_trust_count': 0
            }
        
        trust_values = [s.trust_score for s in scores]
        
        return {
            'total_clients': len(scores),
            'average_trust': sum(trust_values) / len(trust_values),
            'max_trust': max(trust_values),
            'min_trust': min(trust_values),
            'high_trust_count': sum(1 for t in trust_values if t >= 0.7),
            'medium_trust_count': sum(1 for t in trust_values if 0.4 <= t < 0.7),
            'low_trust_count': sum(1 for t in trust_values if t < 0.4),
            'total_reports': sum(s.total_reports for s in scores),
            'total_verified': sum(s.verified_reports for s in scores),
            'total_rejected': sum(s.rejected_reports for s in scores)
        }
    
    def reset_client_trust(self, client_id: str):
        """Reset client trust to initial value"""
        if client_id in self.trust_cache:
            score = self.trust_cache[client_id]
            score.trust_score = self.initial_trust
            score.last_updated = datetime.now().isoformat()
            
            self._save_trust_score(score)
            self._log_trust_event(client_id, self.initial_trust, 'reset', 'Manual reset')
            
            self.logger.info(f"🔄 Reset trust for {client_id[:8]} to {self.initial_trust}")
    
    def calculate_weighted_consensus(self, client_trust_scores: Dict[str, float]) -> float:
        """
        Calculate trust-weighted consensus score
        
        Args:
            client_trust_scores: Dict of client_id -> confidence_score
            
        Returns:
            Weighted consensus score (0-1)
        """
        if not client_trust_scores:
            return 0.0
        
        weighted_sum = 0.0
        trust_sum = 0.0
        
        for client_id, confidence in client_trust_scores.items():
            trust = self.get_trust_score(client_id)
            weighted_sum += confidence * trust
            trust_sum += trust
        
        if trust_sum == 0:
            return 0.0
        
        return weighted_sum / trust_sum