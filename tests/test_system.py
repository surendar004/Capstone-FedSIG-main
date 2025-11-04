"""
FedSIG+ ThreatNet - Comprehensive Test Suite
Tests for all system components
"""

import sys
import os
import unittest
import tempfile
import shutil
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.common.models_enhanced import IOC, ThreatIntel, TrustScore, ClientProfile
from src.coordinator.trust_manager import TrustManager
from src.coordinator.intel_aggregator import IntelAggregator
from src.client.ioc_database import IOCDatabase


class TestModels(unittest.TestCase):
    """Test data models"""
    
    def test_ioc_creation(self):
        """Test IOC creation and ID generation"""
        ioc = IOC(
            ioc_id=IOC.generate_ioc_id('file_hash', 'abc123'),
            ioc_type='file_hash',
            value='abc123',
            threat_level='high',
            source_client='client1'
        )
        
        self.assertEqual(ioc.ioc_type, 'file_hash')
        self.assertEqual(ioc.value, 'abc123')
        self.assertEqual(ioc.threat_level, 'high')
        
        # Test ID consistency
        id1 = IOC.generate_ioc_id('file_hash', 'test')
        id2 = IOC.generate_ioc_id('file_hash', 'test')
        self.assertEqual(id1, id2)
    
    def test_ioc_serialization(self):
        """Test IOC to/from dict"""
        ioc = IOC(
            ioc_id='test123',
            ioc_type='ip_address',
            value='192.168.1.1',
            threat_level='medium',
            source_client='client1',
            metadata={'country': 'US'}
        )
        
        ioc_dict = ioc.to_dict()
        ioc_restored = IOC.from_dict(ioc_dict)
        
        self.assertEqual(ioc.ioc_id, ioc_restored.ioc_id)
        self.assertEqual(ioc.value, ioc_restored.value)
        self.assertEqual(ioc.metadata, ioc_restored.metadata)
    
    def test_trust_score(self):
        """Test TrustScore calculation"""
        score = TrustScore(
            client_id='client1',
            trust_score=0.8,
            total_reports=10,
            verified_reports=8,
            rejected_reports=2
        )
        
        score.calculate_accuracy()
        self.assertEqual(score.accuracy_rate, 0.8)
    
    def test_client_profile(self):
        """Test ClientProfile creation"""
        profile = ClientProfile(
            client_id='client1',
            hostname='test-host',
            ip_address='127.0.0.1',
            platform='Linux'
        )
        
        self.assertIsNotNone(profile.trust_score)
        self.assertEqual(profile.trust_score.client_id, 'client1')


class TestTrustManager(unittest.TestCase):
    """Test trust management"""
    
    def setUp(self):
        """Setup test database"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, 'test_trust.db')
        self.manager = TrustManager(
            db_path=self.db_path,
            initial_trust=0.5,
            max_trust=1.0,
            min_trust=0.1
        )
    
    def tearDown(self):
        """Cleanup"""
        shutil.rmtree(self.temp_dir)
    
    def test_initialize_client(self):
        """Test client initialization"""
        trust = self.manager.initialize_client('client1')
        self.assertEqual(trust, 0.5)
        
        # Should return same value on second call
        trust2 = self.manager.initialize_client('client1')
        self.assertEqual(trust, trust2)
    
    def test_trust_increase(self):
        """Test trust score increases on verification"""
        self.manager.initialize_client('client1')
        initial = self.manager.get_trust_score('client1')
        
        # Report verified
        new_trust = self.manager.update_trust('client1', verified=True)
        self.assertGreater(new_trust, initial)
    
    def test_trust_decrease(self):
        """Test trust score decreases on rejection"""
        self.manager.initialize_client('client1')
        self.manager.update_trust('client1', verified=True)  # Boost first
        current = self.manager.get_trust_score('client1')
        
        # Report rejected
        new_trust = self.manager.update_trust('client1', verified=False)
        self.assertLess(new_trust, current)
    
    def test_trust_bounds(self):
        """Test trust score stays within bounds"""
        self.manager.initialize_client('client1')
        
        # Try to exceed max
        for _ in range(20):
            self.manager.update_trust('client1', verified=True)
        
        trust = self.manager.get_trust_score('client1')
        self.assertLessEqual(trust, self.manager.max_trust)
        
        # Try to go below min
        for _ in range(50):
            self.manager.update_trust('client1', verified=False)
        
        trust = self.manager.get_trust_score('client1')
        self.assertGreaterEqual(trust, self.manager.min_trust)
    
    def test_get_statistics(self):
        """Test statistics generation"""
        self.manager.initialize_client('client1')
        self.manager.initialize_client('client2')
        self.manager.update_trust('client1', verified=True)
        
        stats = self.manager.get_statistics()
        
        self.assertEqual(stats['total_clients'], 2)
        self.assertIn('average_trust', stats)
        self.assertIn('total_reports', stats)


class TestIntelAggregator(unittest.TestCase):
    """Test intelligence aggregation"""
    
    def setUp(self):
        """Setup test database"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, 'test_intel.db')
        self.aggregator = IntelAggregator(
            db_path=self.db_path,
            consensus_threshold=2,
            consensus_trust_avg=0.6
        )
    
    def tearDown(self):
        """Cleanup"""
        shutil.rmtree(self.temp_dir)
    
    def test_report_ioc(self):
        """Test IOC reporting"""
        ioc = IOC(
            ioc_id=IOC.generate_ioc_id('file_hash', 'abc123'),
            ioc_type='file_hash',
            value='abc123',
            threat_level='high',
            source_client='client1'
        )
        
        # First report - should not verify
        intel = self.aggregator.report_ioc(ioc, 'client1', 0.8)
        self.assertIsNone(intel)
        
        # Second report - should verify
        intel = self.aggregator.report_ioc(ioc, 'client2', 0.7)
        self.assertIsNotNone(intel)
        self.assertEqual(intel.status, 'verified')
    
    def test_consensus_requirement(self):
        """Test consensus threshold enforcement"""
        ioc = IOC(
            ioc_id=IOC.generate_ioc_id('file_hash', 'def456'),
            ioc_type='file_hash',
            value='def456',
            threat_level='medium',
            source_client='client1'
        )
        
        # Low trust score - should not verify even with multiple reports
        self.aggregator.report_ioc(ioc, 'client1', 0.3)
        intel = self.aggregator.report_ioc(ioc, 'client2', 0.3)
        self.assertIsNone(intel)  # Average trust too low
    
    def test_get_all_iocs(self):
        """Test retrieving all IOCs"""
        ioc1 = IOC(
            ioc_id=IOC.generate_ioc_id('file_hash', 'hash1'),
            ioc_type='file_hash',
            value='hash1',
            threat_level='high',
            source_client='client1'
        )
        
        self.aggregator.report_ioc(ioc1, 'client1', 0.8)
        self.aggregator.report_ioc(ioc1, 'client2', 0.8)
        
        iocs = self.aggregator.get_all_iocs(status='verified')
        self.assertEqual(len(iocs), 1)
    
    def test_statistics(self):
        """Test statistics generation"""
        stats = self.aggregator.get_statistics()
        
        self.assertIn('total_iocs', stats)
        self.assertIn('verified_iocs', stats)
        self.assertIn('pending_iocs', stats)


class TestIOCDatabase(unittest.TestCase):
    """Test client IOC database"""
    
    def setUp(self):
        """Setup test database"""
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, 'test_client.db')
        self.db = IOCDatabase(self.db_path)
    
    def tearDown(self):
        """Cleanup"""
        shutil.rmtree(self.temp_dir)
    
    def test_add_ioc(self):
        """Test adding IOC to database"""
        ioc = IOC(
            ioc_id='test123',
            ioc_type='file_hash',
            value='abc123',
            threat_level='high',
            source_client='server'
        )
        
        self.db.add_ioc(ioc, verified=True, trust_weight=0.9)
        
        # Check if exists
        found = self.db.check_ioc('file_hash', 'abc123')
        self.assertIsNotNone(found)
        self.assertEqual(found.value, 'abc123')
    
    def test_check_file_hash(self):
        """Test file hash checking"""
        ioc = IOC(
            ioc_id=IOC.generate_ioc_id('file_hash', 'malicious_hash'),
            ioc_type='file_hash',
            value='malicious_hash',
            threat_level='critical',
            source_client='server'
        )
        
        self.db.add_ioc(ioc, verified=True)
        
        # Should find it
        found = self.db.check_file_hash('malicious_hash')
        self.assertIsNotNone(found)
        self.assertEqual(found.threat_level, 'critical')
        
        # Should not find non-existent
        not_found = self.db.check_file_hash('clean_hash')
        self.assertIsNone(not_found)
    
    def test_record_match(self):
        """Test recording IOC matches"""
        ioc = IOC(
            ioc_id='match_test',
            ioc_type='file_hash',
            value='test_hash',
            threat_level='high',
            source_client='server'
        )
        
        self.db.add_ioc(ioc)
        self.db.record_match('match_test', '/tmp/evil.exe', 'test_hash', 'blocked')
        
        stats = self.db.get_statistics()
        self.assertEqual(stats['total_matches'], 1)
    
    def test_get_statistics(self):
        """Test database statistics"""
        # Add verified IOC
        ioc1 = IOC(
            ioc_id='verified1',
            ioc_type='file_hash',
            value='hash1',
            threat_level='high',
            source_client='server'
        )
        self.db.add_ioc(ioc1, verified=True)
        
        # Add local IOC
        ioc2 = IOC(
            ioc_id='local1',
            ioc_type='file_hash',
            value='hash2',
            threat_level='medium',
            source_client='local'
        )
        self.db.add_ioc(ioc2, verified=False)
        
        stats = self.db.get_statistics()
        self.assertEqual(stats['total_iocs'], 2)
        self.assertEqual(stats['verified_iocs'], 1)
        self.assertEqual(stats['local_iocs'], 1)


class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def setUp(self):
        """Setup test environment"""
        self.temp_dir = tempfile.mkdtemp()
        
        self.trust_manager = TrustManager(
            db_path=os.path.join(self.temp_dir, 'trust.db'),
            initial_trust=0.5
        )
        
        self.intel_aggregator = IntelAggregator(
            db_path=os.path.join(self.temp_dir, 'intel.db'),
            consensus_threshold=2,
            consensus_trust_avg=0.6
        )
    
    def tearDown(self):
        """Cleanup"""
        shutil.rmtree(self.temp_dir)
    
    def test_full_threat_workflow(self):
        """Test complete threat detection and verification workflow"""
        # Initialize clients
        self.trust_manager.initialize_client('client1')
        self.trust_manager.initialize_client('client2')
        
        # Create threat IOC
        ioc = IOC(
            ioc_id=IOC.generate_ioc_id('file_hash', 'threat123'),
            ioc_type='file_hash',
            value='threat123',
            threat_level='critical',
            source_client='client1'
        )
        
        # First client reports
        trust1 = self.trust_manager.get_trust_score('client1')
        intel = self.intel_aggregator.report_ioc(ioc, 'client1', trust1)
        self.assertIsNone(intel)  # Not yet verified
        
        # Second client reports same IOC
        trust2 = self.trust_manager.get_trust_score('client2')
        intel = self.intel_aggregator.report_ioc(ioc, 'client2', trust2)
        self.assertIsNotNone(intel)  # Now verified
        self.assertEqual(intel.status, 'verified')
        
        # Update trust scores
        self.trust_manager.update_trust('client1', verified=True)
        self.trust_manager.update_trust('client2', verified=True)
        
        # Check trust increased
        new_trust1 = self.trust_manager.get_trust_score('client1')
        new_trust2 = self.trust_manager.get_trust_score('client2')
        
        self.assertGreater(new_trust1, trust1)
        self.assertGreater(new_trust2, trust2)


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestModels))
    suite.addTests(loader.loadTestsFromTestCase(TestTrustManager))
    suite.addTests(loader.loadTestsFromTestCase(TestIntelAggregator))
    suite.addTests(loader.loadTestsFromTestCase(TestIOCDatabase))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(run_tests())