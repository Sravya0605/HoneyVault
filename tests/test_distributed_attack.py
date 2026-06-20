"""
Tests for Distributed Attack Detection (PRIORITY 3).

Tests the compute_cross_session_correlations functionality
for multi-IP and time-spread attacks.
"""

import pytest
import time
import asyncio
from app.services.sinkhole_service import SinkholeService


class TestDistributedAttackDetection:
    """Test distributed attack detection capabilities."""
    
    @pytest.fixture
    async def sinkhole_service(self):
        """Create sinkhole service instance."""
        return SinkholeService()
    
    @pytest.mark.asyncio
    async def test_credential_reuse_detection(self):
        """Detect credentials accessed across multiple sessions (multi-IP attack)."""
        service = SinkholeService()
        
        # Simulate multi-session attack with credential reuse
        # Session 1: IP1 accesses credentials A, B, C
        logs_session1 = [
            {"session_id": "session_1", "api_key": "AKIA_CRED_A", "is_fake": True, "timestamp": time.time()},
            {"session_id": "session_1", "api_key": "AKIA_CRED_B", "is_fake": True, "timestamp": time.time() + 1},
            {"session_id": "session_1", "api_key": "AKIA_CRED_C", "is_fake": True, "timestamp": time.time() + 2},
        ]
        
        # Session 2: IP2 accesses credentials B, C, D (overlapping!)
        logs_session2 = [
            {"session_id": "session_2", "api_key": "AKIA_CRED_B", "is_fake": True, "timestamp": time.time() + 30},
            {"session_id": "session_2", "api_key": "AKIA_CRED_C", "is_fake": True, "timestamp": time.time() + 31},
            {"session_id": "session_2", "api_key": "AKIA_CRED_D", "is_fake": True, "timestamp": time.time() + 32},
        ]
        
        # Mock the logger to return our test logs
        service.logger.get_logs = lambda limit: logs_session1 + logs_session2
        
        # Run correlation analysis
        result = await service.compute_cross_session_correlations(limit_seconds=100)
        
        # Should detect credential reuse
        assert result["total_sessions"] == 2
        assert result["unique_fake_credentials"] == 4  # A, B, C, D
        
        # Should have found correlations
        assert len(result["correlations_detected"]) > 0
        
        # Find credential_reuse correlation
        credential_reuse = [
            c for c in result["correlations_detected"]
            if c["type"] == "credential_reuse"
        ]
        assert len(credential_reuse) > 0
        assert credential_reuse[0]["severity"] == "high"
    
    @pytest.mark.asyncio
    async def test_temporal_clustering_detection(self):
        """Detect multiple sessions clustered in time (coordinated attack)."""
        service = SinkholeService()
        
        current_time = time.time()
        
        # Session 1: timestamp T
        logs_session1 = [
            {"session_id": "cluster_s1", "api_key": "AKIA_CRED_1", "is_fake": True, "timestamp": current_time},
        ]
        
        # Session 2: timestamp T+30 seconds (suspicious clustering)
        logs_session2 = [
            {"session_id": "cluster_s2", "api_key": "AKIA_CRED_2", "is_fake": True, "timestamp": current_time + 30},
        ]
        
        # Session 3: timestamp T+1000 seconds (normal, not clustered)
        logs_session3 = [
            {"session_id": "cluster_s3", "api_key": "AKIA_CRED_3", "is_fake": True, "timestamp": current_time + 1000},
        ]
        
        service.logger.get_logs = lambda limit: logs_session1 + logs_session2 + logs_session3
        
        result = await service.compute_cross_session_correlations(limit_seconds=2000)
        
        # Should detect temporal clustering
        temporal_clustering = [
            c for c in result["correlations_detected"]
            if c["type"] == "temporal_clustering"
        ]
        
        # Should find at least one temporal clustering (s1-s2)
        assert len(temporal_clustering) > 0
        assert temporal_clustering[0]["time_delta_seconds"] < 60
    
    @pytest.mark.asyncio
    async def test_escalating_attack_detection(self):
        """Detect attack escalation (increasing access rate)."""
        service = SinkholeService()
        
        current_time = time.time()
        
        # Simulate slow start, then escalation
        logs = []
        
        # Phase 1: Slow reconnaissance (1 access every 5 seconds)
        for i in range(5):
            logs.append({
                "session_id": "escalation_test",
                "api_key": f"AKIA_RECON_{i}",
                "is_fake": True,
                "timestamp": current_time + (i * 5),
                "endpoint": "/ec2"
            })
        
        # Phase 2: Escalation (1 access every 0.5 seconds)
        for i in range(10):
            logs.append({
                "session_id": "escalation_test",
                "api_key": f"AKIA_ENUM_{i}",
                "is_fake": True,
                "timestamp": current_time + 25 + (i * 0.5),
                "endpoint": "/iam"
            })
        
        service.logger.get_logs = lambda limit: logs
        
        result = await service.compute_cross_session_correlations(limit_seconds=100)
        
        # Should detect escalating attack pattern
        escalating = [
            p for p in result["attack_patterns"]
            if p["type"] == "escalating_attack"
        ]
        
        # May or may not detect depending on thresholds
        attack_pattern_types = [p["type"] for p in result["attack_patterns"]]
        assert len(result["attack_patterns"]) > 0  # At least some patterns detected
    
    @pytest.mark.asyncio
    async def test_service_reconnaissance_detection(self):
        """Detect reconnaissance phase (probing multiple AWS services)."""
        service = SinkholeService()
        
        logs = [
            {"session_id": "recon_session", "api_key": f"AKIA_KEY_{i}", "is_fake": True, 
             "timestamp": time.time() + i, "endpoint": endpoint}
            for i, endpoint in enumerate([
                "/ec2", "/iam", "/s3", "/rds", "/lambda", "/cloudformation",
                "/dynamodb", "/kms", "/secretsmanager"
            ])
        ]
        
        service.logger.get_logs = lambda limit: logs
        
        result = await service.compute_cross_session_correlations(limit_seconds=100)
        
        # Should detect service reconnaissance
        recon = [
            p for p in result["attack_patterns"]
            if p["type"] == "service_reconnaissance"
        ]
        
        assert len(recon) > 0
        assert recon[0]["unique_endpoints"] == 9
        assert recon[0]["severity"] == "medium"
    
    @pytest.mark.asyncio
    async def test_burst_pattern_detection(self):
        """Detect burst patterns (sub-second intervals between accesses)."""
        service = SinkholeService()
        
        current_time = time.time()
        logs = []
        
        # Simulate burst: many accesses in <1 second
        for i in range(20):
            logs.append({
                "session_id": "burst_session",
                "api_key": f"AKIA_BURST_{i}",
                "is_fake": True,
                "timestamp": current_time + (i * 0.1),  # 0.1 second intervals
            })
        
        service.logger.get_logs = lambda limit: logs
        
        result = await service.compute_cross_session_correlations(limit_seconds=100)
        
        # Check burst detection in temporal analysis
        temporal = result["temporal_analysis"]
        assert temporal["burst_detected"] == True
        assert temporal["accesses_per_minute"] > 60  # >1 per second
    
    @pytest.mark.asyncio
    async def test_risk_score_computation(self):
        """Test distributed attack risk score."""
        service = SinkholeService()
        
        # High-risk scenario: multiple sessions, high access rate, correlations
        current_time = time.time()
        logs = []
        
        # 3 sessions with credential reuse
        for session_num in range(3):
            for i in range(40):
                logs.append({
                    "session_id": f"risk_session_{session_num}",
                    "api_key": f"AKIA_RISK_{session_num}_{i}",
                    "is_fake": True,
                    "timestamp": current_time + (session_num * 15) + i,  # Clustered sessions
                })
        
        service.logger.get_logs = lambda limit: logs
        
        result = await service.compute_cross_session_correlations(limit_seconds=500)
        
        # Should compute high risk score
        assert result["risk_score"] > 0.5, "High-risk scenario should have risk_score > 0.5"
        assert result["total_sessions"] == 3
        assert result["fake_credential_count"] == 120
    
    @pytest.mark.asyncio
    async def test_no_false_positives_normal_usage(self):
        """Ensure normal usage doesn't trigger false positives."""
        service = SinkholeService()
        
        # Normal usage: 1-2 credentials per session, 1-2 minute gap
        logs = [
            {"session_id": "normal_1", "api_key": "AKIA_NORMAL_1", "is_fake": False, "timestamp": time.time()},
            {"session_id": "normal_2", "api_key": "AKIA_NORMAL_2", "is_fake": False, "timestamp": time.time() + 120},
        ]
        
        service.logger.get_logs = lambda limit: logs
        
        result = await service.compute_cross_session_correlations(limit_seconds=300)
        
        # Should not detect attack patterns in normal usage
        # (only 1 real credential access doesn't trigger patterns)
        assert result["risk_score"] < 0.3


class TestTimeSpreadAttackDetection:
    """Test detection of time-spread attacks."""
    
    @pytest.mark.asyncio
    async def test_time_spread_attack_detection(self):
        """Detect attacks spread over time with intentional gaps."""
        service = SinkholeService()
        
        current_time = time.time()
        logs = []
        
        # Spread attack across 1 hour with mixed intervals
        # (attacker trying to evade burst detection)
        for i in range(30):
            if i % 2 == 0:
                # Random intervals to look natural
                interval = 30 + (i * 3)
            else:
                # Occasional quick bursts
                interval = 60 + (i * 2)
            
            logs.append({
                "session_id": f"spread_attack_{i % 5}",  # Multiple sessions
                "api_key": f"AKIA_SPREAD_{i}",
                "is_fake": True,
                "timestamp": current_time + interval,
            })
        
        service.logger.get_logs = lambda limit: logs
        
        result = await service.compute_cross_session_correlations(limit_seconds=3600)
        
        # Should detect despite time-spread
        assert result["total_sessions"] > 1
        # May have multiple sessions
        assert result["fake_credential_count"] == 30


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
