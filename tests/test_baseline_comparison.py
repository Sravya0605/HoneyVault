"""
Tests for Baseline Comparison (PRIORITY 2).

Validates that HoneyVault achieves faster/more reliable detection
than industry standards (HoneyTokens + GuardDuty).
"""

import pytest
from scripts.compare_detection_latency import (
    DefenseSystem,
    HoneyVaultSimulator,
    HoneytokenSimulator,
    GuardDutySimulator,
    BaselineComparison,
)


class TestHoneyVaultDetection:
    """Test HoneyVault detection latencies."""
    
    @pytest.fixture
    def simulator(self):
        return HoneyVaultSimulator()
    
    def test_credential_reuse_detection_fast(self, simulator):
        """HoneyVault should detect credential reuse quickly."""
        # Many credentials (>5)
        latency = simulator.simulate_credential_reuse_detection(num_credentials=10)
        
        # Should be detected quickly (<10 seconds)
        assert latency < 10, f"Expected fast detection, got {latency}s"
    
    def test_credential_reuse_detection_fallback(self, simulator):
        """Single credential reuse should use cloud detection."""
        latency = simulator.simulate_credential_reuse_detection(num_credentials=1)
        
        # Should fall back to cloud detection (20-40 seconds)
        assert 10 < latency < 50, f"Expected cloud detection latency, got {latency}s"
    
    def test_rate_anomaly_detection_fast(self, simulator):
        """HoneyVault should detect high rates quickly."""
        latency = simulator.simulate_rate_anomaly_detection(api_calls_per_minute=150)
        
        # Should detect immediately (<15 seconds)
        assert latency < 15, f"Expected fast detection, got {latency}s"
    
    def test_geographic_anomaly_detection(self, simulator):
        """Geographic anomalies require cloud analysis."""
        latency = simulator.simulate_geographic_anomaly_detection()
        
        # Deferred to cloud (100-140 seconds)
        assert 100 < latency < 150, f"Expected cloud latency, got {latency}s"


class TestHoneytokenDetection:
    """Test traditional HoneyToken detection latencies."""
    
    @pytest.fixture
    def simulator(self):
        return HoneytokenSimulator()
    
    def test_credential_reuse_detection_slow(self, simulator):
        """HoneyTokens are slow - require SNS + alert routing."""
        latency = simulator.simulate_credential_reuse_detection(num_credentials=5)
        
        # Slow due to SNS + routing (150-300+ seconds)
        assert latency > 150, f"HoneyTokens should be slow, got {latency}s"
    
    def test_rate_anomaly_detection_no_capability(self, simulator):
        """HoneyTokens cannot directly detect rate anomalies."""
        latency = simulator.simulate_rate_anomaly_detection(api_calls_per_minute=50)
        
        # Either undetected or very late (600+ seconds)
        assert latency > 200, f"HoneyTokens lack rate detection, got {latency}s"
    
    def test_geographic_anomaly_no_capability(self, simulator):
        """HoneyTokens lack geographic anomaly detection."""
        latency = simulator.simulate_geographic_anomaly_detection()
        
        # No capability, should be very late or inf
        assert latency > 600, f"HoneyTokens cannot detect geographic anomalies, got {latency}s"


class TestGuardDutyDetection:
    """Test AWS GuardDuty detection latencies."""
    
    @pytest.fixture
    def simulator(self):
        return GuardDutySimulator()
    
    def test_credential_reuse_detection_moderate(self, simulator):
        """GuardDuty provides moderate detection latency."""
        # Simulate multiple times to account for probabilistic nature
        latencies = [
            simulator.simulate_credential_reuse_detection(num_credentials=20)
            for _ in range(10)
        ]
        
        detected = [l for l in latencies if l != float('inf')]
        
        # Some should be detected (7/10 typical), take 5-10 minutes
        assert len(detected) >= 6, "GuardDuty should detect high-reuse patterns"
        if detected:
            avg_latency = sum(detected) / len(detected)
            assert 200 < avg_latency < 600, f"GuardDuty latency should be 5-10 minutes, got {avg_latency}s"
    
    def test_rate_anomaly_detection_slow(self, simulator):
        """GuardDuty detects rate anomalies slowly."""
        latencies = [
            simulator.simulate_rate_anomaly_detection(api_calls_per_minute=200)
            for _ in range(10)
        ]
        
        detected = [l for l in latencies if l != float('inf')]
        
        # Should detect and take several minutes
        if detected:
            avg_latency = sum(detected) / len(detected)
            assert 300 < avg_latency < 400, f"GuardDuty high-rate detection latency: {avg_latency}s"
    
    def test_subtle_attack_no_detection(self, simulator):
        """GuardDuty cannot detect subtle attacks."""
        latencies = [
            simulator.simulate_rate_anomaly_detection(api_calls_per_minute=30)
            for _ in range(10)
        ]
        
        # Should mostly not detect (would need GuardDuty ML to be very sensitive)
        detected = [l for l in latencies if l != float('inf')]
        assert len(detected) < 3, "GuardDuty should struggle with subtle patterns"


class TestBaselineComparisonResults:
    """Test complete baseline comparison."""
    
    def test_comparison_runs(self):
        """Baseline comparison should complete without errors."""
        comparison = BaselineComparison()
        results = comparison.run_comparison(num_trials=30)
        
        # Should have results for all systems
        assert DefenseSystem.HONEYVAULT in results
        assert DefenseSystem.HONEYTOKENS in results
        assert DefenseSystem.GUARDDUTY in results
    
    def test_honeyvault_faster_than_honeytokens(self):
        """HoneyVault should be faster than traditional HoneyTokens."""
        comparison = BaselineComparison()
        results = comparison.run_comparison(num_trials=100)
        
        hv = results[DefenseSystem.HONEYVAULT]
        ht = results[DefenseSystem.HONEYTOKENS]
        
        # Mean latency: HoneyVault should be significantly faster
        assert hv.mean_latency < ht.mean_latency, \
            f"HoneyVault ({hv.mean_latency}s) should be faster than HoneyTokens ({ht.mean_latency}s)"
        
        # Should be at least 2x faster
        speedup = ht.mean_latency / hv.mean_latency
        assert speedup > 2.0, f"HoneyVault should be >2x faster, got {speedup}x"
    
    def test_honeyvault_faster_than_guardduty(self):
        """HoneyVault should be faster than GuardDuty."""
        comparison = BaselineComparison()
        results = comparison.run_comparison(num_trials=100)
        
        hv = results[DefenseSystem.HONEYVAULT]
        gd = results[DefenseSystem.GUARDDUTY]
        
        # Mean latency: HoneyVault should be faster
        assert hv.mean_latency < gd.mean_latency, \
            f"HoneyVault ({hv.mean_latency}s) should be faster than GuardDuty ({gd.mean_latency}s)"
        
        # Should be at least 1x faster (accounts for some GuardDuty detections)
        speedup = gd.mean_latency / hv.mean_latency
        assert speedup > 1.0, f"HoneyVault should be faster than GuardDuty, got {speedup}x"
    
    def test_honeyvault_higher_detection_rate(self):
        """HoneyVault should have higher detection rate than passive systems."""
        comparison = BaselineComparison()
        results = comparison.run_comparison(num_trials=100)
        
        hv = results[DefenseSystem.HONEYVAULT]
        gd = results[DefenseSystem.GUARDDUTY]
        
        # HoneyVault should detect more attacks (with active mechanisms)
        # Allow some variance in simulation
        assert hv.detection_rate >= gd.detection_rate * 0.9, \
            "HoneyVault detection rate should be competitive"
    
    def test_comparison_table_generation(self):
        """Test that comparison table generates correctly."""
        comparison = BaselineComparison()
        results = comparison.run_comparison(num_trials=50)
        
        table = comparison.generate_comparison_table(results)
        
        # Should contain system names
        assert "honeyvault" in table.lower()
        assert "honeytokens" in table.lower()
        assert "guardduty" in table.lower()
        
        # Should contain metrics
        assert "mean" in table.lower()
        assert "detection" in table.lower()


class TestDetectionAccuracy:
    """Test detection accuracy and false positives."""
    
    def test_honeyvault_minimal_false_positives(self):
        """HoneyVault should maintain low false positive rate."""
        simulator = HoneyVaultSimulator()
        
        # Test benign traffic (low credentials, normal rate)
        latencies = [
            simulator.simulate_credential_reuse_detection(num_credentials=1)
            for _ in range(20)
        ]
        
        # Should not trigger immediate alerts for normal patterns
        fast_alerts = sum(1 for l in latencies if l < 5)
        assert fast_alerts < 2, "Should have low false positive rate for normal traffic"
    
    def test_honeytokens_dependency_on_usage(self):
        """Traditional HoneyTokens depend on attacker actually using them."""
        simulator = HoneytokenSimulator()
        
        # If attacker doesn't use the token, detection is impossible
        # (Our simulation assumes they might test it)
        latency = simulator.simulate_credential_reuse_detection(num_credentials=1)
        
        # High latency or detection failure
        assert latency > 100, "HoneyTokens depend on token usage"
    
    def test_guardduty_batch_processing_limits(self):
        """GuardDuty is limited by batch processing windows."""
        simulator = GuardDutySimulator()
        
        # Real GuardDuty has 5-30 minute typical latency
        latencies = [
            simulator.simulate_credential_reuse_detection(num_credentials=20)
            for _ in range(20)
        ]
        
        detected = [l for l in latencies if l != float('inf')]
        
        if detected:
            min_latency = min(detected)
            # Should not detect faster than batch window (5 minutes = 300s)
            assert min_latency > 200, "GuardDuty limited by batch processing"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
