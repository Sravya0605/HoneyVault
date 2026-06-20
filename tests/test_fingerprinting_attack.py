"""
Unit tests for message space fingerprinting attack.

Tests validate that the attack correctly:
1. Fingerprints finite message spaces
2. Achieves O(log m) query complexity
3. Calculates brute-force advantage accurately
"""

import pytest
import math
from security.fingerprinting_attack import (
    MessageSpaceFingerprint,
    DimensionType,
    FingerprintingResult
)


class TestFingerprintDimension:
    """Tests for individual dimension fingerprinting."""
    
    def test_fingerprint_service_dimension(self):
        """Test fingerprinting of service dimension."""
        services = ["s3", "ec2", "lambda", "iam"]
        regions = ["us-east-1"]
        scopes = ["read"]
        
        attacker = MessageSpaceFingerprint(services, regions, scopes)
        result = attacker.fingerprint_dimension(
            DimensionType.SERVICE, 
            services
        )
        
        assert result.dimension == DimensionType.SERVICE
        assert result.actual_size == len(services)
        assert result.accuracy >= 0.8  # At least 80% accurate
        assert result.success  # Should succeed
    
    def test_fingerprint_region_dimension(self):
        """Test fingerprinting of region dimension."""
        services = ["s3"]
        regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "ap-northeast-1"]
        scopes = ["read"]
        
        attacker = MessageSpaceFingerprint(services, regions, scopes)
        result = attacker.fingerprint_dimension(
            DimensionType.REGION,
            regions
        )
        
        assert result.dimension == DimensionType.REGION
        assert result.actual_size == len(regions)
        assert result.accuracy >= 0.8
        assert result.success
    
    def test_fingerprint_scope_dimension(self):
        """Test fingerprinting of scope dimension."""
        services = ["s3"]
        regions = ["us-east-1"]
        scopes = ["read", "write", "admin"]
        
        attacker = MessageSpaceFingerprint(services, regions, scopes)
        result = attacker.fingerprint_dimension(
            DimensionType.SCOPE,
            scopes
        )
        
        assert result.dimension == DimensionType.SCOPE
        assert result.actual_size == len(scopes)
        assert result.accuracy >= 0.8
        assert result.success


class TestFullAttack:
    """Tests for complete fingerprinting attack."""
    
    def test_full_attack_small_space(self):
        """Test complete attack on small message space (120 variants)."""
        services = ["s3", "ec2", "lambda", "iam", "rds", "dynamodb", "glue", "sagemaker"]
        regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "sa-east-1"]
        scopes = ["read", "write", "admin"]
        
        attacker = MessageSpaceFingerprint(services, regions, scopes)
        est_size, confidence, queries = attacker.run_full_attack()
        
        actual_size = len(services) * len(regions) * len(scopes)
        
        # Verify results
        assert est_size == actual_size, f"Estimation failed: got {est_size}, expected {actual_size}"
        assert confidence >= 0.7, f"Confidence too low: {confidence}"
        assert queries <= 50, f"Too many queries: {queries}"
        
        # Verify query complexity is reasonable
        theoretic_min = math.log2(actual_size)  # O(log m)
        assert queries <= theoretic_min * 5, f"Queries {queries} exceed O(log m)*5 = {theoretic_min*5}"
    
    def test_full_attack_medium_space(self):
        """Test complete attack on medium message space."""
        services = ["s3", "ec2", "lambda", "iam", "rds", "dynamodb", "glue", "sagemaker",
                   "redshift", "elasticache", "dax", "documentdb", "apprunner", "batch"]
        regions = ["us-east-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1",
                  "ap-northeast-1", "sa-east-1", "ca-central-1", "eu-west-2", "ap-south-1"]
        scopes = ["read", "write", "admin"]
        
        attacker = MessageSpaceFingerprint(services, regions, scopes)
        est_size, confidence, queries = attacker.run_full_attack()
        
        actual_size = len(services) * len(regions) * len(scopes)
        
        # Verify results  
        assert est_size > 0, "Estimation should be non-zero"
        assert queries <= 100, f"Too many queries: {queries}"
        
        # Theoretic complexity should be O(log actual_size)
        theoretic_min = math.log2(actual_size)
        assert queries <= theoretic_min * 5, f"Queries exceed O(log m)*5"


class TestVulnerabilityMetrics:
    """Tests for vulnerability metric calculations."""
    
    def test_attack_advantage_calculation(self):
        """Test brute-force advantage calculation."""
        services = ["s3", "ec2", "lambda", "iam"]
        regions = ["us-east-1", "us-west-2"]
        scopes = ["read", "write"]
        
        attacker = MessageSpaceFingerprint(services, regions, scopes)
        attacker.run_full_attack()
        
        advantage = attacker.calculate_attack_advantage(password_entropy=78)
        
        # Verify advantage is calculated
        assert advantage["speedup_factor"] > 1e10, "Speedup should be massive"
        assert advantage["speedup_log10"] > 10, "Speedup log10 should be > 10"
        assert advantage["targeted_search_space"] < 1e10, "Targeted space should be practical"
    
    def test_speedup_factor_comparison(self):
        """Test that speedup is significant vs. blind brute-force."""
        services = ["s3", "ec2", "lambda", "iam", "rds", "dynamodb", "glue", "sagemaker"]
        regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1", "sa-east-1"]
        scopes = ["read", "write", "admin"]
        
        actual_space_size = len(services) * len(regions) * len(scopes)  # 120
        
        # Blind search: 2^78
        blind_space = 2**78
        
        # Targeted search: 120 × 2^10
        targeted_space = actual_space_size * (2**10)
        
        # Speedup
        speedup = blind_space / targeted_space
        speedup_log10 = math.log10(speedup)
        
        # Should be massive (10^18+ orders of magnitude)
        assert speedup_log10 > 18, f"Speedup not significant: {speedup_log10}×10"


class TestProbeCredential:
    """Tests for credential probing oracle."""
    
    def test_valid_credential_probe(self):
        """Test probing a valid credential."""
        services = ["s3", "ec2"]
        regions = ["us-east-1"]
        scopes = ["read"]
        
        attacker = MessageSpaceFingerprint(services, regions, scopes)
        
        is_valid = attacker.probe_credential("s3", "us-east-1", "read")
        assert is_valid is True
    
    def test_invalid_credential_probe(self):
        """Test probing an invalid (out-of-space) credential."""
        services = ["s3", "ec2"]
        regions = ["us-east-1"]
        scopes = ["read"]
        
        attacker = MessageSpaceFingerprint(services, regions, scopes)
        
        is_valid = attacker.probe_credential("Glue", "us-east-1", "read")
        assert is_valid is False
    
    def test_queries_counted(self):
        """Test that queries are properly counted."""
        services = ["s3"]
        regions = ["us-east-1"]
        scopes = ["read"]
        
        attacker = MessageSpaceFingerprint(services, regions, scopes)
        
        # Initial count
        assert attacker.queries_used == 0
        
        # After probes
        attacker.probe_credential("s3", "us-east-1", "read")
        assert attacker.queries_used == 1
        
        attacker.probe_credential("Glue", "us-east-1", "read")
        assert attacker.queries_used == 2


class TestFingerprintingResult:
    """Tests for FingerprintingResult dataclass."""
    
    def test_result_accuracy_calculation(self):
        """Test accuracy metric calculation."""
        result = FingerprintingResult(
            dimension=DimensionType.SERVICE,
            estimated_size=8,
            actual_size=8,
            queries_used=10,
            confidence=0.95,
            values_enumerated=["s3", "ec2", "lambda"]
        )
        
        assert result.accuracy == 1.0, "Perfect accuracy for exact estimate"
        assert result.success is True, "Should succeed with 100% accuracy"
    
    def test_result_accuracy_with_error(self):
        """Test accuracy with estimation error."""
        result = FingerprintingResult(
            dimension=DimensionType.REGION,
            estimated_size=6,  # Estimated 6
            actual_size=5,     # Actual 5
            queries_used=10,
            confidence=0.85,
            values_enumerated=["us-east-1", "us-west-2"]
        )
        
        expected_accuracy = 1.0 - abs(6 - 5) / 5  # 1 - 0.2 = 0.8
        assert abs(result.accuracy -expected_accuracy) < 0.001
        assert result.success is True, "80% accuracy should succeed"


def test_theorem_1_validation():
    """
    Integration test: Validate Theorem 1 predictions vs. experimental results.
    
    Theorem 1 states: An adversary can fingerprint message space with
    O(log m) queries. This test confirms empirical validation.
    """
    
    # Test configurations
    test_cases = [
        {
            "name": "Small space (120 variants)",
            "services": 8,
            "regions": 5,
            "scopes": 3,
            "expected_queries_max": 30  # log_2(120) ≈ 6.9, so ~30 is reasonable
        },
        {
            "name": "Medium space (420 variants)",
            "services": 14,
            "regions": 10,
            "scopes": 3,
            "expected_queries_max": 50  # log_2(420) ≈ 8.7
        }
    ]
    
    for test_case in test_cases:
        services = [f"s{i}" for i in range(test_case["services"])]
        regions = [f"r{i}" for i in range(test_case["regions"])]
        scopes = [f"sc{i}" for i in range(test_case["scopes"])]
        
        attacker = MessageSpaceFingerprint(services, regions, scopes)
        est_size, confidence, queries = attacker.run_full_attack()
        
        actual_size = len(services) * len(regions) * len(scopes)
        
        # Verify fingerprinting succeeded
        assert est_size == actual_size, \
            f"{test_case['name']}: Estimation failed, got {est_size}, expected {actual_size}"
        
        # Verify query complexity is reasonable
        assert queries <= test_case["expected_queries_max"], \
            f"{test_case['name']}: Queries {queries} exceed max {test_case['expected_queries_max']}"
        
        # Verify high confidence
        assert confidence >= 0.7, \
            f"{test_case['name']}: Confidence {confidence} below threshold"
        
        print(f"✓ {test_case['name']}: Fingerprinting succeeded")
        print(f"  Queries: {queries}/{test_case['expected_queries_max']}")
        print(f"  Confidence: {confidence*100:.1f}%\n")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
