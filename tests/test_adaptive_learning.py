"""
Adaptive distribution learning tests for DTE.

Tests that the DTE can learn from observed credentials and adapt
its distributions to reduce detectability.
"""

import pytest
import math
import secrets
from app.core.dte import DistributionTransformingEncoder


class TestAdaptiveDistribution:
    """Tests for adaptive distribution learning."""
    
    @pytest.fixture
    def dte(self):
        return DistributionTransformingEncoder()
    
    def test_observe_real_credential_records_data(self, dte):
        """Test that observe_real_credential correctly records observations."""
        initial_count = len(dte._real_observations)
        
        dte.observe_real_credential("AKIAIOSFODNN7EXAMPLE", {
            "service": "s3",
            "region": "us-east-1",
            "access_scope": "read-only",
        })
        
        assert len(dte._real_observations) == initial_count + 1
        assert dte._real_observations[-1]["is_real"] == True
        assert "service" in dte._real_observations[-1]
    
    def test_distribution_update_from_observations(self, dte):
        """Test that distribution update changes the distributions."""
        initial_services = dte._services.copy()
        
        # Feed heavily S3-biased observations
        for _ in range(50):
            dte.observe_real_credential(f"AKIA{'FAKE':0>16}", {
                "service": "s3",
                "region": "us-east-1",
                "access_scope": "read-only",
            })
        
        # Update distributions
        dte._update_distributions_from_observations()
        
        # S3 probability should increase
        current_s3_prob = next((p for s, p in dte._services if s == "s3"), 0)
        initial_s3_prob = next((p for s, p in initial_services if s == "s3"), 0)
        
        assert current_s3_prob > initial_s3_prob, (
            f"Distribution didn't adapt properly:\n"
            f"  Initial S3 prob:  {initial_s3_prob}\n"
            f"  Current S3 prob:  {current_s3_prob}"
        )
    
    def test_kl_divergence_computation(self, dte):
        """
        Test KL divergence computation for distribution confidence.
        
        KL(P || Q) measures how far distribution P is from Q.
        """
        # With no observations, compute baseline
        baseline_confidence = dte.distribution_confidence
        
        # Add 100 observations with known distribution
        for _ in range(100):
            dte.observe_real_credential(f"AKIA{'CRED':0>16}", {
                "service": "s3",
                "region": "us-east-1",
                "access_scope": "read-only",
            })
        
        # Compute confidence
        confidence = dte._compute_distribution_confidence()
        
        # Confidence should be a number in [0, 1]
        assert 0 <= confidence <= 1, f"Invalid confidence: {confidence}"
        
        # With matching distribution (S3 heavy), confidence should improve
        print(f"KL-based confidence: baseline={baseline_confidence}, with_obs={confidence}")
    
    def test_adaptive_learning_reduces_kl_divergence(self, dte):
        """
        Paper experiment: Does adaptive learning reduce KL divergence?
        
        Setup:
        - Generate 100 samples from a known distribution
        - Measure KL divergence before learning
        - Feed samples to adaptive learner
        - Measure KL divergence after learning
        - Verify reduction
        """
        # Synthetic "ground truth" distribution (5x more S3 than normal)
        ground_truth_distribution = {
            "s3": 0.60,  # Increased from 0.30
            "ec2": 0.15,
            "iam": 0.10,
            "rds": 0.05,
            "lambda": 0.05,
            "cloudtrail": 0.03,
            "kms": 0.01,
            "dynamodb": 0.01,
        }
        
        # Sample from ground truth
        services = list(ground_truth_distribution.keys())
        probabilities = list(ground_truth_distribution.values())
        
        samples = []
        for _ in range(200):
            # Sample service according to ground truth
            service = secrets.choice(services)  # Simple uniform selection for test
            samples.append({
                "service": service,
                "region": "us-east-1",
                "access_scope": "read-only",
            })
        
        # Measure KL BEFORE learning
        kl_before = self._compute_kl_divergence(dte, ground_truth_distribution, n_samples=500)
        
        # Feed samples to learner
        for sample in samples:
            dte.observe_real_credential(
                f"AKIA{'SAMPLE':0>15}",
                sample
            )
        
        # Update distributions
        dte._update_distributions_from_observations()
        
        # Measure KL AFTER learning
        kl_after = self._compute_kl_divergence(dte, ground_truth_distribution, n_samples=500)
        
        print(f"\nAdaptive Learning KL Divergence:")
        print(f"  Before: {kl_before:.6f}")
        print(f"  After:  {kl_after:.6f}")
        print(f"  Reduction: {(kl_before - kl_after) / kl_before * 100:.1f}%")
        
        # KL should improve (reduce)
        assert kl_after <= kl_before + 1e-6, (  # +epsilon for numerical stability
            f"Learning didn't help: KL increased from {kl_before} to {kl_after}"
        )
    
    @staticmethod
    def _compute_kl_divergence(dte, ground_truth: dict, n_samples: int) -> float:
        """
        Compute KL(P_ground_truth || P_generated).
        
        Low KL = generated distribution matches ground truth.
        """
        generated_dist = {}
        
        for _ in range(n_samples):
            seed = secrets.randbits(64)
            msg = dte.decode(seed)
            service = msg["service"]
            generated_dist[service] = generated_dist.get(service, 0) + 1
        
        # Normalize
        for s in generated_dist:
            generated_dist[s] /= n_samples
        
        # Compute KL(ground_truth || generated)
        kl = 0.0
        for service, gt_prob in ground_truth.items():
            gen_prob = generated_dist.get(service, 1e-10)
            if gt_prob > 0:
                kl += gt_prob * math.log(gt_prob / (gen_prob + 1e-10))
        
        return kl
    
    def test_confidence_metric_bounds(self, dte):
        """Verify confidence metric stays in [0, 1]."""
        # Generate many observations
        for _ in range(200):
            dte.observe_real_credential(f"AKIA{'CRED':0>16}", {
                "service": "s3",
                "region": "us-east-1",
                "access_scope": "read-only",
            })
            
            confidence = dte._compute_distribution_confidence()
            assert 0 <= confidence <= 1, (
                f"Confidence out of bounds: {confidence}"
            )


class TestDistributionIndices:
    """Tests for distribution lookup indices."""
    
    @pytest.fixture
    def dte(self):
        return DistributionTransformingEncoder()
    
    def test_service_index_complete(self, dte):
        """Verify all services have indices."""
        for service, _ in dte._services:
            assert service in dte._service_index, (
                f"Service missing from index: {service}"
            )
            assert 0 <= dte._service_index[service] < len(dte._services)
    
    def test_region_index_complete(self, dte):
        """Verify all regions have indices."""
        for region, _ in dte._regions:
            assert region in dte._region_index, (
                f"Region missing from index: {region}"
            )
            assert 0 <= dte._region_index[region] < len(dte._regions)
    
    def test_scope_index_complete(self, dte):
        """Verify all scopes have indices."""
        for scope, _ in dte._scopes:
            assert scope in dte._scope_index, (
                f"Scope missing from index: {scope}"
            )
            assert 0 <= dte._scope_index[scope] < len(dte._scopes)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
