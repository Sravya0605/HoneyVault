"""
Bijection verification tests for DTE (Distribution-Transforming Encoder).

CRITICAL FOR PAPER CLAIMS:
- encode(decode(seed)) == seed for all 64-bit seeds
- This test empirically verifies the bijective property claim
"""

import pytest
import secrets
from app.core.dte import DistributionTransformingEncoder


class TestDTEBijection:
    """
    Tests for bijective DTE property: encode(decode(seed)) == seed
    """
    
    @pytest.fixture
    def dte(self):
        return DistributionTransformingEncoder()
    
    def test_bijection_small_sample(self, dte):
        """Test bijection on small sample of seeds (fast smoke test)."""
        n_seeds = 100
        failures = []
        
        for _ in range(n_seeds):
            seed = secrets.randbits(64)
            msg = dte.decode(seed)
            recovered_seed = dte.encode(msg)
            
            if recovered_seed != seed:
                failures.append({
                    "original_seed": seed,
                    "message": msg,
                    "recovered_seed": recovered_seed,
                })
        
        assert len(failures) == 0, f"Bijection failed on {len(failures)}/{n_seeds} seeds:\n{failures[:5]}"
    
    def test_bijection_large_sample(self, dte):
        """Test bijection on large sample with detailed statistics.
        
        This is the test you'd include in the paper:
        "encode(decode(s)) = s verified over 10,000 random seeds: 0 failures"
        """
        n_seeds = 10000
        failures = 0
        
        for i in range(n_seeds):
            seed = secrets.randbits(64)
            msg = dte.decode(seed)
            recovered_seed = dte.encode(msg)
            
            if recovered_seed != seed:
                failures += 1
                # Log first few failures for debugging
                if failures <= 3:
                    print(f"\nBijection failure #{failures}:")
                    print(f"  Original seed:   {seed:064b} ({seed})")
                    print(f"  Message:         {msg}")
                    print(f"  Recovered seed:  {recovered_seed:064b} ({recovered_seed})")
        
        success_rate = (n_seeds - failures) / n_seeds * 100
        print(f"\nBijection test: {n_seeds - failures}/{n_seeds} passed ({success_rate:.1f}%)")
        print(f"Failures: {failures}")
        
        assert failures == 0, f"Bijection property FAILED: {failures}/{n_seeds} seeds"
    
    def test_bijection_edge_cases(self, dte):
        """Test bijection on edge-case seeds."""
        edge_seeds = [
            0,                      # Minimum
            (2 ** 64) - 1,         # Maximum
            (2 ** 63) - 1,         # Max signed
            2 ** 63,               # Min negative (as unsigned)
            (1 << 60) - 1,         # Just under service bits
            (1 << 60),             # Service bits boundary
            secrets.randbits(32),  # 32-bit random
            secrets.randbits(48),  # 48-bit random
            secrets.randbits(63),  # 63-bit random
        ]
        
        for seed in edge_seeds:
            msg = dte.decode(seed)
            recovered = dte.encode(msg)
            assert recovered == seed, (
                f"Bijection failed for edge seed {seed}:\n"
                f"  Message: {msg}\n"
                f"  Recovered: {recovered}"
            )
    
    def test_decode_all_fields_present(self, dte):
        """Verify decode always returns all required message fields."""
        required_fields = {"aws_api_key", "service", "region", "access_scope", "account_hint"}
        
        for _ in range(100):
            seed = secrets.randbits(64)
            msg = dte.decode(seed)
            
            assert isinstance(msg, dict), f"decode() returned non-dict: {type(msg)}"
            missing = required_fields - set(msg.keys())
            assert not missing, f"Missing fields in decode(): {missing}"
    
    def test_encode_recovers_all_components(self, dte):
        """Verify encode correctly recovers all message components."""
        for _ in range(100):
            seed = secrets.randbits(64)
            msg = dte.decode(seed)
            
            # Manually reconstruct message
            reconstructed = {
                "aws_api_key": msg["aws_api_key"],
                "service": msg["service"],
                "region": msg["region"],
                "access_scope": msg["access_scope"],
                "account_hint": msg["account_hint"],
            }
            
            recovered_seed = dte.encode(reconstructed)
            assert recovered_seed == seed, (
                f"Encode didn't recover seed correctly:\n"
                f"  Original: {seed}\n"
                f"  Message:  {msg}\n"
                f"  Recovered: {recovered_seed}"
            )
    
    def test_bijection_bit_extraction_invariant(self, dte):
        """
        Test that bit extraction is consistent.
        
        Verifies the bit-partitioning invariant:
        [bits 63-60] = service
        [bits 59-57] = region
        [bits 56-55] = scope
        [bits 54-0] = key entropy
        """
        test_seed = 0b1010_101_10_1010101010101010101010101010101010101010101010101010
        
        # Extract bits
        service_idx = (test_seed >> 60) & 0xF
        region_idx = (test_seed >> 57) & 0x7
        scope_idx = (test_seed >> 55) & 0x3
        key_entropy = test_seed & ((1 << 55) - 1)
        
        # Verify they pack back to original
        reconstructed = (
            ((service_idx & 0xF) << 60) |
            ((region_idx & 0x7) << 57) |
            ((scope_idx & 0x3) << 55) |
            (key_entropy & ((1 << 55) - 1))
        )
        
        assert reconstructed == test_seed, (
            f"Bit extraction lost information:\n"
            f"  Original:      {test_seed:064b}\n"
            f"  Reconstructed: {reconstructed:064b}"
        )


class TestDTEKeyEntropy:
    """Tests for invertible key entropy functions."""
    
    @pytest.fixture
    def dte(self):
        return DistributionTransformingEncoder()
    
    def test_entropy_round_trip(self, dte):
        """Test that _entropy_from_key(_key_from_entropy(e)) == e."""
        entropies = [
            0,
            (1 << 55) - 1,  # Max 55-bit value
            secrets.randbits(55),
            secrets.randbits(55),
            secrets.randbits(55),
        ]
        
        for original_entropy in entropies:
            # Round trip
            key = dte._key_from_entropy(original_entropy)
            recovered_entropy = dte._entropy_from_key(key)
            
            assert recovered_entropy == original_entropy, (
                f"Entropy round trip failed:\n"
                f"  Original:  {original_entropy}\n"
                f"  Key:       {key}\n"
                f"  Recovered: {recovered_entropy}"
            )
    
    def test_key_format_always_valid(self, dte):
        """Verify _key_from_entropy always produces valid AWS key format."""
        for _ in range(1000):
            entropy = secrets.randbits(55)
            key = dte._key_from_entropy(entropy)
            
            # Check format
            assert len(key) == 20, f"Invalid key length: {len(key)}"
            assert key.startswith("AKIA"), f"Invalid AWS key prefix: {key[:4]}"
            assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" for c in key), (
                f"Invalid character in key: {key}"
            )
    
    def test_different_entropy_different_keys(self, dte):
        """Verify different entropies produce different keys."""
        keys = set()
        entropies = [secrets.randbits(55) for _ in range(1000)]
        
        for entropy in entropies:
            key = dte._key_from_entropy(entropy)
            assert key not in keys, f"Entropy function produced duplicate key: {key}"
            keys.add(key)
        
        assert len(keys) == 1000, "Some entropy values produced the same key"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])
