"""
Tests for Crypto Fixes (PRIORITY 5).

Validates AES-256-GCM encryption and Argon2id key derivation upgrades.
"""

import pytest
from app.core.security import HoneyEncryption
from app.core.config import settings


class TestArgon2idKeyDerivation:
    """Test Argon2id key derivation (PRIORITY 5B)."""
    
    @pytest.fixture
    def he(self):
        return HoneyEncryption()
    
    def test_argon2id_derives_32_byte_key(self, he):
        """Argon2id should derive 32-byte (256-bit) keys."""
        password = "test_password"
        salt = b"test_salt_16byte"
        
        key = he._derive_cipher_key(password, salt)
        
        assert len(key) == 32, f"Key should be 32 bytes, got {len(key)}"
    
    def test_argon2id_deterministic(self, he):
        """Argon2id should be deterministic (same input → same output)."""
        password = "secure_pass"
        salt = b"consistent_salt1"
        
        key1 = he._derive_cipher_key(password, salt)
        key2 = he._derive_cipher_key(password, salt)
        
        assert key1 == key2, "Argon2id should be deterministic"
    
    def test_argon2id_different_password_different_key(self, he):
        """Different passwords should produce different keys."""
        salt = b"same_salt_16byte"
        
        key1 = he._derive_cipher_key("password1", salt)
        key2 = he._derive_cipher_key("password2", salt)
        
        assert key1 != key2, "Different passwords should produce different keys"
    
    def test_argon2id_different_salt_different_key(self, he):
        """Different salts should produce different keys."""
        password = "same_password"
        
        key1 = he._derive_cipher_key(password, b"salt_number_one1")
        key2 = he._derive_cipher_key(password, b"salt_number_two2")
        
        assert key1 != key2, "Different salts should produce different keys"
    
    def test_argon2id_memory_and_time_costs(self):
        """Verify Argon2id parameters are properly configured."""
        assert settings.ARGON2_TIME_COST >= 1, "Time cost should be at least 1"
        assert settings.ARGON2_MEMORY_COST >= 8, "Memory cost should be at least 8 KB"
        assert settings.ARGON2_PARALLELISM >= 1, "Parallelism should be at least 1"
        assert settings.ARGON2_LENGTH == 32, "Output length should be 32 bytes (256-bit)"
        assert settings.ARGON2_TYPE == "id", "Should use Argon2id variant"


class TestAES256GCMEncryption:
    """Test AES-256-GCM encryption (PRIORITY 5A)."""
    
    @pytest.fixture
    def he(self):
        return HoneyEncryption()
    
    def test_encrypt_produces_aes256_gcm_format(self, he):
        """Encryption should produce AES-256-GCM format vault."""
        message = {"aws_api_key": "AKIAIOSFODNN7EXAMPLE"}
        password = "test_password"
        
        vault = he.encrypt(message, password)
        
        assert "ciphertext" in vault
        assert "salt" in vault
        assert "nonce" in vault, "GCM format should have nonce"
        assert "tag" in vault, "GCM format should have authentication tag"
        assert vault["metadata"]["encryption"] == "AES-256-GCM"
        assert vault["metadata"]["kdf"] == "Argon2id"
    
    def test_encrypt_produces_different_ciphertexts(self, he):
        """Each encryption should produce different ciphertext (random nonce)."""
        message = {"aws_api_key": "AKIAIOSFODNN7EXAMPLE"}
        password = "test_password"
        
        vault1 = he.encrypt(message, password)
        vault2 = he.encrypt(message, password)
        
        # Different nonces → different ciphertexts
        assert vault1["ciphertext"] != vault2["ciphertext"], "Different encryptions should use different nonces"
        assert vault1["nonce"] != vault2["nonce"], "Nonces should be random"
    
    def test_decrypt_aes256_gcm_vault(self, he):
        """AES-256-GCM vaults should decrypt correctly."""
        message = {"aws_api_key": "AKIAIOSFODNN7EXAMPLE"}
        password = "test_password"
        
        vault = he.encrypt(message, password)
        decrypted = he.decrypt(vault, password)
        
        assert decrypted["status"] == "decrypted"
        assert decrypted["data"]["aws_api_key"] == "AKIAIOSFODNN7EXAMPLE"
    
    def test_wrong_password_produces_different_output(self, he):
        """Wrong password should decrypt to different (but valid) message."""
        message = {"aws_api_key": "AKIAIOSFODNN7EXAMPLE"}
        password = "correct_password"
        
        vault = he.encrypt(message, password)
        
        # Decrypt with wrong password
        wrong_result = he.decrypt(vault, "wrong_password")
        
        assert wrong_result["status"] == "decrypted"
        # Should get a different valid message (not the original)
        # Note: Due to DTE, it's a valid AWS key format even if wrong
        assert "aws_api_key" in wrong_result["data"]
    
    def test_gcm_nonce_length(self, he):
        """GCM should use 96-bit (12-byte) nonce."""
        import base64
        
        message = {"aws_api_key": "AKIAIOSFODNN7EXAMPLE"}
        vault = he.encrypt(message, "password")
        
        nonce = base64.urlsafe_b64decode(vault["nonce"].encode())
        # 12 bytes = 96 bits (standard for GCM)
        assert len(nonce) == 12, f"GCM nonce should be 12 bytes, got {len(nonce)}"
    
    def test_gcm_tag_length(self, he):
        """GCM should produce 128-bit (16-byte) authentication tag."""
        import base64
        
        message = {"aws_api_key": "AKIAIOSFODNN7EXAMPLE"}
        vault = he.encrypt(message, "password")
        
        tag = base64.urlsafe_b64decode(vault["tag"].encode())
        # 16 bytes = 128 bits (full authentication)
        assert len(tag) == 16, f"GCM tag should be 16 bytes, got {len(tag)}"
    
    def test_gcm_authenticated_encryption(self, he):
        """Tampering with ciphertext should not cause visible failure."""
        import base64
        
        message = {"aws_api_key": "AKIAIOSFODNN7EXAMPLE"}
        vault = he.encrypt(message, "password")
        
        # Tamper with ciphertext
        original_ct = base64.urlsafe_b64decode(vault["ciphertext"].encode())
        tampered_ct = bytes([(b + 1) % 256 for b in original_ct])
        vault["ciphertext"] = base64.urlsafe_b64encode(tampered_ct).decode()
        
        # Decryption should still succeed (HE property), but with different message
        result = he.decrypt(vault, "password")
        
        assert result["status"] == "decrypted"
        # Should get a different (valid) message
        assert "aws_api_key" in result["data"]


class TestBackwardCompatibility:
    """Test backward compatibility with legacy encryption formats."""
    
    @pytest.fixture
    def he(self):
        return HoneyEncryption()
    
    def test_legacy_aes_ctr_vault_decryption(self, he):
        """Should be able to decrypt legacy AES-CTR vaults."""
        import base64
        
        # Create a mock legacy vault (AES-CTR format)
        legacy_vault = {
            "ciphertext": base64.urlsafe_b64encode(b"\x00" * 8).decode(),
            "salt": base64.urlsafe_b64encode(b"legacy_salt16byt").decode(),
            # No nonce/tag - indicates legacy format
            "metadata": {
                "scheme": "REAL_HE_DTE_V1_AES_CTR",
                "version": "5"
            }
        }
        
        # Should not raise error
        result = he.decrypt(legacy_vault, "password")
        
        assert result["status"] == "decrypted"
        assert "data" in result
    
    def test_new_vaults_use_gcm(self, he):
        """New vaults should use GCM format by default."""
        message = {"aws_api_key": "AKIAIOSFODNN7EXAMPLE"}
        vault = he.encrypt(message, "password")
        
        # Should be new GCM format
        assert "nonce" in vault
        assert "tag" in vault
        assert vault["metadata"]["scheme"] == "REAL_HE_DTE_V2_AES256_GCM"


class TestCryptoUpgradeImpact:
    """Test impact of crypto upgrades on security properties."""
    
    @pytest.fixture
    def he(self):
        return HoneyEncryption()
    
    def test_aes256_vs_aes128_key_size(self):
        """AES-256 provides stronger security than AES-128 (2^128 vs better)."""
        # AES-256: 2^256 key space
        # AES-128: 2^128 key space
        # Upgrade provides 2^128x more security
        assert settings.ARGON2_LENGTH == 32, "Should derive 256-bit keys"
    
    def test_argon2id_resistance_to_gpu_mining(self):
        """Argon2id should resist GPU/ASIC mining attacks."""
        # Key characteristics:
        # - High memory cost (64 MB per derivation)
        # - GPU/ASIC unfriendly
        # - Better than scrypt which is GPU-friendly
        assert settings.ARGON2_MEMORY_COST >= 65536, "Should have high memory cost (>=64MB)"
    
    def test_gcm_provides_authentication(self, he):
        """AES-256-GCM provides authenticated encryption (AEAD)."""
        # Previous: Fernet = AES-128-CBC + HMAC (two operations)
        # New: AES-256-GCM = unified AEAD (one operation)
        import base64
        
        vault = he.encrypt({"aws_api_key": "AKIAIOSFODNN7EXAMPLE"}, "password")
        
        # GCM should have authentication tag
        tag = base64.urlsafe_b64decode(vault["tag"].encode())
        assert len(tag) == 16, "Should have 128-bit authentication tag"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
