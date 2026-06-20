import pytest
from app.core.security import HoneyEncryption

@pytest.fixture
def he_instance():
    """Provides a HoneyEncryption instance for tests."""
    return HoneyEncryption()

def test_encrypt_creates_valid_vault(he_instance):
    """
    Tests that the encrypt method produces a dictionary with the correct structure.
    """
    original_data = {"aws_api_key": "AKIAIOSFODNN7EXAMPLE"}
    password = "my-secure-password"
    
    vault = he_instance.encrypt(original_data, password)
    
    assert "ciphertext" in vault
    assert "salt" in vault
    assert "nonce" in vault
    assert "tag" in vault
    assert "metadata" in vault

def test_decrypt_with_correct_password(he_instance):
    """
    Tests that decrypting a vault with the correct password returns the
    original data.
    """
    original_data = {"aws_api_key": "AKIAIOSFODNN7EXAMPLE", "user": "test"}
    password = "my-secure-password"
    
    vault = he_instance.encrypt(original_data, password)
    decryption_result = he_instance.decrypt(vault, password)
    
    assert decryption_result["status"] == "decrypted"
    assert decryption_result["data"]["aws_api_key"] == original_data["aws_api_key"]
    assert "service" in decryption_result["data"]
    assert decryption_result["data"]["service"] == "s3"
    assert decryption_result["data"]["region"] == "us-east-1"

def test_decrypt_with_incorrect_password(he_instance):
    """
    Tests that decrypting a vault with an incorrect password returns
    a plausible fake key.
    """
    original_data = {"aws_api_key": "AKIAIOSFODNN7EXAMPLE"}
    correct_password = "my-secure-password"
    incorrect_password = "wrong-password"
    
    vault = he_instance.encrypt(original_data, correct_password)
    decryption_result = he_instance.decrypt(vault, incorrect_password)
    fake_key = decryption_result["data"]["aws_api_key"]
    
    assert decryption_result["status"] == "fake"
    assert fake_key != original_data["aws_api_key"]
    assert fake_key.startswith("AKIA")
    assert len(fake_key) == 20


def test_decrypt_with_different_wrong_passwords_produce_distinct_fakes(he_instance):
    """
    Tests that different wrong passwords produce different plausible fake keys.
    """
    original_data = {"aws_api_key": "AKIAIOSFODNN7EXAMPLE"}
    correct_password = "my-secure-password"
    wrong_passwords = ["wrong-password-1", "wrong-password-2", "wrong-password-3"]

    vault = he_instance.encrypt(original_data, correct_password)
    fake_keys = []

    for pw in wrong_passwords:
        result = he_instance.decrypt(vault, pw)
        assert result["status"] == "fake"
        assert "aws_api_key" in result["data"]
        fake_keys.append(result["data"]["aws_api_key"])

    assert len(set(fake_keys)) == len(wrong_passwords), "Different wrong passwords should produce distinct fake keys"
    assert all(len(key) == 20 and key.startswith("AKIA") for key in fake_keys)


def test_decryption_fails_with_missing_salt(he_instance):
    """
    Tests that decryption returns a 'fake' status if the salt is missing.
    """
    original_data = {"aws_api_key": "AKIAIOSFODNN7EXAMPLE"}
    password = "my-secure-password"
    
    vault = he_instance.encrypt(original_data, password)
    
    # Tamper with the vault by removing the salt
    del vault["salt"]
    
    decryption_result = he_instance.decrypt(vault, password)
    
    assert decryption_result["status"] == "fake"

def test_decryption_fails_with_missing_ciphertext(he_instance):
    """
    Tests that decryption returns a 'fake' status if the ciphertext is missing.
    """
    original_data = {"aws_api_key": "AKIAIOSFODNN7EXAMPLE"}
    password = "my-secure-password"
    
    vault = he_instance.encrypt(original_data, password)
    
    # Tamper with the vault by removing the ciphertext
    del vault["ciphertext"]
    
    decryption_result = he_instance.decrypt(vault, password)
    
    assert decryption_result["status"] == "fake"
