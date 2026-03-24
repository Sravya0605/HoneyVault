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
    original_data = {"aws_api_key": "AKIAREALKEY12345678"}
    password = "my-secure-password"
    
    vault = he_instance.encrypt(original_data, password)
    
    assert "ciphertext" in vault
    assert "salt" in vault
    assert "fake_keys" in vault
    assert "fake_secrets" in vault
    assert isinstance(vault["fake_keys"], list)
    assert len(vault["fake_keys"]) > 0
    assert "metadata" in vault

def test_decrypt_with_correct_password(he_instance):
    """
    Tests that decrypting a vault with the correct password returns the
    original data and a 'real' status.
    """
    original_data = {"aws_api_key": "AKIAREALKEY12345678", "user": "test"}
    password = "my-secure-password"
    
    vault = he_instance.encrypt(original_data, password)
    decryption_result = he_instance.decrypt(vault, password)
    
    assert decryption_result["status"] == "real"
    assert decryption_result["data"] == original_data

def test_decrypt_with_incorrect_password(he_instance):
    """
    Tests that decrypting a vault with an incorrect password returns
    a 'fake' status and fake data.
    """
    original_data = {"aws_api_key": "AKIAREALKEY12345678"}
    correct_password = "my-secure-password"
    incorrect_password = "wrong-password"
    
    vault = he_instance.encrypt(original_data, correct_password)
    decryption_result = he_instance.decrypt(vault, incorrect_password)
    
    assert decryption_result["status"] == "fake"
    assert "aws_api_key" in decryption_result["data"]
    # The returned key should be one of the fake keys
    assert decryption_result["data"]["aws_api_key"] in vault["fake_keys"]

def test_decryption_fails_with_missing_salt(he_instance):
    """
    Tests that decryption returns a 'fake' status if the salt is missing.
    """
    original_data = {"aws_api_key": "AKIAREALKEY12345678"}
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
    original_data = {"aws_api_key": "AKIAREALKEY12345678"}
    password = "my-secure-password"
    
    vault = he_instance.encrypt(original_data, password)
    
    # Tamper with the vault by removing the ciphertext
    del vault["ciphertext"]
    
    decryption_result = he_instance.decrypt(vault, password)
    
    assert decryption_result["status"] == "fake"
