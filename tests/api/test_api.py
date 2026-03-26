import pytest

pytestmark = pytest.mark.asyncio

async def test_create_and_decrypt_vault_success(client):
    """
    Tests the full flow of creating a vault and then decrypting it with the correct password.
    """
    # Step 1: Create the vault
    encrypt_payload = {
        "password": "super-secret-password-123",
        "aws_api_key": "AKIAREALKEY12345678"
    }
    encrypt_response = await client.post("/api/encrypt", json=encrypt_payload)
    
    assert encrypt_response.status_code == 200
    
    encrypt_data = encrypt_response.json()
    assert "vault_id" in encrypt_data
    assert "vault" in encrypt_data
    
    vault_id = encrypt_data["vault_id"]
    
    # Step 2: Decrypt the vault with the correct password
    decrypt_payload = {
        "password": "super-secret-password-123",
        "vault_id": vault_id
    }
    decrypt_response = await client.post("/api/decrypt", json=decrypt_payload)
    
    assert decrypt_response.status_code == 200
    decrypt_data = decrypt_response.json()
    assert decrypt_data["status"] == "real"
    assert decrypt_data["data"]["aws_api_key"] == "AKIAREALKEY12345678"

async def test_decrypt_vault_with_wrong_password(client):
    """
    Tests that attempting to decrypt a vault with the wrong password returns a 'fake' status.
    """
    # Step 1: Create the vault
    encrypt_payload = {
        "password": "correct-password",
        "aws_api_key": "AKIAREALKEY12345678"
    }
    encrypt_response = await client.post("/api/encrypt", json=encrypt_payload)
    vault_id = encrypt_response.json()["vault_id"]
    
    # Step 2: Attempt to decrypt with the wrong password
    decrypt_payload = {
        "password": "wrong-password",
        "vault_id": vault_id
    }
    decrypt_response = await client.post("/api/decrypt", json=decrypt_payload)
    
    assert decrypt_response.status_code == 200
    decrypt_data = decrypt_response.json()
    assert decrypt_data["status"] == "fake"
    assert decrypt_data["data"]["aws_api_key"] != "AKIAREALKEY12345678"

async def test_decrypt_nonexistent_vault(client):
    """
    Tests that attempting to decrypt a vault that doesn't exist returns a 404 Not Found error.
    """
    decrypt_payload = {
        "password": "any-password",
        "vault_id": "60c72b2f9b1d8b001f8e4c3d"  # A valid but non-existent ObjectId
    }
    response = await client.post("/api/decrypt", json=decrypt_payload)
    
    assert response.status_code == 404
    assert response.json()["detail"] == "Vault not found"

async def test_root_and_health_endpoints(client):
    """
    Tests the root and health check endpoints.
    """
    root_response = await client.get("/")
    assert root_response.status_code == 200
    assert root_response.json()["message"] == "HoneyVault API is running"
    
    health_response = await client.get("/health")
    assert health_response.status_code == 200
    assert health_response.json()["status"] == "healthy"


async def test_sinkhole_allows_multiple_log_entries(client):
    """
    Regression test: sinkhole requests should not fail due to duplicate _id in logs.
    """
    headers = {"x-api-key": "AKIA1234567890ABCDEF"}

    first = await client.get("/api/cloud/instances", headers=headers)
    second = await client.get("/api/cloud/instances", headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
