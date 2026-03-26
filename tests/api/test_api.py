import pytest
from app.core.config import settings

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
    Tests that unknown vault IDs return deception-safe fake output (no existence oracle).
    """
    decrypt_payload = {
        "password": "any-password",
        "vault_id": "60c72b2f9b1d8b001f8e4c3d"  # A valid but non-existent ObjectId
    }
    response = await client.post("/api/decrypt", json=decrypt_payload)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "fake"
    assert "aws_api_key" in body["data"]

async def test_root_and_health_endpoints(client):
    """
    Tests the root and health check endpoints.
    """
    root_response = await client.get("/")
    assert root_response.status_code == 200
    assert root_response.json()["message"] == "HoneyVault API is running"
    
    health_response = await client.get("/health")
    assert health_response.status_code == 200
    assert health_response.json()["status"] in {"healthy", "degraded"}

    ready_response = await client.get("/ready")
    assert ready_response.status_code == 200
    assert ready_response.json()["status"] == "ready"


async def test_sinkhole_allows_multiple_log_entries(client):
    """
    Regression test: sinkhole requests should not fail due to duplicate _id in logs.
    """
    headers = {"x-api-key": "AKIA1234567890ABCDEF"}

    first = await client.get("/api/cloud/instances", headers=headers)
    second = await client.get("/api/cloud/instances", headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200


async def test_decrypt_prefers_vault_id_when_both_sources_provided(client):
    encrypt_payload = {
        "password": "real-password-123",
        "aws_api_key": "AKIAREALKEY12345678",
    }
    encrypt_response = await client.post("/api/encrypt", json=encrypt_payload)
    vault_id = encrypt_response.json()["vault_id"]

    payload = {
        "password": "real-password-123",
        "vault_id": vault_id,
        "vault": {"ciphertext": "x", "salt": "y", "fake_keys": []},
    }
    response = await client.post("/api/decrypt", json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "real"


async def test_sinkhole_invalid_key_returns_401(client):
    response = await client.get(
        "/api/cloud/instances",
        headers={"x-api-key": "bad"},
    )
    assert response.status_code == 401


async def test_metrics_summary_endpoint_returns_expected_shape(client, db):
    headers = {"x-api-key": "AKIA1234567890ABCDEF"}
    await client.get("/api/cloud/instances", headers=headers)

    response = await client.get(
        "/api/metrics/summary",
        headers={"x-admin-token": settings.ADMIN_API_TOKEN},
    )
    assert response.status_code == 200

    data = response.json()
    assert "indistinguishability" in data
    assert "detection_latency_seconds" in data
    assert "average_dwell_time_seconds" in data
    assert "unique_sessions" in data
    assert "unique_source_ips" in data
    assert "decoy_engagement_ratio" in data
    assert "top_session_risks" in data
    assert "slo" in data
    assert "availability_target" in data["slo"]
    assert "availability_observed" in data["slo"]

    one_log = await db["logs"].find_one({})
    assert one_log is not None
    assert "api_key_masked" in one_log
    assert "api_key_hash" in one_log


async def test_metrics_summary_requires_admin_token(client):
    response = await client.get("/api/metrics/summary")
    assert response.status_code == 401


async def test_metrics_integrity_endpoint(client):
    response = await client.get(
        "/api/metrics/integrity",
        headers={"x-admin-token": settings.ADMIN_API_TOKEN},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "status" in payload
    assert "broken_links" in payload


async def test_metrics_prometheus_endpoint(client):
    response = await client.get(
        "/api/metrics/prometheus",
        headers={"x-admin-token": settings.ADMIN_API_TOKEN},
    )
    assert response.status_code == 200
    assert "honeyvault_total_events" in response.text


async def test_metrics_prometheus_allows_service_token(client):
    response = await client.get(
        "/api/metrics/prometheus",
        headers={"x-api-token": settings.SERVICE_API_TOKEN},
    )
    assert response.status_code == 200
    assert "honeyvault_slo_availability_observed" in response.text


async def test_metrics_slo_requires_admin(client):
    denied = await client.get(
        "/api/metrics/slo",
        headers={"x-api-token": settings.SERVICE_API_TOKEN},
    )
    assert denied.status_code == 401

    allowed = await client.get(
        "/api/metrics/slo",
        headers={"x-api-token": settings.ADMIN_API_TOKEN},
    )
    assert allowed.status_code == 200
    assert "error_budget_remaining_ratio" in allowed.json()


async def test_sinkhole_lure_level_progression_for_fake_key(client):
    encrypt_payload = {
        "password": "real-password-123",
        "aws_api_key": "AKIAREALKEY12345678",
    }
    encrypt_response = await client.post("/api/encrypt", json=encrypt_payload)
    vault_id = encrypt_response.json()["vault_id"]

    decrypt_payload = {
        "password": "wrong-password-456",
        "vault_id": vault_id,
    }
    decrypt_response = await client.post("/api/decrypt", json=decrypt_payload)
    fake_key = decrypt_response.json()["data"]["aws_api_key"]

    headers = {"x-api-key": fake_key}
    first = await client.get("/api/cloud/instances", headers=headers)
    second = await client.get("/api/storage/buckets", headers=headers)
    third = await client.post("/api/cloud/start-instance", headers=headers)

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 200

    assert first.json().get("lure_level") == 1
    assert second.json().get("lure_level") in (1, 2)
    assert third.json().get("lure_level") >= 2
