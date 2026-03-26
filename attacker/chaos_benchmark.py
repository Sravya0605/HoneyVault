import random
import time
import os
from pathlib import Path
import requests

API_URL = "http://127.0.0.1:8000"


def _read_env_file_value(name: str) -> str | None:
    env_path = Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return None

    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        if key.strip() == name:
            return value.strip().strip('"').strip("'")
    return None


def _token(name: str) -> str | None:
    return os.getenv(name) or _read_env_file_value(name)


def create_vault(password: str, api_key: str) -> str:
    response = requests.post(
        f"{API_URL}/api/encrypt",
        json={"password": password, "aws_api_key": api_key},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()["vault_id"]


def simulate_mixed_traffic(vault_id: str, rounds: int = 40) -> None:
    fake_key = None
    valid_key = "AKIAREALKEY12345678"

    for i in range(rounds):
        action = random.choice(["decrypt_wrong", "decrypt_right", "sinkhole_bad", "sinkhole_real"])

        if action == "decrypt_wrong":
            response = requests.post(
                f"{API_URL}/api/decrypt",
                json={"password": f"wrong-{i}-password", "vault_id": vault_id},
                timeout=10,
            )
            if response.status_code == 200 and response.json().get("status") == "fake":
                fake_key = response.json()["data"]["aws_api_key"]

        elif action == "decrypt_right":
            requests.post(
                f"{API_URL}/api/decrypt",
                json={"password": "correct-password-xyz", "vault_id": vault_id},
                timeout=10,
            )

        elif action == "sinkhole_bad":
            requests.get(
                f"{API_URL}/api/cloud/instances",
                headers={"x-api-key": "bad"},
                timeout=10,
            )

        elif action == "sinkhole_real":
            requests.get(
                f"{API_URL}/api/cloud/instances",
                headers={"x-api-key": fake_key or valid_key},
                timeout=10,
            )


def pull_metrics() -> tuple[dict, str]:
    admin_token = _token("ADMIN_API_TOKEN")
    service_token = _token("SERVICE_API_TOKEN")

    summary = requests.get(
        f"{API_URL}/api/metrics/summary",
        headers={"x-api-token": admin_token} if admin_token else None,
        timeout=10,
    )
    if summary.status_code == 401:
        raise RuntimeError("Unauthorized summary metrics access. Set ADMIN_API_TOKEN.")
    summary.raise_for_status()

    exporter = requests.get(
        f"{API_URL}/api/metrics/prometheus",
        headers={"x-api-token": service_token} if service_token else None,
        timeout=10,
    )
    if exporter.status_code == 401:
        raise RuntimeError("Unauthorized prometheus metrics access. Set SERVICE_API_TOKEN.")
    exporter.raise_for_status()

    return summary.json(), exporter.text


def run_chaos_benchmark() -> None:
    print("[CHAOS] Starting mixed-traffic resilience benchmark")
    start = time.time()

    vault_id = create_vault("correct-password-xyz", "AKIAREALKEY12345678")
    simulate_mixed_traffic(vault_id, rounds=60)

    summary, exporter = pull_metrics()
    elapsed = time.time() - start

    slo = summary.get("slo", {})
    print(f"[CHAOS] Completed in {elapsed:.2f}s")
    print(f"[CHAOS] Observed availability: {slo.get('availability_observed')}")
    print(f"[CHAOS] Error budget remaining: {slo.get('error_budget_remaining_ratio')}")
    print(f"[CHAOS] Avg latency ms: {slo.get('avg_latency_ms')}")
    print(f"[CHAOS] Top session risks: {len(summary.get('top_session_risks', []))}")

    print("[CHAOS] Prometheus sample:")
    for line in exporter.splitlines()[:12]:
        print(line)


if __name__ == "__main__":
    run_chaos_benchmark()
