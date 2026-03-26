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


def _admin_token() -> str | None:
    return os.getenv("ADMIN_API_TOKEN") or _read_env_file_value("ADMIN_API_TOKEN")


def create_vault(password: str, key: str) -> str:
    res = requests.post(
        f"{API_URL}/api/encrypt",
        json={"password": password, "aws_api_key": key},
        timeout=15,
    )
    res.raise_for_status()
    return res.json()["vault_id"]


def run_wrong_password_trials(vault_id: str, attempts: int) -> list[str]:
    discovered = []
    for i in range(attempts):
        res = requests.post(
            f"{API_URL}/api/decrypt",
            json={"password": f"wrong-pass-{i}", "vault_id": vault_id},
            timeout=15,
        )
        if res.status_code == 200:
            key = res.json()["data"]["aws_api_key"]
            discovered.append(key)
    return discovered


def validate_keys(keys: list[str], rounds: int = 1) -> None:
    endpoints = [
        ("GET", "/api/cloud/instances"),
        ("GET", "/api/storage/buckets"),
        ("POST", "/api/cloud/start-instance"),
    ]
    for _ in range(rounds):
        for key in keys:
            headers = {"x-api-key": key}
            for method, path in endpoints:
                if method == "GET":
                    requests.get(f"{API_URL}{path}", headers=headers, timeout=15)
                else:
                    requests.post(f"{API_URL}{path}", headers=headers, timeout=15)


def fetch_metrics() -> dict:
    token = _admin_token()
    headers = {"x-api-token": token} if token else None
    res = requests.get(f"{API_URL}/api/metrics/summary", headers=headers, timeout=15)
    if res.status_code == 401:
        raise RuntimeError(
            "Unauthorized metrics access. Set ADMIN_API_TOKEN in environment "
            "or .env to match the API."
        )
    res.raise_for_status()
    return res.json()


def run_benchmark(scenarios: int = 3, wrong_attempts: int = 8) -> None:
    print("[BENCH] Starting benchmark")
    start = time.time()

    for scenario in range(scenarios):
        vault_id = create_vault(
            password=f"correct-pass-{scenario}",
            key=f"AKIAREALKEY{scenario:08d}ABCD",
        )
        fake_candidates = run_wrong_password_trials(vault_id, attempts=wrong_attempts)
        unique_candidates = list(dict.fromkeys(fake_candidates))[:5]
        validate_keys(unique_candidates, rounds=2)

    metrics = fetch_metrics()
    elapsed = time.time() - start

    print(f"[BENCH] Completed in {elapsed:.2f}s")
    print(f"[BENCH] Total events: {metrics.get('total_events')}")
    print(f"[BENCH] Decoy engagement ratio: {metrics.get('decoy_engagement_ratio')}")
    print(f"[BENCH] Detection latency (s): {metrics.get('detection_latency_seconds')}")

    top = metrics.get("top_session_risks", [])
    if top:
        print("[BENCH] Top session risks:")
        for item in top[:3]:
            print(
                f"  - {item['session_id']} score={item['score']} "
                f"risk={item['risk_level']} decoys={item['decoy_hits']}"
            )


if __name__ == "__main__":
    run_benchmark()
