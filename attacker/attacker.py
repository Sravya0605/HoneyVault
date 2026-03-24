from brute_force import BruteForcer
from validator import KeyValidator

API_URL = "http://127.0.0.1:8000"

def run_attack():
    print("\n[STEP 1] Creating vault (simulating stolen data)\n")

    import requests

    encrypt_res = requests.post(
        f"{API_URL}/api/encrypt",
        json={
            "password": "secure123",
            "aws_api_key": "AKIAREALKEY12345678"
        }
    )

    vault = encrypt_res.json()["vault"]
    vault_id = encrypt_res.json().get("vault_id")
    print("[INFO] Vault acquired by attacker\n")

    print("[STEP 2] Running brute-force attack\n")

    passwords = [
        "123456",
        "password",
        "admin",
        "letmein",
        "secure123",  # correct one hidden inside
        "qwerty"
    ]

    brute = BruteForcer(API_URL)
    results = brute.attempt_passwords(vault, passwords, vault_id=vault_id)

    print("\n[STEP 3] Validating discovered keys\n")

    validator = KeyValidator(API_URL)

    for result in results:
        key = result["key"]
        print(f"\n[ATTACKER] Testing key: {key}\n")
        validator.test_key(key)


if __name__ == "__main__": # Fixed typo
    run_attack()