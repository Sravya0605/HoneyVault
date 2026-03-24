import requests 

class KeyValidator: 
    def __init__(self, api_url: str): 
        self.api_url = api_url 

    def test_key(self, key: str): 
        headers = { 
            "x-api-key": key 
        } 
    
        endpoints = [
            ("GET", "/api/cloud/instances"),
            ("GET", "/api/storage/buckets"),
            ("POST", "/api/cloud/start-instance"),
        ]
    
        results = [] 
    
        for method, endpoint in endpoints:
            if method == "GET":
                response = requests.get(
                    f"{self.api_url}{endpoint}",
                    headers=headers,
                )
            else:
                response = requests.post(
                    f"{self.api_url}{endpoint}",
                    headers=headers,
                )
    
            try: 
                data = response.json() 
            except Exception:
                data = {"error": "invalid response"} 
    
            outcome = "SUCCESS" if 200 <= response.status_code < 300 else "FAILED"
            print(
                f"[VALIDATE] Key {key} → {method} {endpoint} "
                f"→ {outcome} (HTTP {response.status_code})"
            )
    
            results.append({ 
                "method": method,
                "endpoint": endpoint, 
                "status_code": response.status_code,
                "response": data 
            }) 
    
        return results 