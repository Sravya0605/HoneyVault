import re 

def is_valid_api_key_format(key: str) -> bool:  
    """  
    Check if key looks like AWS-style key  
    """  

    pattern = r"^AKIA[A-Z0-9]{16}$"  
    return bool(re.match(pattern, key)) 

def mask_key(key: str) -> str:  
    """  
    Mask key for logs/dashboard Example: AKIA****1234  
    """  
    if len(key) < 8:  
        return key 

    return key[:4] + "****" + key[-4:] 