import re


def is_valid_api_key_format(key: str) -> bool:
    """
    Accept AWS-style keys and generic alphanumeric keys for demo workflows.
    """
    if not key:
        return False

    aws_pattern = r"^(AKIA|ASIA|ANPA)[A-Z0-9]{16}$"
    generic_pattern = r"^[A-Za-z0-9]{16,64}$"
    return bool(re.match(aws_pattern, key) or re.match(generic_pattern, key))

def mask_key(key: str) -> str:  
    """  
    Mask key for logs/dashboard Example: AKIA****1234  
    """  
    if len(key) < 8:  
        return key 

    return key[:4] + "****" + key[-4:] 