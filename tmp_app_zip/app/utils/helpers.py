import random  
import string  
from datetime import datetime 

def generate_random_ip() -> str:  
    """
    Simulate attacker IP
    """  
    return ".".join(str(random.randint(1, 255)) for _ in range(4)) 

def current_timestamp():  
    return datetime.utcnow() 

def generate_session_id(length: int = 12) -> str:  
    chars = string.ascii_letters + string.digits  
    return ''.join(random.choices(chars, k=length)) 