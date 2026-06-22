from pydantic import BaseModel  
from datetime import datetime 

class AttackSession(BaseModel):  
    session_id: str 

    start_time: datetime 
    end_time: datetime | None = None 
    
    total_requests: int = 0 
    
    fake_key_usage: int = 0 
    real_key_usage: int = 0 
    
    detected: bool = False 