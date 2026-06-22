from pydantic import BaseModel, Field  

from datetime import datetime  

from typing import Optional 

class AccessLog(BaseModel):  

    id: str | None = Field(default=None, alias="_id") 

    api_key: str 
    endpoint: str 
    method: str 
    
    is_fake: bool  # critical for analysis 
    
    timestamp: datetime = Field(default_factory=datetime.utcnow) 
    
    # simulated attacker info 
    source_ip: Optional[str] = "127.0.0.1" 
    user_agent: Optional[str] = "attacker-script" 
    
    # extra behavior tracking 
    response_status: Optional[str] = "success" 
    response_code: Optional[int] = 200
    response_kind: Optional[str] = "unknown"  # decoy, real, rejected
    session_id: Optional[str] = None
    event_type: Optional[str] = "api_access"