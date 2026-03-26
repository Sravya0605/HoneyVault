from pydantic import BaseModel, Field  

from datetime import datetime, timezone

from typing import Optional 

class AccessLog(BaseModel):  

    id: str | None = Field(default=None, alias="_id") 

    api_key: Optional[str] = None
    api_key_masked: str
    api_key_hash: str
    prev_chain_hash: str
    chain_hash: str
    endpoint: str 
    method: str 
    
    is_fake: bool  # critical for analysis 
    
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # simulated attacker info 
    source_ip: Optional[str] = "127.0.0.1" 
    user_agent: Optional[str] = "attacker-script" 
    
    # extra behavior tracking 
    response_status: Optional[str] = "success" 
    response_code: Optional[int] = 200
    response_kind: Optional[str] = "unknown"  # decoy, real, rejected
    session_id: Optional[str] = None
    event_type: Optional[str] = "api_access"