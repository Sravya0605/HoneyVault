from pydantic import BaseModel, Field, ConfigDict
from typing import List, Dict, Any  
from datetime import datetime, timezone

class VaultModel(BaseModel):  
    id: str | None = Field(default=None, alias="_id") 

    ciphertext: str 
    salt: str | None = None
    fake_keys: List[str] 
    fake_secrets: List[Dict[str, Any]] = Field(default_factory=list)
    
    metadata: Dict[str, Any] = Field(default_factory=dict) 
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(populate_by_name=True, arbitrary_types_allowed=True)
