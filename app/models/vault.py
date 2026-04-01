from pydantic import BaseModel, Field
from typing import Optional, Dict, Any


class VaultModel(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")

    ciphertext: str
    salt: str
    real_seed: str

    real_api_key_hash: str

    metadata: Dict[str, Any]

    class Config:
        populate_by_name = True