from pydantic import BaseModel, Field
from typing import Optional, Dict, Any


class VaultModel(BaseModel):
    id: Optional[str] = Field(default=None, alias="_id")

    ciphertext: str
    salt: str
    nonce: Optional[str] = None
    tag: Optional[str] = None

    metadata: Dict[str, Any]

    class Config:
        populate_by_name = True