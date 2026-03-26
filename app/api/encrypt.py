from fastapi import APIRouter
from pydantic import BaseModel, Field
from app.services.vault_service import VaultService

router = APIRouter()
vault_service = VaultService()

class EncryptRequest(BaseModel):
    password: str = Field(min_length=8, max_length=256)
    aws_api_key: str = Field(min_length=16, max_length=64)

@router.post("/encrypt")
async def encrypt_vault(req: EncryptRequest):
    created = await vault_service.create_vault(req.aws_api_key, req.password)
    
    return {
        "message": "Vault created successfully",
        "vault_id": created["vault_id"],
        "vault": created["vault"],
    }