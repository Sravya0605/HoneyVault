from fastapi import APIRouter
from pydantic import BaseModel
from app.services.vault_service import VaultService

router = APIRouter()
vault_service = VaultService()

class EncryptRequest(BaseModel):
    password: str
    aws_api_key: str

@router.post("/encrypt")
async def encrypt_vault(req: EncryptRequest):
    created = await vault_service.create_vault(req.aws_api_key, req.password)
    
    return {
        "message": "Vault created successfully",
        "vault_id": created["vault_id"],
        "vault": created["vault"],
    }