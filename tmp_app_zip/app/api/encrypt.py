from fastapi import APIRouter
from pydantic import BaseModel, validator
from app.services.vault_service import VaultService

router = APIRouter()
vault_service = VaultService()

class EncryptRequest(BaseModel):
    password: str
    aws_api_key: str

    @validator('aws_api_key')
    def validate_aws_api_key(cls, value: str) -> str:
        if not value.startswith('AKIA') or len(value) != 20:
            raise ValueError('aws_api_key must be a valid 20-character AWS API key (AKIA...)')
        return value

@router.post("/encrypt")
async def encrypt_vault(req: EncryptRequest):
    created = await vault_service.create_vault(req.aws_api_key, req.password)
    
    return {
        "message": "Vault created successfully",
        "vault_id": created["vault_id"],
        "vault": created["vault"],
    }