from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.vault_service import VaultService
from typing import Any

router = APIRouter()
vault_service = VaultService()

class DecryptRequest(BaseModel):
    password: str
    vault_id: str | None = None
    vault: dict[str, Any] | None = None

@router.post("/decrypt")
async def decrypt_vault(req: DecryptRequest):
    if req.vault is not None:
        vault = req.vault
    elif req.vault_id:
        vault = await vault_service.get_vault(req.vault_id)
        if not vault:
            raise HTTPException(status_code=404, detail="Vault not found")
    else:
        raise HTTPException(status_code=422, detail="Provide either vault_id or vault")

    result = vault_service.decrypt_vault(vault, req.password)
    
    # Here, we might also log the decryption attempt, especially if it's a 'fake' one.
    # This is where you would trigger sinkhole/deception mechanisms.

    return {
        "status": result["status"],  # 'real' or 'fake'
        "data": result["data"]
    }