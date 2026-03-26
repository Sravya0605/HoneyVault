from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from app.services.vault_service import VaultService
from app.utils.rate_limiter import InMemoryRateLimiter
from app.core.config import settings
from typing import Any
import hashlib

router = APIRouter()
vault_service = VaultService()
decrypt_rate_limiter = InMemoryRateLimiter(
    max_requests=settings.DECRYPT_RATE_LIMIT,
    window_seconds=settings.RATE_LIMIT_WINDOW_SECONDS,
)

class DecryptRequest(BaseModel):
    password: str = Field(min_length=8, max_length=256)
    vault_id: str | None = None
    vault: dict[str, Any] | None = None


def _fake_for_missing_vault(vault_id: str, password: str) -> dict[str, Any]:
    # Avoid vault-id enumeration by returning deterministic fake output.
    seed_material = f"{vault_id}:{password}"
    seed = int(hashlib.sha256(seed_material.encode()).hexdigest(), 16)
    return vault_service.he.dte.sample_secret(seed)

@router.post("/decrypt")
async def decrypt_vault(req: DecryptRequest, request: Request):
    if not req.vault_id and req.vault is None:
        raise HTTPException(status_code=422, detail="Provide at least one of vault_id or vault")

    client_ip = request.client.host if request.client else "unknown"
    target = req.vault_id if req.vault_id else "inline-vault"
    if not decrypt_rate_limiter.allow(f"{client_ip}:{target}"):
        raise HTTPException(status_code=429, detail="Too many decrypt attempts")

    if req.vault_id:
        vault = await vault_service.get_vault(req.vault_id)
        if not vault:
            return {
                "status": "fake",
                "data": _fake_for_missing_vault(req.vault_id, req.password),
            }
    else:
        vault = req.vault

    result = vault_service.decrypt_vault(vault, req.password)
    
    # Here, we might also log the decryption attempt, especially if it's a 'fake' one.
    # This is where you would trigger sinkhole/deception mechanisms.

    return {
        "status": result["status"],  # 'real' or 'fake'
        "data": result["data"]
    }