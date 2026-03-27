from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.services.vault_service import VaultService
from app.services.logging_service import LoggingService
from typing import Any

router = APIRouter()
vault_service = VaultService()
logger = LoggingService()


class DecryptRequest(BaseModel):
    password: str
    vault_id: str | None = None
    vault: dict[str, Any] | None = None


@router.post("/decrypt")
async def decrypt_vault(req: DecryptRequest):
    if req.vault_id:
        vault = await vault_service.get_vault(req.vault_id)
        if not vault:
            raise HTTPException(status_code=404, detail="Vault not found")

    elif req.vault:
        if "ciphertext" not in req.vault or "salt" not in req.vault:
            raise HTTPException(
                status_code=400,
                detail="Invalid vault format: missing ciphertext or salt"
            )
        vault = req.vault

    else:
        raise HTTPException(
            status_code=422,
            detail="Provide either vault_id or vault"
        )
    result = vault_service.decrypt_vault(vault, req.password)

    api_key = None
    if isinstance(result.get("data"), dict):
        api_key = result["data"].get("aws_api_key")

    await logger.log_access(
        api_key=api_key or "unknown",
        endpoint="/decrypt",
        method="POST",
        is_fake=(result["status"] == "fake"),
        response_kind=result["status"],
        event_type="decryption_attempt",
    )

    return result