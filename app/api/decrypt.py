from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from app.services.vault_service import VaultService
from app.services.logging_service import LoggingService
from app.utils.rate_limiter import RateLimiter
from typing import Any
import time
import asyncio

router = APIRouter()
vault_service = VaultService()
logger = LoggingService()
rate_limiter = RateLimiter(max_requests=30, time_window_seconds=60)


class DecryptRequest(BaseModel):
    password: str
    vault_id: str | None = None
    vault: dict[str, Any] | None = None


@router.post("/decrypt")
async def decrypt_vault(req: DecryptRequest, request: Request):
    """
    Decrypt vault with any password.
    
    Real HE property:
    - Every password produces a valid output
    - No "wrong password" signal
    - Indistinguishable from real or fake without external knowledge
    - Constant-time response to prevent timing attacks
    - Rate limited to prevent brute-force attacks
    """
    start_time = time.time()
    
    # Get client IP for rate limiting
    client_ip = request.client.host if request.client else "unknown"
    
    # Check rate limit
    allowed, rate_info = rate_limiter.is_allowed(client_ip)
    if not allowed:
        # Return 429 Too Many Requests
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: {rate_info['current_count']} / {rate_info['limit']} requests per {rate_info['window_seconds']}s. Reset in {rate_info['reset_seconds']:.0f}s"
        )
    
    try:
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
        
        # Decrypt (always succeeds with plausible output)
        result = await vault_service.decrypt_vault(vault, req.password)
        
        # Extract API key for logging
        api_key = None
        if isinstance(result.get("data"), dict):
            api_key = result["data"].get("aws_api_key")
        
        # Log access (is_real may be None, True, or False)
        is_real = result.get("is_real")
        await logger.log_access(
            api_key=api_key or "unknown",
            endpoint="/decrypt",
            method="POST",
            is_fake=(is_real is False),
            response_kind="unknown" if is_real is None else ("real" if is_real else "fake"),
            event_type="decryption_attempt",
        )
        
        # Pad response time to minimum to prevent timing attacks
        MIN_RESPONSE_TIME_MS = 50
        elapsed_ms = (time.time() - start_time) * 1000
        remaining_ms = max(0, MIN_RESPONSE_TIME_MS - elapsed_ms)
        if remaining_ms > 0:
            await asyncio.sleep(remaining_ms / 1000)
        
        # Return in constant-time format (no timing leaks)
        return {
            "status": "success",
            "data": result.get("data"),
            "metadata": {
                "scheme": "REAL_HE_DTE_V1_AES_CTR",
                "indistinguishable": True
            }
        }
    except HTTPException:
        # Allow HTTP exceptions through
        raise
    except Exception as e:
        # Unexpected errors - still pad timing
        elapsed_ms = (time.time() - start_time) * 1000
        MIN_RESPONSE_TIME_MS = 50
        remaining_ms = max(0, MIN_RESPONSE_TIME_MS - elapsed_ms)
        if remaining_ms > 0:
            await asyncio.sleep(remaining_ms / 1000)
        raise