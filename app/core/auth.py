import secrets
from fastapi import Header, HTTPException
from app.core.config import settings


def _token_matches(candidate: str | None, expected: str) -> bool:
    return bool(candidate) and secrets.compare_digest(candidate, expected)


def _has_admin_role(x_api_token: str | None, x_admin_token: str | None) -> bool:
    # Keep legacy admin header for compatibility with existing clients.
    return _token_matches(x_api_token, settings.ADMIN_API_TOKEN) or _token_matches(
        x_admin_token, settings.ADMIN_API_TOKEN
    )


def _has_service_role(x_api_token: str | None) -> bool:
    return _token_matches(x_api_token, settings.SERVICE_API_TOKEN)


async def require_admin_token(
    x_api_token: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
):
    if not settings.METRICS_AUTH_ENABLED:
        return

    if not _has_admin_role(x_api_token, x_admin_token):
        raise HTTPException(status_code=401, detail="Unauthorized")


async def require_service_or_admin_token(
    x_api_token: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
):
    if not settings.METRICS_AUTH_ENABLED:
        return

    if _has_admin_role(x_api_token, x_admin_token):
        return

    if _has_service_role(x_api_token):
        return

    raise HTTPException(status_code=401, detail="Unauthorized")
