from __future__ import annotations

import secrets

from fastapi import HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def verify_admin_bearer_token(credentials: HTTPAuthorizationCredentials | None) -> None:
    settings = get_settings()
    configured_token = settings.admin_api_token

    if configured_token is None:
        logger.error("ADMIN_API_TOKEN is not configured. Admin routes are disabled.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Admin routes are disabled because admin authentication is not configured.",
        )

    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Admin authentication required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not secrets.compare_digest(credentials.credentials, configured_token):
        logger.warning("Rejected admin request with an invalid bearer token.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid admin token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
