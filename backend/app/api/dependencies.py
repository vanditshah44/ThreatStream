from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.database import get_db_session
from app.core.security import verify_admin_bearer_token

DatabaseSession = Annotated[Session, Depends(get_db_session)]

_admin_bearer_scheme = HTTPBearer(auto_error=False)


def require_admin_access(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_admin_bearer_scheme)],
) -> None:
    verify_admin_bearer_token(credentials)


AdminAccess = Annotated[None, Depends(require_admin_access)]
