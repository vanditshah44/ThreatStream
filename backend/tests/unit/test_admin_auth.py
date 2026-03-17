from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials

from app.core import security


def test_verify_admin_bearer_token_accepts_valid_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(security, "get_settings", lambda: SimpleNamespace(admin_api_token="test-secret"))

    security.verify_admin_bearer_token(
        HTTPAuthorizationCredentials(scheme="Bearer", credentials="test-secret")
    )


def test_verify_admin_bearer_token_rejects_missing_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(security, "get_settings", lambda: SimpleNamespace(admin_api_token=None))

    with pytest.raises(HTTPException) as exc_info:
        security.verify_admin_bearer_token(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials="anything")
        )

    assert exc_info.value.status_code == 503


def test_verify_admin_bearer_token_rejects_invalid_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(security, "get_settings", lambda: SimpleNamespace(admin_api_token="expected-token"))

    with pytest.raises(HTTPException) as exc_info:
        security.verify_admin_bearer_token(
            HTTPAuthorizationCredentials(scheme="Bearer", credentials="wrong-token")
        )

    assert exc_info.value.status_code == 401
    assert exc_info.value.headers == {"WWW-Authenticate": "Bearer"}
