from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.schemas.health import HealthResponse
from app.utils.datetime import utc_now


class HealthService:
    def get_health(self, session: Session) -> HealthResponse:
        settings = get_settings()
        database_status = "ok"

        try:
            session.execute(text("SELECT 1"))
        except SQLAlchemyError:
            database_status = "degraded"

        overall_status = "ok" if database_status == "ok" else "degraded"

        return HealthResponse(
            status=overall_status,
            application=settings.app_name,
            version=settings.app_version,
            environment=settings.app_env,
            database_status=database_status,
            checked_at=utc_now(),
        )

