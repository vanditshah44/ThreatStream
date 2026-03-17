from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy.orm import Session

from app.api.v1.routes import admin as admin_route
from app.models.enums import FeedRunStatus, FeedSource
from app.schemas.ingestion import IngestionSummaryResponse
from app.services.ingestion_models import CollectorRefreshResult, IngestionSummary


class _StubIngestionService:
    def has_active_run(self, session: object) -> bool:
        return False

    def refresh_all(self, session: object) -> IngestionSummary:
        timestamp = datetime(2026, 3, 17, tzinfo=timezone.utc)
        return IngestionSummary(
            started_at=timestamp,
            completed_at=timestamp,
            collector_runs=(
                CollectorRefreshResult(
                    feed_run_id="run-1",
                    source=FeedSource.CISA_KEV,
                    status=FeedRunStatus.SUCCESS,
                    started_at=timestamp,
                    completed_at=timestamp,
                    items_fetched=10,
                    items_normalized=10,
                    items_inserted=6,
                    items_updated=4,
                    error_message=None,
                ),
            ),
        )


def test_admin_refresh_returns_ingestion_summary(monkeypatch, db_session: Session) -> None:
    monkeypatch.setattr(admin_route, "ingestion_service", _StubIngestionService())
    response = admin_route.trigger_refresh(db_session, source=None)

    assert isinstance(response, IngestionSummaryResponse)
    assert response.status == "success"
    assert response.total_fetched == 10
    assert response.inserted == 6
    assert response.updated == 4
    assert response.failed_collectors == []
    assert response.collector_runs[0].source == FeedSource.CISA_KEV


class _BusyStubIngestionService:
    def has_active_run(self, session: object) -> bool:
        return True


def test_admin_refresh_rejects_overlapping_runs(monkeypatch, db_session: Session) -> None:
    monkeypatch.setattr(admin_route, "ingestion_service", _BusyStubIngestionService())

    with pytest.raises(Exception) as exc_info:
        admin_route.trigger_refresh(db_session, source=None)

    assert getattr(exc_info.value, "status_code", None) == 409
    assert "already running" in str(getattr(exc_info.value, "detail", "")).lower()
