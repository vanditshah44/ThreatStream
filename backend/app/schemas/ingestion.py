from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.models.enums import FeedRunStatus, FeedSource
from app.services.ingestion_models import CollectorRefreshResult, IngestionSummary


class CollectorRefreshResponse(BaseModel):
    feed_run_id: str | None = None
    source: FeedSource
    status: FeedRunStatus
    started_at: datetime
    completed_at: datetime
    fetched: int = Field(ge=0)
    normalized: int = Field(ge=0)
    inserted: int = Field(ge=0)
    updated: int = Field(ge=0)
    upserted: int = Field(ge=0)
    error_message: str | None = None

    @classmethod
    def from_result(cls, result: CollectorRefreshResult) -> "CollectorRefreshResponse":
        return cls(
            feed_run_id=result.feed_run_id,
            source=result.source,
            status=result.status,
            started_at=result.started_at,
            completed_at=result.completed_at,
            fetched=result.items_fetched,
            normalized=result.items_normalized,
            inserted=result.items_inserted,
            updated=result.items_updated,
            upserted=result.items_upserted,
            error_message=result.error_message,
        )


class IngestionSummaryResponse(BaseModel):
    status: str
    started_at: datetime
    completed_at: datetime
    total_fetched: int = Field(ge=0)
    total_normalized: int = Field(ge=0)
    inserted: int = Field(ge=0)
    updated: int = Field(ge=0)
    upserted: int = Field(ge=0)
    failed_collectors: list[FeedSource]
    collector_runs: list[CollectorRefreshResponse]

    @classmethod
    def from_summary(cls, summary: IngestionSummary) -> "IngestionSummaryResponse":
        return cls(
            status=summary.status,
            started_at=summary.started_at,
            completed_at=summary.completed_at,
            total_fetched=summary.total_fetched,
            total_normalized=summary.total_normalized,
            inserted=summary.total_inserted,
            updated=summary.total_updated,
            upserted=summary.total_upserted,
            failed_collectors=summary.failed_collectors,
            collector_runs=[CollectorRefreshResponse.from_result(result) for result in summary.collector_runs],
        )
