from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from app.api.dependencies import AdminAccess, DatabaseSession
from app.models.enums import FeedSource
from app.schemas.ingestion import IngestionSummaryResponse
from app.services.ingestion_service import IngestionService

router = APIRouter(prefix="/admin", tags=["admin"])

ingestion_service = IngestionService()


@router.post("/refresh", response_model=IngestionSummaryResponse, summary="Trigger manual feed refresh")
def trigger_refresh(
    session: DatabaseSession,
    _: AdminAccess = None,
    source: FeedSource | None = Query(
        default=None,
        description="Optional single source to refresh. Omit to refresh all collectors.",
    ),
) -> IngestionSummaryResponse:
    if ingestion_service.has_active_run(session):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A feed refresh is already running. Wait for it to complete before starting another run.",
        )

    if source is None:
        summary = ingestion_service.refresh_all(session)
    else:
        summary = ingestion_service.refresh_sources(session, [source])

    return IngestionSummaryResponse.from_summary(summary)
