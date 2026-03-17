from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query, status

from app.api.dependencies import DatabaseSession
from app.models.enums import FeedSource, IndicatorType, Severity, ThreatCategory
from app.schemas.threat import (
    SortOrder,
    ThreatFilterParams,
    ThreatItemRead,
    ThreatListResponse,
    ThreatSortBy,
)
from app.services.threat_service import ThreatService

router = APIRouter(prefix="/threats", tags=["threats"])

threat_service = ThreatService()


@router.get("", response_model=ThreatListResponse, summary="List threat items")
def list_threats(
    session: DatabaseSession,
    source: FeedSource | None = Query(default=None),
    severity: Severity | None = Query(default=None),
    category: ThreatCategory | None = Query(default=None),
    indicator_type: IndicatorType | None = Query(default=None),
    search: str | None = Query(default=None, min_length=1, max_length=200),
    sort_by: ThreatSortBy = Query(default=ThreatSortBy.RECENCY),
    sort_order: SortOrder = Query(default=SortOrder.DESC),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
) -> ThreatListResponse:
    filters = ThreatFilterParams(
        source=source,
        severity=severity,
        category=category,
        indicator_type=indicator_type,
        search=search,
        sort_by=sort_by,
        sort_order=sort_order,
        page=page,
        page_size=page_size,
    )
    return threat_service.list_threats(session, filters)


@router.get("/{threat_id}", response_model=ThreatItemRead, summary="Get a threat item by id")
def get_threat(threat_id: str, session: DatabaseSession) -> ThreatItemRead:
    threat = threat_service.get_threat_by_id(session, threat_id)
    if threat is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat item '{threat_id}' was not found.",
        )

    return threat
