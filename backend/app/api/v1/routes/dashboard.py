from __future__ import annotations

from fastapi import APIRouter, Query

from app.api.dependencies import DatabaseSession
from app.schemas.dashboard import DashboardCharts, DashboardSourceStatus, DashboardSummary
from app.services.dashboard_service import DashboardService

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

dashboard_service = DashboardService()


@router.get("/summary", response_model=DashboardSummary, summary="Get dashboard summary metrics")
def get_dashboard_summary(session: DatabaseSession) -> DashboardSummary:
    return dashboard_service.get_summary(session)


@router.get("/charts", response_model=DashboardCharts, summary="Get dashboard chart datasets")
def get_dashboard_charts(
    session: DatabaseSession,
    days: int = Query(default=14, ge=7, le=90),
) -> DashboardCharts:
    return dashboard_service.get_charts(session, days=days)


@router.get(
    "/source-status",
    response_model=list[DashboardSourceStatus],
    summary="Get per-source ingestion status and coverage",
)
def get_dashboard_source_status(session: DatabaseSession) -> list[DashboardSourceStatus]:
    return dashboard_service.get_source_status(session)
