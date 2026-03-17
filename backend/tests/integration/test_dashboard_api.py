from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.api.v1.routes.dashboard import (
    get_dashboard_charts,
    get_dashboard_source_status,
    get_dashboard_summary,
)


def test_dashboard_summary_route_returns_expected_metrics(
    db_session: Session,
    fixed_now: datetime,
    seeded_threat_data: dict[str, object],
) -> None:
    response = get_dashboard_summary(db_session)

    assert response.total_indicators == 3
    assert response.critical_items == 1
    assert response.phishing_items == 1
    assert response.ransomware_items == 1
    assert response.kev_items == 1
    assert response.last_updated == fixed_now - timedelta(minutes=1)


def test_dashboard_charts_route_returns_chart_series(
    db_session: Session,
    seeded_threat_data: dict[str, object],
) -> None:
    response = get_dashboard_charts(db_session, days=7)

    assert len(response.source_distribution) == 3
    assert len(response.severity_distribution) == 2
    assert len(response.category_distribution) == 3
    assert len(response.recent_activity_trend) == 7


def test_dashboard_source_status_route_returns_all_supported_sources(
    db_session: Session,
    seeded_threat_data: dict[str, object],
) -> None:
    response = get_dashboard_source_status(db_session)

    assert len(response) == 4
    assert any(status.source.value == "ransomware_live" and status.status is not None for status in response)
