from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.services.dashboard_service import DashboardService


def test_dashboard_summary_counts_and_last_updated(
    db_session: Session,
    fixed_now: datetime,
    seeded_threat_data: dict[str, object],
) -> None:
    summary = DashboardService().get_summary(db_session)

    assert summary.total_indicators == 3
    assert summary.critical_items == 1
    assert summary.phishing_items == 1
    assert summary.ransomware_items == 1
    assert summary.kev_items == 1
    assert summary.last_updated == fixed_now - timedelta(minutes=1)


def test_dashboard_charts_return_distributions_and_recent_activity(
    db_session: Session,
    fixed_now: datetime,
    seeded_threat_data: dict[str, object],
) -> None:
    charts = DashboardService().get_charts(db_session, days=7, reference_time=fixed_now)

    assert [(bucket.label, bucket.value) for bucket in charts.source_distribution] == [
        ("cisa_kev", 1),
        ("openphish", 1),
        ("ransomware_live", 1),
    ]
    assert [(bucket.label, bucket.value) for bucket in charts.severity_distribution] == [
        ("high", 2),
        ("critical", 1),
    ]
    assert [(bucket.label, bucket.value) for bucket in charts.category_distribution] == [
        ("exploited_vuln", 1),
        ("phishing", 1),
        ("ransomware", 1),
    ]
    assert len(charts.recent_activity_trend) == 7
    assert charts.recent_activity_trend[-2].date.isoformat() == "2026-03-16"
    assert charts.recent_activity_trend[-2].value == 3
    assert charts.recent_activity_trend[-1].date.isoformat() == "2026-03-17"
    assert charts.recent_activity_trend[-1].value == 0


def test_dashboard_source_status_reports_latest_run_and_indicator_counts(
    db_session: Session,
    fixed_now: datetime,
    seeded_threat_data: dict[str, object],
) -> None:
    statuses = DashboardService().get_source_status(db_session)
    by_source = {status.source.value: status for status in statuses}

    ransomware_status = by_source["ransomware_live"]
    assert ransomware_status.indicator_count == 1
    assert ransomware_status.status is not None
    assert ransomware_status.status.value == "success"
    assert ransomware_status.last_success_at == fixed_now - timedelta(minutes=1)

    kev_status = by_source["cisa_kev"]
    assert kev_status.indicator_count == 1
    assert kev_status.status is None
    assert kev_status.last_success_at is None
