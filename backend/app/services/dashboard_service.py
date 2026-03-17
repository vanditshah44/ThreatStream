from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone

from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from app.models.enums import FeedRunStatus, FeedSource, Severity, ThreatCategory
from app.models.feed_run import FeedRun
from app.models.threat_item import ThreatItem
from app.schemas.dashboard import (
    DashboardChartBucket,
    DashboardCharts,
    DashboardSourceStatus,
    DashboardSummary,
    DashboardTrendPoint,
)
from app.utils.datetime import utc_now


class DashboardService:
    def get_summary(self, session: Session) -> DashboardSummary:
        summary_row = session.execute(
            select(
                func.count().label("total_indicators"),
                func.sum(case((ThreatItem.severity == Severity.CRITICAL, 1), else_=0)).label("critical_items"),
                func.sum(case((ThreatItem.category == ThreatCategory.PHISHING, 1), else_=0)).label("phishing_items"),
                func.sum(
                    case((ThreatItem.category == ThreatCategory.RANSOMWARE, 1), else_=0)
                ).label("ransomware_items"),
                func.sum(case((ThreatItem.source == FeedSource.CISA_KEV, 1), else_=0)).label("kev_items"),
            )
            .select_from(ThreatItem)
        ).one()

        last_updated = session.scalar(
            select(func.max(FeedRun.completed_at)).where(FeedRun.status == FeedRunStatus.SUCCESS)
        )
        if last_updated is None:
            last_updated = session.scalar(select(func.max(ThreatItem.updated_at)))
        last_updated = self._ensure_utc_datetime(last_updated)

        return DashboardSummary(
            total_indicators=summary_row.total_indicators or 0,
            critical_items=summary_row.critical_items or 0,
            phishing_items=summary_row.phishing_items or 0,
            ransomware_items=summary_row.ransomware_items or 0,
            kev_items=summary_row.kev_items or 0,
            last_updated=last_updated,
        )

    def get_charts(
        self,
        session: Session,
        *,
        days: int = 14,
        reference_time: datetime | None = None,
    ) -> DashboardCharts:
        return DashboardCharts(
            severity_distribution=self._build_distribution(session, ThreatItem.severity),
            source_distribution=self._build_distribution(session, ThreatItem.source),
            category_distribution=self._build_distribution(session, ThreatItem.category),
            recent_activity_trend=self._build_recent_activity_trend(
                session,
                days=days,
                reference_time=reference_time,
            ),
        )

    def get_source_status(self, session: Session) -> list[DashboardSourceStatus]:
        indicator_counts = {
            source: count
            for source, count in session.execute(
                select(ThreatItem.source, func.count())
                .select_from(ThreatItem)
                .group_by(ThreatItem.source)
            ).all()
        }

        latest_runs_by_source: dict[FeedSource, FeedRun] = {}
        for run in session.scalars(
            select(FeedRun).order_by(FeedRun.started_at.desc(), FeedRun.created_at.desc())
        ).all():
            latest_runs_by_source.setdefault(run.source, run)

        latest_success_at = {
            source: completed_at
            for source, completed_at in session.execute(
                select(FeedRun.source, func.max(FeedRun.completed_at))
                .where(FeedRun.status == FeedRunStatus.SUCCESS)
                .group_by(FeedRun.source)
            ).all()
        }

        statuses: list[DashboardSourceStatus] = []
        for source in FeedSource:
            latest_run = latest_runs_by_source.get(source)
            statuses.append(
                DashboardSourceStatus(
                    source=source,
                    status=latest_run.status if latest_run is not None else None,
                    indicator_count=indicator_counts.get(source, 0) or 0,
                    last_started_at=self._ensure_utc_datetime(latest_run.started_at) if latest_run is not None else None,
                    last_completed_at=self._ensure_utc_datetime(latest_run.completed_at) if latest_run is not None else None,
                    last_success_at=self._ensure_utc_datetime(latest_success_at.get(source)),
                    last_error_message=latest_run.error_message if latest_run is not None else None,
                    items_fetched=(latest_run.items_fetched or 0) if latest_run is not None else 0,
                    items_upserted=(latest_run.items_upserted or 0) if latest_run is not None else 0,
                )
            )

        return statuses

    def _build_distribution(self, session: Session, column) -> list[DashboardChartBucket]:
        rows = session.execute(
            select(column, func.count())
            .select_from(ThreatItem)
            .group_by(column)
            .order_by(func.count().desc(), column.asc())
        ).all()

        return [
            DashboardChartBucket(
                label=self._normalize_bucket_label(label),
                value=count,
            )
            for label, count in rows
        ]

    def _build_recent_activity_trend(
        self,
        session: Session,
        *,
        days: int,
        reference_time: datetime | None,
    ) -> list[DashboardTrendPoint]:
        current_time = self._ensure_utc_datetime(reference_time or utc_now()) or utc_now()
        end_date = current_time.date()
        start_date = end_date - timedelta(days=days - 1)
        window_start = datetime.combine(start_date, time.min, tzinfo=timezone.utc)
        observed_expression = func.coalesce(
            ThreatItem.last_seen,
            ThreatItem.first_seen,
            ThreatItem.updated_at,
            ThreatItem.created_at,
        )

        rows = session.execute(
            select(func.date(observed_expression), func.count())
            .select_from(ThreatItem)
            .where(observed_expression >= window_start)
            .group_by(func.date(observed_expression))
            .order_by(func.date(observed_expression).asc())
        ).all()

        counts_by_date = {
            self._normalize_date_label(date_value): count
            for date_value, count in rows
            if self._normalize_date_label(date_value) is not None
        }

        points: list[DashboardTrendPoint] = []
        current_date = start_date
        while current_date <= end_date:
            points.append(
                DashboardTrendPoint(
                    date=current_date,
                    value=counts_by_date.get(current_date, 0),
                )
            )
            current_date += timedelta(days=1)

        return points

    def _ensure_utc_datetime(self, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is not None:
            return value
        return value.replace(tzinfo=timezone.utc)

    def _normalize_bucket_label(self, value: object) -> str:
        if hasattr(value, "value"):
            return str(getattr(value, "value"))
        return str(value)

    def _normalize_date_label(self, value: object) -> date | None:
        if value is None:
            return None
        if isinstance(value, date) and not isinstance(value, datetime):
            return value
        if isinstance(value, datetime):
            return value.date()
        if isinstance(value, str):
            return date.fromisoformat(value)
        return None
