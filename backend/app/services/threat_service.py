from __future__ import annotations

from math import ceil

from sqlalchemy import Text, cast, func, or_, select
from sqlalchemy.orm import Session

from app.models.enums import FeedSource, Severity
from app.models.threat_item import ThreatItem
from app.schemas.threat import (
    SortOrder,
    ThreatFilterParams,
    ThreatItemRead,
    ThreatListItemRead,
    ThreatListMeta,
    ThreatListResponse,
    ThreatListStats,
    ThreatSourceDistributionItem,
    ThreatSortBy,
)


class ThreatService:
    def list_threats(self, session: Session, filters: ThreatFilterParams) -> ThreatListResponse:
        statement = self._build_filtered_statement(filters)
        filtered_subquery = statement.subquery()

        total = session.scalar(select(func.count()).select_from(filtered_subquery)) or 0
        stats = self._build_stats(session, filtered_subquery)

        paginated_statement = (
            statement.order_by(*self._build_sort_order(filters))
            .offset((filters.page - 1) * filters.page_size)
            .limit(filters.page_size)
        )

        items = session.scalars(paginated_statement).all()
        total_pages = ceil(total / filters.page_size) if total > 0 else 0

        return ThreatListResponse(
            items=[ThreatListItemRead.model_validate(item) for item in items],
            meta=ThreatListMeta(
                page=filters.page,
                page_size=filters.page_size,
                total=total,
                total_pages=total_pages,
                sort_by=filters.sort_by,
                sort_order=filters.sort_order,
            ),
            stats=stats,
        )

    def get_threat_by_id(self, session: Session, threat_id: str) -> ThreatItemRead | None:
        statement = select(ThreatItem).where(ThreatItem.id == threat_id)
        threat = session.scalar(statement)
        if threat is None:
            return None
        return ThreatItemRead.model_validate(threat)

    def _build_filtered_statement(self, filters: ThreatFilterParams):
        statement = select(ThreatItem)

        if filters.source is not None:
            statement = statement.where(ThreatItem.source == filters.source)
        if filters.severity is not None:
            statement = statement.where(ThreatItem.severity == filters.severity)
        if filters.category is not None:
            statement = statement.where(ThreatItem.category == filters.category)
        if filters.indicator_type is not None:
            statement = statement.where(ThreatItem.indicator_type == filters.indicator_type)
        if filters.search:
            statement = statement.where(self._build_search_clause(filters.search))

        return statement

    def _build_search_clause(self, search: str):
        pattern = f"%{search}%"
        return or_(
            ThreatItem.indicator_value.ilike(pattern),
            ThreatItem.title.ilike(pattern),
            ThreatItem.description.ilike(pattern),
            ThreatItem.threat_actor.ilike(pattern),
            cast(ThreatItem.tags, Text).ilike(pattern),
        )

    def _build_sort_order(self, filters: ThreatFilterParams) -> tuple:
        recency_expression = func.coalesce(
            ThreatItem.last_seen,
            ThreatItem.first_seen,
            ThreatItem.updated_at,
            ThreatItem.created_at,
        )
        if filters.sort_by == ThreatSortBy.RECENCY:
            primary_column = recency_expression
            fallback_column = ThreatItem.risk_score
        else:
            primary_column = ThreatItem.risk_score
            fallback_column = recency_expression

        if filters.sort_order == SortOrder.ASC:
            return (
                primary_column.asc(),
                fallback_column.asc(),
                ThreatItem.created_at.asc(),
            )

        return (
            primary_column.desc(),
            fallback_column.desc(),
            ThreatItem.created_at.desc(),
        )

    def _build_stats(self, session: Session, filtered_subquery) -> ThreatListStats:
        average_risk = session.scalar(select(func.avg(filtered_subquery.c.risk_score))) or 0
        critical_count = session.scalar(
            select(func.count())
            .select_from(filtered_subquery)
            .where(filtered_subquery.c.severity == Severity.CRITICAL)
        ) or 0
        source_count = session.scalar(
            select(func.count(func.distinct(filtered_subquery.c.source))).select_from(filtered_subquery)
        ) or 0
        latest_ingested_at = session.scalar(select(func.max(filtered_subquery.c.updated_at)))

        recency_expression = func.coalesce(
            filtered_subquery.c.last_seen,
            filtered_subquery.c.first_seen,
            filtered_subquery.c.updated_at,
            filtered_subquery.c.created_at,
        )
        latest_activity_row = session.execute(
            select(
                filtered_subquery.c.source,
                filtered_subquery.c.indicator_value,
                recency_expression.label("observed_at"),
            )
            .select_from(filtered_subquery)
            .order_by(
                recency_expression.desc(),
                filtered_subquery.c.updated_at.desc(),
                filtered_subquery.c.created_at.desc(),
            )
            .limit(1)
        ).first()

        source_rows = session.execute(
            select(
                filtered_subquery.c.source,
                func.count().label("count"),
            )
            .select_from(filtered_subquery)
            .group_by(filtered_subquery.c.source)
            .order_by(func.count().desc(), filtered_subquery.c.source.asc())
        ).all()

        latest_activity_source: FeedSource | None = None
        latest_activity_indicator: str | None = None
        latest_activity_at = None
        if latest_activity_row is not None:
            latest_activity_source = latest_activity_row.source
            latest_activity_indicator = latest_activity_row.indicator_value
            latest_activity_at = latest_activity_row.observed_at

        return ThreatListStats(
            average_risk_score=round(float(average_risk)) if average_risk else 0,
            critical_count=critical_count,
            source_count=source_count,
            latest_activity_at=latest_activity_at,
            latest_activity_source=latest_activity_source,
            latest_activity_indicator=latest_activity_indicator,
            latest_ingested_at=latest_ingested_at,
            source_distribution=[
                ThreatSourceDistributionItem(source=source, count=count)
                for source, count in source_rows
            ],
        )
