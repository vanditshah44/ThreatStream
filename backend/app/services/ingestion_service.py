from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.collectors.registry import CollectorRegistry
from app.core.logging import get_logger
from app.models.enums import FeedRunStatus, FeedSource
from app.models.feed_run import FeedRun
from app.services.ingestion_models import CollectorRefreshResult, IngestionSummary
from app.services.threat_upsert_service import ThreatUpsertService
from app.utils.datetime import utc_now


class IngestionService:
    def __init__(
        self,
        collector_registry: CollectorRegistry | None = None,
        threat_upsert_service: ThreatUpsertService | None = None,
    ) -> None:
        self.collector_registry = collector_registry or CollectorRegistry()
        self.threat_upsert_service = threat_upsert_service or ThreatUpsertService()
        self.logger = get_logger(__name__)

    def has_active_run(self, session: Session, *, stale_after_minutes: int = 30) -> bool:
        cutoff = utc_now() - timedelta(minutes=stale_after_minutes)
        running_run = session.scalar(
            select(FeedRun)
            .where(FeedRun.status == FeedRunStatus.RUNNING, FeedRun.started_at >= cutoff)
            .order_by(FeedRun.started_at.desc())
            .limit(1)
        )
        return running_run is not None

    def refresh_all(self, session: Session) -> IngestionSummary:
        return self.refresh_sources(session, self.collector_registry.available_sources())

    def refresh_sources(self, session: Session, sources: list[FeedSource]) -> IngestionSummary:
        started_at = utc_now()
        self.logger.info(
            "Starting ThreatStream ingestion run for %s collector(s): %s.",
            len(sources),
            ", ".join(source.value for source in sources),
        )

        collector_runs: list[CollectorRefreshResult] = []
        for source in sources:
            collector_runs.append(self.refresh_source(session, source))

        completed_at = utc_now()
        summary = IngestionSummary(
            started_at=started_at,
            completed_at=completed_at,
            collector_runs=tuple(collector_runs),
        )
        self.logger.info(
            "Finished ThreatStream ingestion run with status=%s fetched=%s inserted=%s updated=%s failed_collectors=%s.",
            summary.status,
            summary.total_fetched,
            summary.total_inserted,
            summary.total_updated,
            [source.value for source in summary.failed_collectors],
        )
        return summary

    def refresh_source(self, session: Session, source: FeedSource) -> CollectorRefreshResult:
        collector = self.collector_registry.get(source)
        run = FeedRun(
            source=source,
            status=FeedRunStatus.RUNNING,
            started_at=utc_now(),
            items_fetched=0,
            items_normalized=0,
            items_upserted=0,
        )
        session.add(run)
        session.commit()
        session.refresh(run)
        self.logger.info("Starting collector '%s'.", source.value)
        inserted_count = 0
        updated_count = 0

        try:
            result = collector.collect()
            run.items_fetched = result.raw_count
            run.items_normalized = len(result.normalized_items)
            upsert_result = self.threat_upsert_service.upsert_many(session, result.normalized_items)
            inserted_count = upsert_result.inserted_count
            updated_count = upsert_result.updated_count
            run.items_upserted = upsert_result.processed_count
            run.status = FeedRunStatus.SUCCESS
            self.logger.info(
                "Collector '%s' completed: fetched=%s normalized=%s inserted=%s updated=%s upserted=%s.",
                source.value,
                run.items_fetched,
                run.items_normalized,
                inserted_count,
                updated_count,
                run.items_upserted,
            )
        except Exception as exc:  # pragma: no cover - placeholder error path for future collectors
            session.rollback()
            run.status = FeedRunStatus.FAILED
            run.error_message = str(exc)
            self.logger.exception("Collector '%s' failed.", source.value)
        finally:
            run.completed_at = utc_now()
            session.add(run)
            session.commit()
            session.refresh(run)

        return CollectorRefreshResult(
            feed_run_id=run.id,
            source=source,
            status=run.status,
            started_at=run.started_at,
            completed_at=run.completed_at or run.started_at,
            items_fetched=run.items_fetched or 0,
            items_normalized=run.items_normalized or 0,
            items_inserted=inserted_count,
            items_updated=updated_count,
            error_message=run.error_message,
        )
