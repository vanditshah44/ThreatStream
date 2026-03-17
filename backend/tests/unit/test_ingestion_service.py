from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from app.collectors.base import CollectorError, CollectorResult, FeedCollector
from app.models.enums import FeedRunStatus, FeedSource, IndicatorType, Severity, ThreatCategory
from app.models.feed_run import FeedRun
from app.schemas.normalized_threat import NormalizedThreatItem
from app.services.ingestion_models import UpsertResult
from app.services.ingestion_service import IngestionService


class _FakeSession:
    def __init__(self) -> None:
        self._run_counter = 0

    def add(self, obj: object) -> None:
        if isinstance(obj, FeedRun) and not obj.id:
            self._run_counter += 1
            obj.id = f"run-{self._run_counter}"

    def commit(self) -> None:
        return None

    def refresh(self, obj: object) -> None:
        if isinstance(obj, FeedRun) and not obj.id:
            self._run_counter += 1
            obj.id = f"run-{self._run_counter}"

    def rollback(self) -> None:
        return None


class _StaticCollector(FeedCollector):
    def __init__(self, source: FeedSource, normalized_items: list[NormalizedThreatItem]) -> None:
        self.source = source
        self._normalized_items = normalized_items

    def fetch(self) -> list[dict[str, Any]]:
        return [{"source": self.source.value}]

    def normalize(self, raw_records: list[dict[str, Any]]) -> list[NormalizedThreatItem]:
        return self._normalized_items


class _FailingCollector(FeedCollector):
    def __init__(self, source: FeedSource) -> None:
        self.source = source

    def fetch(self) -> list[dict[str, Any]]:
        raise CollectorError("simulated failure")

    def normalize(self, raw_records: list[dict[str, Any]]) -> list[NormalizedThreatItem]:
        return []


class _StubCollectorRegistry:
    def __init__(self, collectors: dict[FeedSource, FeedCollector]) -> None:
        self._collectors = collectors

    def available_sources(self) -> list[FeedSource]:
        return list(self._collectors.keys())

    def get(self, source: FeedSource) -> FeedCollector:
        return self._collectors[source]


class _StubThreatUpsertService:
    def upsert_many(self, session: _FakeSession, threats: list[NormalizedThreatItem]) -> UpsertResult:
        return UpsertResult(
            input_count=len(threats),
            deduplicated_count=len(threats),
            inserted_count=len(threats),
            updated_count=0,
        )


def _build_normalized_threat(threat_id: str, source: FeedSource) -> NormalizedThreatItem:
    timestamp = datetime(2026, 3, 17, tzinfo=timezone.utc)
    return NormalizedThreatItem(
        id=threat_id,
        source=source,
        indicator_type=IndicatorType.URL,
        indicator_value=f"https://example.test/{threat_id}",
        title="Example threat",
        description="Example",
        category=ThreatCategory.PHISHING,
        first_seen=timestamp,
        last_seen=timestamp,
        tags=["phishing"],
        confidence=75,
        severity=Severity.HIGH,
        risk_score=70,
        raw_payload={"id": threat_id},
    )


def test_refresh_all_continues_when_one_collector_fails() -> None:
    registry = _StubCollectorRegistry(
        {
            FeedSource.OPENPHISH: _StaticCollector(
                FeedSource.OPENPHISH,
                [_build_normalized_threat("phish-1", FeedSource.OPENPHISH)],
            ),
            FeedSource.URLHAUS: _FailingCollector(FeedSource.URLHAUS),
        }
    )
    service = IngestionService(
        collector_registry=registry,
        threat_upsert_service=_StubThreatUpsertService(),
    )

    summary = service.refresh_all(_FakeSession())

    assert summary.status == "partial_failure"
    assert summary.total_fetched == 1
    assert summary.total_inserted == 1
    assert summary.total_updated == 0
    assert summary.failed_collectors == [FeedSource.URLHAUS]
    assert len(summary.collector_runs) == 2
    assert summary.collector_runs[0].status == FeedRunStatus.SUCCESS
    assert summary.collector_runs[1].status == FeedRunStatus.FAILED
