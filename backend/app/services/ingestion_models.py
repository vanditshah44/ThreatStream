from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from app.models.enums import FeedRunStatus, FeedSource


@dataclass(frozen=True, slots=True)
class UpsertResult:
    input_count: int
    deduplicated_count: int
    inserted_count: int
    updated_count: int

    @property
    def processed_count(self) -> int:
        return self.inserted_count + self.updated_count

    @property
    def duplicate_input_count(self) -> int:
        return max(0, self.input_count - self.deduplicated_count)


@dataclass(frozen=True, slots=True)
class CollectorRefreshResult:
    feed_run_id: str | None
    source: FeedSource
    status: FeedRunStatus
    started_at: datetime
    completed_at: datetime
    items_fetched: int
    items_normalized: int
    items_inserted: int
    items_updated: int
    error_message: str | None = None

    @property
    def items_upserted(self) -> int:
        return self.items_inserted + self.items_updated


@dataclass(frozen=True, slots=True)
class IngestionSummary:
    started_at: datetime
    completed_at: datetime
    collector_runs: tuple[CollectorRefreshResult, ...]

    @property
    def total_fetched(self) -> int:
        return sum(run.items_fetched for run in self.collector_runs)

    @property
    def total_normalized(self) -> int:
        return sum(run.items_normalized for run in self.collector_runs)

    @property
    def total_inserted(self) -> int:
        return sum(run.items_inserted for run in self.collector_runs)

    @property
    def total_updated(self) -> int:
        return sum(run.items_updated for run in self.collector_runs)

    @property
    def total_upserted(self) -> int:
        return self.total_inserted + self.total_updated

    @property
    def failed_collectors(self) -> list[FeedSource]:
        return [run.source for run in self.collector_runs if run.status == FeedRunStatus.FAILED]

    @property
    def status(self) -> str:
        if not self.collector_runs:
            return "success"
        if len(self.failed_collectors) == len(self.collector_runs):
            return "failed"
        if self.failed_collectors:
            return "partial_failure"
        return "success"
