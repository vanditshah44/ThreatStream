from __future__ import annotations

from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import Any

from app.models.enums import FeedSource
from app.schemas.normalized_threat import NormalizedThreatItem


class CollectorError(Exception):
    """Raised when a collector cannot fetch or normalize feed data."""


@dataclass(frozen=True, slots=True)
class CollectorResult:
    source: FeedSource
    raw_count: int
    normalized_items: list[NormalizedThreatItem]


class FeedCollector(ABC):
    source: FeedSource

    def collect(self) -> CollectorResult:
        raw_records = self.fetch()
        normalized_items = self.normalize(raw_records)
        return CollectorResult(
            source=self.source,
            raw_count=len(raw_records),
            normalized_items=normalized_items,
        )

    @abstractmethod
    def fetch(self) -> list[dict[str, Any]]:
        """Fetch raw records from the upstream feed."""

    @abstractmethod
    def normalize(self, raw_records: list[dict[str, Any]]) -> list[NormalizedThreatItem]:
        """Normalize raw source records into ThreatStream threat items."""
