from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import FeedSource, IndicatorType, Severity, ThreatCategory


class ThreatSortBy(StrEnum):
    RECENCY = "recency"
    RISK_SCORE = "risk_score"


class SortOrder(StrEnum):
    ASC = "asc"
    DESC = "desc"


class ThreatFilterParams(BaseModel):
    source: FeedSource | None = None
    severity: Severity | None = None
    category: ThreatCategory | None = None
    indicator_type: IndicatorType | None = None
    search: str | None = Field(default=None, min_length=1, max_length=200)
    sort_by: ThreatSortBy = ThreatSortBy.RECENCY
    sort_order: SortOrder = SortOrder.DESC
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=25, ge=1, le=100)

    @field_validator("search")
    @classmethod
    def normalize_search(cls, value: str | None) -> str | None:
        if value is None:
            return None

        normalized = value.strip()
        return normalized or None


class ThreatListMeta(BaseModel):
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)
    total_pages: int = Field(ge=0)
    sort_by: ThreatSortBy
    sort_order: SortOrder


class ThreatSourceDistributionItem(BaseModel):
    source: FeedSource
    count: int = Field(ge=0)


class ThreatListStats(BaseModel):
    average_risk_score: int = Field(ge=0, le=100)
    critical_count: int = Field(ge=0)
    source_count: int = Field(ge=0)
    latest_activity_at: datetime | None = None
    latest_activity_source: FeedSource | None = None
    latest_activity_indicator: str | None = None
    latest_ingested_at: datetime | None = None
    source_distribution: list[ThreatSourceDistributionItem] = Field(default_factory=list)


class ThreatListItemRead(BaseModel):
    id: str
    source: FeedSource
    indicator_type: IndicatorType
    indicator_value: str
    title: str
    description: str | None = None
    category: ThreatCategory
    threat_actor: str | None = None
    target_country: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: list[str] = Field(default_factory=list)
    confidence: int
    severity: Severity
    risk_score: int
    reference_url: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ThreatItemRead(ThreatListItemRead):
    raw_payload: dict[str, Any] | list[Any] | None = None


class ThreatListResponse(BaseModel):
    items: list[ThreatListItemRead]
    meta: ThreatListMeta
    stats: ThreatListStats
