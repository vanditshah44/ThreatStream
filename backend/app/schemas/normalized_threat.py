from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.enums import FeedSource, IndicatorType, Severity, ThreatCategory
from app.utils.network import sanitize_external_url


class NormalizedThreatItem(BaseModel):
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
    confidence: int = Field(ge=0, le=100)
    severity: Severity
    risk_score: int = Field(ge=0, le=100)
    reference_url: str | None = None
    raw_payload: dict[str, Any] | list[Any] | None = None

    model_config = ConfigDict(extra="forbid")

    @field_validator("reference_url", mode="before")
    @classmethod
    def validate_reference_url(cls, value: object) -> str | None:
        if value in (None, ""):
            return None
        if not isinstance(value, str):
            raise TypeError("reference_url must be a string.")

        return sanitize_external_url(value)
