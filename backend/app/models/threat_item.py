from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import CheckConstraint, DateTime, Enum, Index, Integer, JSON, String, Text
from sqlalchemy.ext.mutable import MutableList
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin
from app.models.enums import FeedSource, IndicatorType, Severity, ThreatCategory

PORTABLE_ENUM_OPTIONS: dict[str, object] = {
    "native_enum": False,
    "validate_strings": True,
    "create_constraint": True,
}


class ThreatItem(TimestampMixin, Base):
    __tablename__ = "threat_items"
    __table_args__ = (
        CheckConstraint("confidence >= 0 AND confidence <= 100", name="confidence_range"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="risk_score_range"),
        Index(
            "ix_threat_items_filter_dimensions",
            "source",
            "severity",
            "category",
            "indicator_type",
        ),
        Index(
            "ix_threat_items_indicator_lookup",
            "indicator_type",
            "indicator_value",
        ),
        Index(
            "ix_threat_items_recent_activity",
            "last_seen",
            "created_at",
        ),
        Index(
            "ix_threat_items_priority",
            "risk_score",
            "last_seen",
        ),
    )

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source: Mapped[FeedSource] = mapped_column(
        Enum(FeedSource, name="threat_source_enum", **PORTABLE_ENUM_OPTIONS),
        nullable=False,
        index=True,
    )
    indicator_type: Mapped[IndicatorType] = mapped_column(
        Enum(IndicatorType, name="indicator_type_enum", **PORTABLE_ENUM_OPTIONS),
        nullable=False,
        index=True,
    )
    indicator_value: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[ThreatCategory] = mapped_column(
        Enum(ThreatCategory, name="threat_category_enum", **PORTABLE_ENUM_OPTIONS),
        nullable=False,
        index=True,
    )
    threat_actor: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    target_country: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    tags: Mapped[list[str]] = mapped_column(MutableList.as_mutable(JSON), nullable=False, default=list)
    confidence: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity, name="severity_enum", **PORTABLE_ENUM_OPTIONS),
        nullable=False,
        default=Severity.MEDIUM,
        index=True,
    )
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=50, index=True)
    reference_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    raw_payload: Mapped[dict[str, Any] | list[Any] | None] = mapped_column(JSON, nullable=True)
