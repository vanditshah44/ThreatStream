from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Enum, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin
from app.models.enums import FeedRunStatus, FeedSource


class FeedRun(TimestampMixin, Base):
    __tablename__ = "feed_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    source: Mapped[FeedSource] = mapped_column(
        Enum(FeedSource, name="feed_source_enum"),
        nullable=False,
        index=True,
    )
    status: Mapped[FeedRunStatus] = mapped_column(
        Enum(FeedRunStatus, name="feed_run_status_enum"),
        nullable=False,
        default=FeedRunStatus.RUNNING,
        index=True,
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    items_fetched: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    items_normalized: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    items_upserted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

