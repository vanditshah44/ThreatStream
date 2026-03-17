from datetime import date, datetime

from pydantic import BaseModel, Field


from app.models.enums import FeedRunStatus, FeedSource


class DashboardSummary(BaseModel):
    total_indicators: int = Field(ge=0)
    critical_items: int = Field(ge=0)
    phishing_items: int = Field(ge=0)
    ransomware_items: int = Field(ge=0)
    kev_items: int = Field(ge=0)
    last_updated: datetime | None = None


class DashboardChartBucket(BaseModel):
    label: str
    value: int = Field(ge=0)


class DashboardTrendPoint(BaseModel):
    date: date
    value: int = Field(ge=0)


class DashboardCharts(BaseModel):
    severity_distribution: list[DashboardChartBucket]
    source_distribution: list[DashboardChartBucket]
    category_distribution: list[DashboardChartBucket]
    recent_activity_trend: list[DashboardTrendPoint]


class DashboardSourceStatus(BaseModel):
    source: FeedSource
    status: FeedRunStatus | None = None
    indicator_count: int = Field(ge=0)
    last_started_at: datetime | None = None
    last_completed_at: datetime | None = None
    last_success_at: datetime | None = None
    last_error_message: str | None = None
    items_fetched: int = Field(ge=0)
    items_upserted: int = Field(ge=0)
