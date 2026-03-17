from __future__ import annotations

from sqlalchemy.orm import Session

from app.api.v1.routes.threats import get_threat, list_threats
from app.models.enums import FeedSource, ThreatCategory
from app.schemas.threat import SortOrder, ThreatSortBy


def test_list_threats_route_applies_filters_search_and_sort(
    db_session: Session,
    seeded_threat_data: dict[str, object],
) -> None:
    response = list_threats(
        session=db_session,
        source=FeedSource.OPENPHISH,
        severity=None,
        category=ThreatCategory.PHISHING,
        indicator_type=None,
        search="credential-theft",
        sort_by=ThreatSortBy.RECENCY,
        sort_order=SortOrder.DESC,
        page=1,
        page_size=10,
    )

    assert response.meta.total == 1
    assert response.meta.sort_by == ThreatSortBy.RECENCY
    assert response.meta.sort_order == SortOrder.DESC
    assert len(response.items) == 1
    assert response.items[0].id == "phish-1"
    assert response.stats.latest_activity_source == FeedSource.OPENPHISH
    assert response.stats.source_count == 1
    assert not hasattr(response.items[0], "raw_payload")


def test_get_threat_route_returns_detail_payload(
    db_session: Session,
    seeded_threat_data: dict[str, object],
) -> None:
    response = get_threat("kev-1", db_session)

    assert response.id == "kev-1"
    assert response.source == FeedSource.CISA_KEV
    assert response.raw_payload == {"cveID": "CVE-2026-0001"}
