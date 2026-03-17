from __future__ import annotations

from sqlalchemy.orm import Session

from app.models.enums import ThreatCategory
from app.schemas.threat import SortOrder, ThreatFilterParams, ThreatSortBy
from app.services.threat_service import ThreatService


def test_list_threats_filters_and_searches_tags(
    db_session: Session,
    seeded_threat_data: dict[str, object],
) -> None:
    service = ThreatService()

    response = service.list_threats(
        db_session,
        ThreatFilterParams(
            category=ThreatCategory.PHISHING,
            search="credential-theft",
            page=1,
            page_size=25,
        ),
    )

    assert response.meta.total == 1
    assert response.meta.total_pages == 1
    assert response.items[0].id == "phish-1"
    assert response.items[0].category == ThreatCategory.PHISHING
    assert response.stats.source_count == 1
    assert response.stats.latest_activity_indicator == "https://phish.example/login"
    assert response.stats.source_distribution[0].count == 1


def test_list_threats_sorts_by_recency(
    db_session: Session,
    seeded_threat_data: dict[str, object],
) -> None:
    service = ThreatService()

    response = service.list_threats(
        db_session,
        ThreatFilterParams(
            sort_by=ThreatSortBy.RECENCY,
            sort_order=SortOrder.DESC,
            page=1,
            page_size=25,
        ),
    )

    assert [item.id for item in response.items] == ["phish-1", "kev-1", "ransom-1"]
    assert response.stats.source_count == 3
    assert response.stats.critical_count == 1
    assert response.stats.latest_activity_indicator == "https://phish.example/login"
    assert response.stats.average_risk_score == 79


def test_get_threat_by_id_returns_detail_payload(
    db_session: Session,
    seeded_threat_data: dict[str, object],
) -> None:
    service = ThreatService()

    response = service.get_threat_by_id(db_session, "kev-1")

    assert response is not None
    assert response.id == "kev-1"
    assert response.risk_score == 92
