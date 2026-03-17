from __future__ import annotations

from collections.abc import Callable, Generator
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

import app.models.feed_run  # noqa: F401
import app.models.threat_item  # noqa: F401
from app.models.base import Base
from app.models.enums import FeedRunStatus, FeedSource, IndicatorType, Severity, ThreatCategory
from app.models.feed_run import FeedRun
from app.models.threat_item import ThreatItem
from app.schemas.normalized_threat import NormalizedThreatItem


@pytest.fixture
def fixed_now() -> datetime:
    return datetime(2026, 3, 17, tzinfo=timezone.utc)


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    engine = create_engine("sqlite+pysqlite:///:memory:", future=True)
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)

    with session_factory() as session:
        yield session

    engine.dispose()


@pytest.fixture
def threat_item_factory(
    fixed_now: datetime,
) -> Callable[..., ThreatItem]:
    def _build(**overrides: object) -> ThreatItem:
        defaults: dict[str, object] = {
            "id": uuid4().hex,
            "source": FeedSource.OPENPHISH,
            "indicator_type": IndicatorType.URL,
            "indicator_value": f"https://example.test/{uuid4().hex[:8]}",
            "title": "Example threat item",
            "description": "Example threat description",
            "category": ThreatCategory.PHISHING,
            "threat_actor": None,
            "target_country": None,
            "first_seen": fixed_now - timedelta(hours=6),
            "last_seen": fixed_now - timedelta(hours=1),
            "tags": ["phishing"],
            "confidence": 75,
            "severity": Severity.HIGH,
            "risk_score": 70,
            "reference_url": "https://example.test/reference",
            "raw_payload": {"fixture": True},
        }
        defaults.update(overrides)
        return ThreatItem(**defaults)

    return _build


@pytest.fixture
def normalized_threat_factory(
    fixed_now: datetime,
) -> Callable[..., NormalizedThreatItem]:
    def _build(**overrides: object) -> NormalizedThreatItem:
        defaults: dict[str, object] = {
            "id": uuid4().hex,
            "source": FeedSource.OPENPHISH,
            "indicator_type": IndicatorType.URL,
            "indicator_value": f"https://example.test/{uuid4().hex[:8]}",
            "title": "Example normalized threat",
            "description": "Example normalized threat description",
            "category": ThreatCategory.PHISHING,
            "threat_actor": None,
            "target_country": None,
            "first_seen": fixed_now - timedelta(hours=6),
            "last_seen": fixed_now - timedelta(hours=1),
            "tags": ["phishing"],
            "confidence": 80,
            "severity": Severity.HIGH,
            "risk_score": 72,
            "reference_url": "https://example.test/reference",
            "raw_payload": {"fixture": True},
        }
        defaults.update(overrides)
        return NormalizedThreatItem(**defaults)

    return _build


@pytest.fixture
def seeded_threat_data(
    db_session: Session,
    fixed_now: datetime,
    threat_item_factory: Callable[..., ThreatItem],
) -> dict[str, object]:
    items = [
        threat_item_factory(
            id="kev-1",
            source=FeedSource.CISA_KEV,
            indicator_type=IndicatorType.CVE,
            indicator_value="CVE-2026-0001",
            title="KEV critical issue",
            description="A critical exploited vulnerability",
            category=ThreatCategory.EXPLOITED_VULN,
            tags=["kev", "zero-day"],
            confidence=95,
            severity=Severity.CRITICAL,
            risk_score=92,
            first_seen=fixed_now - timedelta(days=2),
            last_seen=fixed_now - timedelta(hours=1),
            raw_payload={"cveID": "CVE-2026-0001"},
        ),
        threat_item_factory(
            id="phish-1",
            source=FeedSource.OPENPHISH,
            indicator_type=IndicatorType.URL,
            indicator_value="https://phish.example/login",
            title="Credential phishing page",
            description="Targets corporate accounts",
            category=ThreatCategory.PHISHING,
            tags=["phishing", "credential-theft"],
            confidence=80,
            severity=Severity.HIGH,
            risk_score=71,
            first_seen=fixed_now - timedelta(days=1),
            last_seen=fixed_now - timedelta(minutes=10),
            raw_payload={"url": "https://phish.example/login"},
        ),
        threat_item_factory(
            id="ransom-1",
            source=FeedSource.RANSOMWARE_LIVE,
            indicator_type=IndicatorType.DOMAIN,
            indicator_value="victim.example",
            title="Ransomware event for victim",
            description="Public leak site claim",
            category=ThreatCategory.RANSOMWARE,
            tags=["ransomware_event", "group_lockbit"],
            confidence=88,
            severity=Severity.HIGH,
            risk_score=73,
            first_seen=fixed_now - timedelta(days=4),
            last_seen=fixed_now - timedelta(days=1),
            threat_actor="lockbit",
            raw_payload={"victim": "Victim Org"},
        ),
    ]
    feed_run = FeedRun(
        id="feed-run-1",
        source=FeedSource.RANSOMWARE_LIVE,
        status=FeedRunStatus.SUCCESS,
        started_at=fixed_now - timedelta(minutes=5),
        completed_at=fixed_now - timedelta(minutes=1),
        items_fetched=10,
        items_normalized=10,
        items_upserted=10,
    )

    db_session.add_all([*items, feed_run])
    db_session.commit()

    return {"items": items, "feed_run": feed_run}


@pytest.fixture
def sample_cisa_kev_record() -> dict[str, object]:
    return {
        "cveID": "CVE-2024-9999",
        "vendorProject": "Acme",
        "product": "Secure Gateway",
        "vulnerabilityName": "Remote Code Execution Vulnerability",
        "dateAdded": "2026-03-10",
        "shortDescription": "A remote code execution flaw in a public-facing gateway.",
        "requiredAction": "Apply the vendor patch immediately.",
        "dueDate": "2026-03-31",
        "knownRansomwareCampaignUse": "Known",
        "notes": "Vendor advisory: https://example.com/advisory",
        "cwes": ["CWE-94"],
    }
