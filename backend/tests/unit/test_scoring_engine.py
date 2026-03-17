from __future__ import annotations

from datetime import datetime, timedelta

from app.models.enums import FeedSource, Severity, ThreatCategory
from app.scoring import ThreatScoreInput, ThreatScoringEngine
from app.scoring.engine import has_exploitation_signal, severity_for_score


def test_recent_exploited_kev_item_scores_critical(fixed_now: datetime) -> None:
    engine = ThreatScoringEngine()
    item = ThreatScoreInput(
        source=FeedSource.CISA_KEV,
        category=ThreatCategory.VULNERABILITY,
        title="CISA KEV entry for actively exploited zero-day RCE",
        confidence=95,
        tags=["zero-day", "rce"],
        last_seen=fixed_now - timedelta(hours=6),
        raw_payload={"known_ransomware_campaign_use": True},
    )

    result = engine.score(item, reference_time=fixed_now)

    assert result.risk_score == 99
    assert result.severity == Severity.CRITICAL


def test_recent_phishing_item_scores_high(fixed_now: datetime) -> None:
    engine = ThreatScoringEngine()
    item = ThreatScoreInput(
        source=FeedSource.OPENPHISH,
        category=ThreatCategory.PHISHING,
        title="Credential theft campaign targeting Microsoft 365",
        description="Phishing kit harvesting enterprise logins.",
        confidence=80,
        tags=["credential-theft"],
        last_seen=fixed_now - timedelta(hours=12),
    )

    result = engine.score(item, reference_time=fixed_now)

    assert result.risk_score == 68
    assert result.severity == Severity.HIGH


def test_old_low_confidence_other_item_scores_low(fixed_now: datetime) -> None:
    engine = ThreatScoringEngine()
    item = ThreatScoreInput(
        source=FeedSource.RANSOMWARE_LIVE,
        category=ThreatCategory.OTHER,
        title="Archived mention of suspicious activity",
        confidence=20,
        tags=[],
        last_seen=fixed_now - timedelta(days=60),
    )

    result = engine.score(item, reference_time=fixed_now)

    assert result.risk_score == 21
    assert result.severity == Severity.LOW


def test_exploitation_signal_detected_from_payload_and_tags() -> None:
    item_from_payload = ThreatScoreInput(
        source=FeedSource.URLHAUS,
        category=ThreatCategory.MALWARE,
        title="Malware delivery URL",
        confidence=70,
        raw_payload={"metadata": {"actively_exploited": "true"}},
    )
    item_from_tags = ThreatScoreInput(
        source=FeedSource.URLHAUS,
        category=ThreatCategory.MALWARE,
        title="Malware delivery URL",
        confidence=70,
        tags=["known-exploited"],
    )
    engine = ThreatScoringEngine()

    assert has_exploitation_signal(item_from_payload, engine.config)
    assert has_exploitation_signal(item_from_tags, engine.config)


def test_severity_thresholds_are_deterministic() -> None:
    engine = ThreatScoringEngine()

    assert severity_for_score(39, engine.config) == Severity.LOW
    assert severity_for_score(40, engine.config) == Severity.MEDIUM
    assert severity_for_score(65, engine.config) == Severity.HIGH
    assert severity_for_score(85, engine.config) == Severity.CRITICAL


def test_unknown_ransomware_tag_does_not_add_bonus(fixed_now: datetime) -> None:
    engine = ThreatScoringEngine()
    item_unknown = ThreatScoreInput(
        source=FeedSource.CISA_KEV,
        category=ThreatCategory.EXPLOITED_VULN,
        title="Actively exploited KEV entry",
        confidence=95,
        tags=["kev", "actively_exploited", "ransomware_use_unknown"],
        last_seen=fixed_now - timedelta(days=3),
    )
    item_known = ThreatScoreInput(
        source=FeedSource.CISA_KEV,
        category=ThreatCategory.EXPLOITED_VULN,
        title="Actively exploited KEV entry",
        confidence=95,
        tags=["kev", "actively_exploited", "ransomware_known"],
        last_seen=fixed_now - timedelta(days=3),
    )

    result_unknown = engine.score(item_unknown, reference_time=fixed_now)
    result_known = engine.score(item_known, reference_time=fixed_now)

    assert result_unknown.risk_score == 80
    assert result_known.risk_score == 85
    assert result_unknown.severity == Severity.HIGH
    assert result_known.severity == Severity.CRITICAL
