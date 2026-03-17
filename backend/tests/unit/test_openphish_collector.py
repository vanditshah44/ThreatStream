from __future__ import annotations

from app.collectors.openphish import OpenPhishCollector
from app.models.enums import IndicatorType, ThreatCategory


def test_openphish_parses_and_normalizes_urls() -> None:
    collector = OpenPhishCollector()
    raw_records = collector._parse_feed(
        """
        https://login-microsoft.example/verify
        https://login-microsoft.example/verify
        http://paypal-alert.example/security?session=1
        """
    )

    items = collector.normalize(raw_records)

    assert len(items) == 2
    first = items[0]
    assert first.category == ThreatCategory.PHISHING
    assert first.indicator_type == IndicatorType.URL
    assert first.reference_url is None
    assert first.raw_payload["hostname"] == "login-microsoft.example"
    assert "openphish" in first.tags
    assert "active_phishing" in first.tags


def test_openphish_skips_invalid_urls() -> None:
    collector = OpenPhishCollector()
    raw_records = [{"url": "not-a-url", "line_number": 1, "feed_url": collector.feed_url}]

    items = collector.normalize(raw_records)

    assert items == []
