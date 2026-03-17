from __future__ import annotations

from app.collectors.urlhaus import URLHausCollector
from app.models.enums import IndicatorType, ThreatCategory


def test_urlhaus_normalizes_recent_url_record() -> None:
    collector = URLHausCollector(auth_key="test-key")
    raw_records = [
        {
            "id": 123456,
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/123456/",
            "url": "http://malicious.example/payload.exe",
            "url_status": "online",
            "host": "malicious.example",
            "date_added": "2026-03-16 09:02:05 UTC",
            "threat": "malware_download",
            "blacklists": {"spamhaus_dbl": "listed", "surbl": "not listed"},
            "reporter": "abuse-ch",
            "larted": True,
            "tags": ["stealer", "exe"],
        }
    ]

    items = collector.normalize(raw_records)

    assert len(items) == 1
    item = items[0]
    assert item.category == ThreatCategory.MALWARE
    assert item.indicator_type == IndicatorType.URL
    assert item.indicator_value == "http://malicious.example/payload.exe"
    assert item.reference_url == "https://urlhaus.abuse.ch/url/123456/"
    assert item.raw_payload == raw_records[0]
    assert "malicious_url" in item.tags
    assert "status_online" in item.tags
    assert "spamhaus_dbl_listed" in item.tags
    assert item.confidence >= 85


def test_urlhaus_falls_back_to_domain_indicator_when_url_missing() -> None:
    collector = URLHausCollector(auth_key="test-key")
    raw_records = [
        {
            "id": 654321,
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/654321/",
            "url_status": "offline",
            "host": "fallback.example",
            "date_added": "2026-03-15 10:00:00 UTC",
            "threat": "malware_download",
            "blacklists": {"spamhaus_dbl": "not listed", "surbl": "not listed"},
            "reporter": "abuse-ch",
            "larted": False,
            "tags": None,
        }
    ]

    items = collector.normalize(raw_records)

    assert len(items) == 1
    item = items[0]
    assert item.indicator_type == IndicatorType.DOMAIN
    assert item.indicator_value == "fallback.example"
