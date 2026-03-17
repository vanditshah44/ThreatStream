from __future__ import annotations

from app.collectors.ransomware_live import RansomwareLiveCollector
from app.models.enums import IndicatorType, ThreatCategory


def test_ransomware_live_normalizes_domain_backed_event() -> None:
    collector = RansomwareLiveCollector()
    raw_records = [
        {
            "activity": "Construction",
            "attackdate": "2026-03-16 23:51:29.275000",
            "claim_url": "http://exampleonion.onion/post/123",
            "country": "US",
            "description": "Victim description",
            "discovered": "2026-03-17 00:20:55.084954",
            "domain": "www.nollandtam.com",
            "duplicates": [],
            "extrainfos": [],
            "group": "termite",
            "infostealer": "",
            "press": None,
            "screenshot": "https://images.example/victim.png",
            "url": "https://www.ransomware.live/id/abc",
            "victim": "Noll and Tam Architects",
        }
    ]

    items = collector.normalize(raw_records)

    assert len(items) == 1
    item = items[0]
    assert item.category == ThreatCategory.RANSOMWARE
    assert item.indicator_type == IndicatorType.DOMAIN
    assert item.indicator_value == "www.nollandtam.com"
    assert item.threat_actor == "termite"
    assert item.reference_url == "https://www.ransomware.live/id/abc"
    assert item.raw_payload == raw_records[0]
    assert "ransomware_event" in item.tags
    assert "group_termite" in item.tags


def test_ransomware_live_falls_back_to_ransomware_event_indicator() -> None:
    collector = RansomwareLiveCollector()
    raw_records = [
        {
            "activity": "Healthcare",
            "attackdate": "2026-03-14",
            "country": "DE",
            "description": "Victim posted on leak site.",
            "discovered": "2026-03-15 01:02:03",
            "domain": "",
            "duplicates": [],
            "extrainfos": [],
            "group": "akira",
            "infostealer": "",
            "press": None,
            "screenshot": "",
            "url": "https://www.ransomware.live/id/xyz",
            "victim": "Sample Clinic",
        }
    ]

    items = collector.normalize(raw_records)

    assert len(items) == 1
    item = items[0]
    assert item.indicator_type == IndicatorType.RANSOMWARE_EVENT
    assert item.indicator_value == "https://www.ransomware.live/id/xyz"


def test_ransomware_live_preserves_infostealer_signal_from_nested_object() -> None:
    collector = RansomwareLiveCollector()
    raw_records = [
        {
            "activity": "Legal",
            "attackdate": "2026-03-10",
            "country": "FR",
            "description": "Victim listed on leak site.",
            "discovered": "2026-03-11 08:00:00",
            "domain": "https://examplelaw.fr",
            "group": "kairos",
            "infostealer": {
                "employees": 3,
                "infostealer_stats": {
                    "lumma": 2,
                    "redline": 1,
                },
            },
            "url": "https://www.ransomware.live/id/example",
            "victim": "Example Law",
        }
    ]

    items = collector.normalize(raw_records)

    assert len(items) == 1
    item = items[0]
    assert item.indicator_type == IndicatorType.DOMAIN
    assert item.indicator_value == "examplelaw.fr"
    assert "infostealer" in item.tags
    assert item.description is not None
    assert "Infostealer exposure noted" in item.description
