from __future__ import annotations

from app.collectors.cisa_kev import CisaKevCollector
from app.models.enums import IndicatorType, ThreatCategory


def test_cisa_kev_normalizes_expected_fields(sample_cisa_kev_record: dict[str, object]) -> None:
    collector = CisaKevCollector()
    raw_records = [sample_cisa_kev_record]

    items = collector.normalize(raw_records)

    assert len(items) == 1
    item = items[0]
    assert item.category == ThreatCategory.EXPLOITED_VULN
    assert item.indicator_type == IndicatorType.CVE
    assert item.indicator_value == "CVE-2024-9999"
    assert item.reference_url == "https://example.com/advisory"
    assert item.raw_payload == sample_cisa_kev_record
    assert "actively_exploited" in item.tags
    assert "ransomware_known" in item.tags
    assert "rce" in item.tags


def test_cisa_kev_skips_invalid_records() -> None:
    collector = CisaKevCollector()

    items = collector.normalize([{"vendorProject": "Missing CVE"}])

    assert items == []
