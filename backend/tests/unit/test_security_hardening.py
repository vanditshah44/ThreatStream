from __future__ import annotations

import pytest

from app.collectors.openphish import OpenPhishCollector
from app.core.config import Settings
from app.schemas.normalized_threat import NormalizedThreatItem
from app.utils.network import sanitize_external_url


def test_sanitize_external_url_blocks_unsafe_schemes_and_local_targets() -> None:
    assert sanitize_external_url("javascript:alert(1)") is None
    assert sanitize_external_url("http://127.0.0.1/admin") is None
    assert sanitize_external_url("https://example.com/report#fragment") == "https://example.com/report"


def test_normalized_threat_item_sanitizes_reference_url() -> None:
    threat = NormalizedThreatItem(
        id="test-id",
        source="openphish",
        indicator_type="url",
        indicator_value="https://example.test/login",
        title="Example threat",
        category="phishing",
        confidence=80,
        severity="medium",
        risk_score=60,
        reference_url="javascript:alert(1)",
    )

    assert threat.reference_url is None


def test_settings_rejects_wildcard_cors_when_credentials_are_enabled() -> None:
    with pytest.raises(ValueError):
        Settings(cors_origins=["*"])


def test_settings_do_not_append_dev_origins_in_production() -> None:
    settings = Settings(app_env="production", debug=False, cors_origins=["https://app.example.com"])

    assert settings.cors_origins == ["https://app.example.com"]


def test_openphish_collector_rejects_unsafe_feed_url() -> None:
    with pytest.raises(ValueError):
        OpenPhishCollector(feed_url="http://127.0.0.1/phish-feed.txt")
