from __future__ import annotations

from hashlib import sha256

from app.models.enums import FeedSource, IndicatorType


def generate_stable_id(*parts: str) -> str:
    normalized_parts = [part.strip().lower() for part in parts if part and part.strip()]
    digest_input = ":".join(normalized_parts)
    return sha256(digest_input.encode("utf-8")).hexdigest()


def generate_threat_id(source: FeedSource, indicator_type: IndicatorType, indicator_value: str) -> str:
    return generate_stable_id(source.value, indicator_type.value, indicator_value)
