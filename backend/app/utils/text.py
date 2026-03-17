from __future__ import annotations

import re
from collections.abc import Iterable

URL_PATTERN = re.compile(r"https?://[^\s]+", re.IGNORECASE)


def normalize_whitespace(value: str) -> str:
    return " ".join(value.split())


def extract_first_url(value: str | None) -> str | None:
    if not value:
        return None

    match = URL_PATTERN.search(value)
    return match.group(0).rstrip(".,);]") if match else None


def strip_urls(value: str | None) -> str | None:
    if not value:
        return None

    stripped = URL_PATTERN.sub("", value)
    normalized = normalize_whitespace(stripped)
    return normalized or None


def join_text_parts(parts: Iterable[str | None]) -> str | None:
    cleaned_parts = [normalize_whitespace(part) for part in parts if part and normalize_whitespace(part)]
    if not cleaned_parts:
        return None
    return " ".join(cleaned_parts)
