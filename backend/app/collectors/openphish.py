from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator
from urllib.parse import urlparse

import httpx

from app.collectors.base import CollectorError, FeedCollector
from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.enums import FeedSource, IndicatorType, ThreatCategory
from app.schemas.normalized_threat import NormalizedThreatItem
from app.scoring import ThreatScoreInput, ThreatScoringEngine
from app.utils.identifiers import generate_threat_id
from app.utils.network import validate_feed_source_url
from app.utils.text import join_text_parts, normalize_whitespace


class OpenPhishCollector(FeedCollector):
    source = FeedSource.OPENPHISH

    def __init__(
        self,
        *,
        http_client: httpx.Client | None = None,
        scoring_engine: ThreatScoringEngine | None = None,
        feed_url: str | None = None,
        timeout_seconds: float | None = None,
        max_retries: int | None = None,
    ) -> None:
        settings = get_settings()
        self.logger = get_logger(__name__)
        self.http_client = http_client
        self.scoring_engine = scoring_engine or ThreatScoringEngine()
        self.feed_url = validate_feed_source_url(
            feed_url or settings.openphish_feed_url,
            allowed_hosts={"openphish.com"},
            allow_unsafe=settings.allow_unsafe_feed_urls,
        )
        self.timeout_seconds = timeout_seconds if timeout_seconds is not None else settings.http_timeout_seconds
        configured_retries = max_retries if max_retries is not None else settings.http_max_retries
        self.max_retries = max(1, configured_retries)
        self.user_agent = settings.http_user_agent

    @contextmanager
    def _client_context(self) -> Iterator[httpx.Client]:
        if self.http_client is not None:
            yield self.http_client
            return

        with httpx.Client(
            follow_redirects=True,
            headers={
                "Accept": "text/plain",
                "User-Agent": self.user_agent,
            },
            timeout=self.timeout_seconds,
        ) as client:
            yield client

    def fetch(self) -> list[dict[str, str | int]]:
        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                with self._client_context() as client:
                    response = client.get(self.feed_url)
                    response.raise_for_status()
                    feed_text = response.text

                records = self._parse_feed(feed_text)
                self.logger.info(
                    "Fetched %s OpenPhish feed entries from %s.",
                    len(records),
                    self.feed_url,
                )
                return records
            except (httpx.HTTPError, ValueError) as exc:
                last_error = exc
                self.logger.warning(
                    "OpenPhish fetch attempt %s/%s failed: %s",
                    attempt,
                    self.max_retries,
                    exc,
                )

        if last_error is not None:
            self.logger.error(
                "OpenPhish collector failed after %s attempts: %s",
                self.max_retries,
                last_error,
            )
        raise CollectorError("Unable to fetch or parse the OpenPhish feed.") from last_error

    def normalize(self, raw_records: list[dict[str, str | int]]) -> list[NormalizedThreatItem]:
        normalized_items: list[NormalizedThreatItem] = []
        deduplicated_records: dict[str, dict[str, str | int]] = {}

        for raw_record in raw_records:
            candidate_url = normalize_whitespace(str(raw_record.get("url", "")))
            if not candidate_url:
                continue
            deduplicated_records[candidate_url] = raw_record

        observed_at = datetime.now(timezone.utc)

        for raw_record in deduplicated_records.values():
            try:
                normalized_items.append(self._normalize_record(raw_record, observed_at))
            except ValueError as exc:
                record_hint = self._build_record_hint(raw_record)
                self.logger.warning("Skipping malformed OpenPhish record %s: %s", record_hint, exc)

        if len(deduplicated_records) != len(raw_records):
            self.logger.info(
                "Deduplicated OpenPhish feed from %s raw entries to %s unique URLs.",
                len(raw_records),
                len(deduplicated_records),
            )

        self.logger.info(
            "Normalized %s/%s OpenPhish records into ThreatStream threat objects.",
            len(normalized_items),
            len(raw_records),
        )
        return normalized_items

    def _parse_feed(self, feed_text: str) -> list[dict[str, str | int]]:
        if not feed_text.strip():
            return []

        records: list[dict[str, str | int]] = []
        for line_number, raw_line in enumerate(feed_text.splitlines(), start=1):
            candidate = normalize_whitespace(raw_line)
            if not candidate or candidate.startswith("#"):
                continue

            records.append(
                {
                    "url": candidate,
                    "line_number": line_number,
                    "feed_url": self.feed_url,
                }
            )

        return records

    def _normalize_record(
        self,
        raw_record: dict[str, str | int],
        observed_at: datetime,
    ) -> NormalizedThreatItem:
        candidate_url = normalize_whitespace(str(raw_record.get("url", "")))
        parsed_url = urlparse(candidate_url)

        if not parsed_url.scheme or not parsed_url.netloc:
            raise ValueError("OpenPhish record does not contain a valid URL.")

        hostname = (parsed_url.hostname or "").lower()
        if not hostname:
            raise ValueError("OpenPhish URL does not contain a hostname.")

        tags = self._build_tags(hostname)
        title = f"OpenPhish Phishing URL for {hostname}"
        description = join_text_parts(
            [
                "OpenPhish community feed identified this URL as an active phishing indicator.",
                f"Host: {hostname}.",
                f"Path: {parsed_url.path}." if parsed_url.path else None,
            ]
        )
        confidence = self._calculate_confidence(candidate_url)

        score = self.scoring_engine.score(
            ThreatScoreInput(
                source=self.source,
                category=ThreatCategory.PHISHING,
                title=title,
                description=description,
                confidence=confidence,
                tags=tags,
                first_seen=observed_at,
                last_seen=observed_at,
                raw_payload=raw_record,
            )
        )

        return NormalizedThreatItem(
            id=generate_threat_id(self.source, IndicatorType.URL, candidate_url),
            source=self.source,
            indicator_type=IndicatorType.URL,
            indicator_value=candidate_url,
            title=title,
            description=description,
            category=ThreatCategory.PHISHING,
            threat_actor=None,
            target_country=None,
            first_seen=observed_at,
            last_seen=observed_at,
            tags=tags,
            confidence=confidence,
            severity=score.severity,
            risk_score=score.risk_score,
            reference_url=None,
            raw_payload={
                **raw_record,
                "hostname": hostname,
            },
        )

    def _build_record_hint(self, raw_record: dict[str, str | int]) -> str:
        candidate_url = normalize_whitespace(str(raw_record.get("url", "")))
        parsed_url = urlparse(candidate_url)
        hostname = (parsed_url.hostname or "").lower()
        if hostname:
            return hostname

        line_number = raw_record.get("line_number")
        if isinstance(line_number, int):
            return f"line:{line_number}"

        return "<unknown-openphish-url>"

    def _build_tags(self, hostname: str) -> list[str]:
        tags = {"openphish", "phishing_url", "active_phishing"}

        parts = hostname.split(".")
        if len(parts) >= 2:
            tags.add(f"tld_{parts[-1]}")

        popular_brands = {
            "microsoft",
            "office365",
            "apple",
            "google",
            "paypal",
            "amazon",
            "facebook",
            "instagram",
            "netflix",
            "dhl",
            "adobe",
        }
        for brand in popular_brands:
            if brand in hostname:
                tags.add(f"brand_{brand}")

        return sorted(tags)

    def _calculate_confidence(self, url: str) -> int:
        parsed = urlparse(url)
        confidence = 78

        if parsed.scheme == "https":
            confidence += 2
        else:
            confidence += 5

        if parsed.query:
            confidence += 3
        if parsed.username or parsed.password:
            confidence += 5
        if parsed.port is not None:
            confidence += 2

        return max(60, min(90, confidence))
