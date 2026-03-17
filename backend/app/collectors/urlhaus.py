from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Iterator
from urllib.parse import urlparse

import httpx
from pydantic import AliasChoices, BaseModel, Field, ValidationError, field_validator

from app.collectors.base import CollectorError, FeedCollector
from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.enums import FeedSource, IndicatorType, ThreatCategory
from app.schemas.normalized_threat import NormalizedThreatItem
from app.scoring import ThreatScoreInput, ThreatScoringEngine
from app.utils.identifiers import generate_threat_id
from app.utils.network import sanitize_external_url, validate_feed_source_url
from app.utils.text import join_text_parts, normalize_whitespace


class URLHausRecentResponse(BaseModel):
    query_status: str
    urls: list[dict[str, Any]] = Field(default_factory=list)


class URLHausBlacklists(BaseModel):
    spamhaus_dbl: str | None = Field(default=None, validation_alias=AliasChoices("spamhaus_dbl"))
    surbl: str | None = None


class URLHausRecentRecord(BaseModel):
    id: str = Field(validation_alias=AliasChoices("id", "url_id"))
    urlhaus_reference: str | None = None
    url: str | None = None
    url_status: str | None = None
    host: str | None = None
    date_added: datetime = Field(validation_alias=AliasChoices("date_added", "dateadded"))
    threat: str | None = None
    blacklists: URLHausBlacklists | None = None
    reporter: str | None = None
    larted: bool | str | int | None = None
    tags: list[str] = Field(default_factory=list)

    @field_validator("date_added", mode="before")
    @classmethod
    def parse_urlhaus_datetime(cls, value: object) -> datetime:
        if isinstance(value, datetime):
            return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        if isinstance(value, str):
            normalized = normalize_whitespace(value)
            for fmt in ("%Y-%m-%d %H:%M:%S %Z", "%Y-%m-%d %H:%M:%S"):
                try:
                    parsed = datetime.strptime(normalized, fmt)
                    return parsed.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        raise ValueError("URLHaus date_added has an unsupported format.")

    @field_validator("id", mode="before")
    @classmethod
    def normalize_id(cls, value: object) -> str:
        if isinstance(value, int | str):
            normalized = str(value).strip()
            if normalized:
                return normalized
        raise ValueError("URLHaus id must be a non-empty string or integer.")

    @field_validator("tags", mode="before")
    @classmethod
    def normalize_tags(cls, value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, list):
            return [str(tag) for tag in value if tag is not None]
        raise ValueError("URLHaus tags must be a list or null.")


class URLHausCollector(FeedCollector):
    source = FeedSource.URLHAUS

    def __init__(
        self,
        *,
        http_client: httpx.Client | None = None,
        scoring_engine: ThreatScoringEngine | None = None,
        api_base_url: str | None = None,
        auth_key: str | None = None,
        recent_limit: int | None = None,
        timeout_seconds: float | None = None,
        max_retries: int | None = None,
    ) -> None:
        settings = get_settings()
        self.logger = get_logger(__name__)
        self.http_client = http_client
        self.scoring_engine = scoring_engine or ThreatScoringEngine()
        self.api_base_url = validate_feed_source_url(
            (api_base_url or settings.urlhaus_api_base_url).rstrip("/"),
            allowed_hosts={"urlhaus-api.abuse.ch"},
            allow_unsafe=settings.allow_unsafe_feed_urls,
        ).rstrip("/")
        self.auth_key = auth_key if auth_key is not None else settings.urlhaus_auth_key
        configured_limit = recent_limit if recent_limit is not None else settings.urlhaus_recent_limit
        self.recent_limit = max(1, min(1000, configured_limit))
        self.timeout_seconds = timeout_seconds if timeout_seconds is not None else settings.http_timeout_seconds
        configured_retries = max_retries if max_retries is not None else settings.http_max_retries
        self.max_retries = max(1, configured_retries)
        self.user_agent = settings.http_user_agent

    @contextmanager
    def _client_context(self) -> Iterator[httpx.Client]:
        if self.http_client is not None:
            yield self.http_client
            return

        headers = {
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }
        if self.auth_key:
            headers["Auth-Key"] = self.auth_key

        with httpx.Client(
            follow_redirects=True,
            headers=headers,
            timeout=self.timeout_seconds,
        ) as client:
            yield client

    def fetch(self) -> list[dict[str, Any]]:
        if not self.auth_key:
            message = (
                "URLHaus collector requires URLHAUS_AUTH_KEY because the official recent URLs API "
                "expects an Auth-Key header."
            )
            self.logger.error(message)
            raise CollectorError(message)

        endpoint = f"{self.api_base_url}/v1/urls/recent/limit/{self.recent_limit}/"
        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                with self._client_context() as client:
                    response = client.get(endpoint, headers={"Auth-Key": self.auth_key})
                    response.raise_for_status()
                    payload = response.json()

                parsed_response = URLHausRecentResponse.model_validate(payload)
                if parsed_response.query_status == "no_results":
                    self.logger.info("URLHaus returned no recent results.")
                    return []
                if parsed_response.query_status != "ok":
                    raise CollectorError(
                        f"Unexpected URLHaus query status '{parsed_response.query_status}'."
                    )

                self.logger.info(
                    "Fetched %s URLHaus records from %s.",
                    len(parsed_response.urls),
                    endpoint,
                )
                return parsed_response.urls
            except (httpx.HTTPError, ValueError, ValidationError, CollectorError) as exc:
                last_error = exc
                self.logger.warning(
                    "URLHaus fetch attempt %s/%s failed: %s",
                    attempt,
                    self.max_retries,
                    exc,
                )

        if last_error is not None:
            self.logger.error(
                "URLHaus collector failed after %s attempts: %s",
                self.max_retries,
                last_error,
            )
        raise CollectorError("Unable to fetch or parse the URLHaus feed.") from last_error

    def normalize(self, raw_records: list[dict[str, Any]]) -> list[NormalizedThreatItem]:
        normalized_items: list[NormalizedThreatItem] = []

        for raw_record in raw_records:
            record_hint = raw_record.get("id") or raw_record.get("url") or "<unknown-urlhaus-record>"
            try:
                record = URLHausRecentRecord.model_validate(raw_record)
                normalized_items.append(self._normalize_record(record, raw_record))
            except ValidationError as exc:
                self.logger.warning("Skipping malformed URLHaus record %s: %s", record_hint, exc)

        self.logger.info(
            "Normalized %s/%s URLHaus records into ThreatStream threat objects.",
            len(normalized_items),
            len(raw_records),
        )
        return normalized_items

    def _normalize_record(
        self,
        record: URLHausRecentRecord,
        raw_record: dict[str, Any],
    ) -> NormalizedThreatItem:
        indicator_type, indicator_value = self._derive_indicator(record)
        tags = self._build_tags(record)
        title = self._build_title(record, indicator_value)
        description = self._build_description(record)
        confidence = self._calculate_confidence(record)

        score = self.scoring_engine.score(
            ThreatScoreInput(
                source=self.source,
                category=ThreatCategory.MALWARE,
                title=title,
                description=description,
                confidence=confidence,
                tags=tags,
                first_seen=record.date_added,
                last_seen=record.date_added,
                raw_payload=raw_record,
            )
        )

        return NormalizedThreatItem(
            id=generate_threat_id(self.source, indicator_type, indicator_value),
            source=self.source,
            indicator_type=indicator_type,
            indicator_value=indicator_value,
            title=title,
            description=description,
            category=ThreatCategory.MALWARE,
            threat_actor=None,
            target_country=None,
            first_seen=record.date_added,
            last_seen=record.date_added,
            tags=tags,
            confidence=confidence,
            severity=score.severity,
            risk_score=score.risk_score,
            reference_url=sanitize_external_url(record.urlhaus_reference),
            raw_payload=raw_record,
        )

    def _derive_indicator(self, record: URLHausRecentRecord) -> tuple[IndicatorType, str]:
        candidate_url = normalize_whitespace(record.url or "")
        if candidate_url:
            parsed_url = urlparse(candidate_url)
            if parsed_url.scheme and parsed_url.netloc:
                return IndicatorType.URL, candidate_url

        host = normalize_whitespace(record.host or "")
        if host:
            return IndicatorType.DOMAIN, host.lower()

        raise ValueError(f"URLHaus record {record.id} does not contain a usable indicator.")

    def _build_tags(self, record: URLHausRecentRecord) -> list[str]:
        tags = {"urlhaus", "malicious_url"}

        if record.url_status:
            tags.add(f"status_{normalize_whitespace(record.url_status).lower()}")
            if normalize_whitespace(record.url_status).lower() == "online":
                tags.add("online")

        threat = normalize_whitespace(record.threat or "").lower()
        if threat:
            tags.add(threat.replace(" ", "_"))
            if "malware" in threat:
                tags.add("malware")

        for tag in record.tags:
            normalized_tag = normalize_whitespace(tag).lower()
            if normalized_tag:
                tags.add(normalized_tag.replace(" ", "_"))

        if record.blacklists:
            if self._is_listed(record.blacklists.spamhaus_dbl):
                tags.add("spamhaus_dbl_listed")
            if self._is_listed(record.blacklists.surbl):
                tags.add("surbl_listed")

        if self._is_true(record.larted):
            tags.add("larted")

        return sorted(tags)

    def _build_title(self, record: URLHausRecentRecord, indicator_value: str) -> str:
        threat_text = normalize_whitespace(record.threat or "").lower()
        if threat_text:
            human_threat = threat_text.replace("_", " ").title()
            return f"URLHaus {human_threat} Indicator for {indicator_value}"
        return f"URLHaus Malicious URL Indicator for {indicator_value}"

    def _build_description(self, record: URLHausRecentRecord) -> str | None:
        blacklist_text = None
        if record.blacklists:
            blacklist_parts = []
            if record.blacklists.spamhaus_dbl:
                blacklist_parts.append(f"Spamhaus DBL: {normalize_whitespace(record.blacklists.spamhaus_dbl)}")
            if record.blacklists.surbl:
                blacklist_parts.append(f"SURBL: {normalize_whitespace(record.blacklists.surbl)}")
            blacklist_text = "; ".join(blacklist_parts) if blacklist_parts else None

        tag_text = ", ".join(sorted({normalize_whitespace(tag) for tag in record.tags if normalize_whitespace(tag)}))
        if tag_text:
            tag_text = f"Tags: {tag_text}"

        larted_text = None
        if record.larted is not None:
            larted_text = "LARTed: yes." if self._is_true(record.larted) else "LARTed: no."

        return join_text_parts(
            [
                "URLHaus flagged this indicator as malicious infrastructure associated with malware delivery.",
                f"Status: {normalize_whitespace(record.url_status)}." if record.url_status else None,
                f"Host: {normalize_whitespace(record.host)}." if record.host else None,
                f"Threat: {normalize_whitespace(record.threat)}." if record.threat else None,
                f"Reporter: {normalize_whitespace(record.reporter)}." if record.reporter else None,
                f"{blacklist_text}." if blacklist_text else None,
                tag_text,
                larted_text,
            ]
        )

    def _calculate_confidence(self, record: URLHausRecentRecord) -> int:
        confidence = 70

        status = normalize_whitespace(record.url_status or "").lower()
        if status == "online":
            confidence += 15
        elif status in {"offline", "dead"}:
            confidence += 5
        elif status:
            confidence += 10

        if self._is_listed(record.blacklists.spamhaus_dbl if record.blacklists else None):
            confidence += 5
        if self._is_listed(record.blacklists.surbl if record.blacklists else None):
            confidence += 5
        if record.tags:
            confidence += min(5, len(record.tags))

        parsed_url = urlparse(record.url or "")
        hostname = parsed_url.hostname or (record.host or "")
        if hostname and self._is_ip_address(hostname):
            confidence -= 5

        return max(35, min(95, confidence))

    def _is_listed(self, value: str | None) -> bool:
        normalized = normalize_whitespace(value or "").lower()
        return normalized in {"listed", "yes", "true"}

    def _is_true(self, value: bool | str | int | None) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return value > 0
        if isinstance(value, str):
            return normalize_whitespace(value).lower() in {"1", "true", "yes", "y"}
        return False

    def _is_ip_address(self, value: str) -> bool:
        try:
            ip_address(value)
        except ValueError:
            return False
        return True
