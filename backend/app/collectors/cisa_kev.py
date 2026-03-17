from __future__ import annotations

from contextlib import contextmanager
from datetime import date, datetime, time, timezone
from typing import Any, Iterator

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
from app.utils.text import extract_first_url, join_text_parts, normalize_whitespace, strip_urls


class CisaKevCatalogPayload(BaseModel):
    title: str | None = None
    catalog_version: str | None = Field(
        default=None,
        validation_alias=AliasChoices("catalogVersion", "catalog_version"),
    )
    date_released: date | datetime | None = Field(
        default=None,
        validation_alias=AliasChoices("dateReleased", "date_released"),
    )
    count: int | None = None
    vulnerabilities: list[dict[str, Any]] = Field(default_factory=list)


class CisaKevRecord(BaseModel):
    cve_id: str = Field(validation_alias=AliasChoices("cveID", "cve_id"))
    vendor_project: str | None = Field(
        default=None,
        validation_alias=AliasChoices("vendorProject", "vendor_project"),
    )
    product: str | None = None
    vulnerability_name: str | None = Field(
        default=None,
        validation_alias=AliasChoices("vulnerabilityName", "vulnerability_name"),
    )
    date_added: date | datetime = Field(validation_alias=AliasChoices("dateAdded", "date_added"))
    short_description: str | None = Field(
        default=None,
        validation_alias=AliasChoices("shortDescription", "short_description"),
    )
    required_action: str | None = Field(
        default=None,
        validation_alias=AliasChoices("requiredAction", "required_action"),
    )
    due_date: date | datetime | None = Field(
        default=None,
        validation_alias=AliasChoices("dueDate", "due_date"),
    )
    known_ransomware_campaign_use: str | None = Field(
        default=None,
        validation_alias=AliasChoices("knownRansomwareCampaignUse", "known_ransomware_campaign_use"),
    )
    notes: str | None = None
    cwes: list[str] = Field(default_factory=list, validation_alias=AliasChoices("cwes", "CWEs"))

    @field_validator("cve_id")
    @classmethod
    def normalize_cve_id(cls, value: str) -> str:
        normalized = normalize_whitespace(value).upper()
        if not normalized.startswith("CVE-"):
            raise ValueError("CISA KEV records must include a valid CVE identifier.")
        return normalized


class CisaKevCollector(FeedCollector):
    source = FeedSource.CISA_KEV

    def __init__(
        self,
        *,
        http_client: httpx.Client | None = None,
        scoring_engine: ThreatScoringEngine | None = None,
        catalog_url: str | None = None,
        catalog_page_url: str | None = None,
        timeout_seconds: float | None = None,
        max_retries: int | None = None,
    ) -> None:
        settings = get_settings()
        self.logger = get_logger(__name__)
        self.http_client = http_client
        self.scoring_engine = scoring_engine or ThreatScoringEngine()
        self.catalog_url = validate_feed_source_url(
            catalog_url or settings.cisa_kev_catalog_url,
            allowed_hosts={"cisa.gov", "www.cisa.gov"},
            allow_unsafe=settings.allow_unsafe_feed_urls,
        )
        self.catalog_page_url = validate_feed_source_url(
            catalog_page_url or settings.cisa_kev_catalog_page_url,
            allowed_hosts={"cisa.gov", "www.cisa.gov"},
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
                "Accept": "application/json",
                "User-Agent": self.user_agent,
            },
            timeout=self.timeout_seconds,
        ) as client:
            yield client

    def fetch(self) -> list[dict[str, Any]]:
        last_error: Exception | None = None

        for attempt in range(1, self.max_retries + 1):
            try:
                with self._client_context() as client:
                    response = client.get(self.catalog_url)
                    response.raise_for_status()
                    payload = response.json()

                catalog = CisaKevCatalogPayload.model_validate(payload)
                if catalog.count is not None and catalog.count != len(catalog.vulnerabilities):
                    self.logger.warning(
                        "CISA KEV record count mismatch: declared=%s actual=%s.",
                        catalog.count,
                        len(catalog.vulnerabilities),
                    )

                self.logger.info(
                    "Fetched %s CISA KEV records from %s.",
                    len(catalog.vulnerabilities),
                    self.catalog_url,
                )
                return catalog.vulnerabilities
            except (httpx.HTTPError, ValueError, ValidationError) as exc:
                last_error = exc
                self.logger.warning(
                    "CISA KEV fetch attempt %s/%s failed: %s",
                    attempt,
                    self.max_retries,
                    exc,
                )

        if last_error is not None:
            self.logger.error(
                "CISA KEV collector failed after %s attempts: %s",
                self.max_retries,
                last_error,
            )
        raise CollectorError("Unable to fetch or parse the CISA KEV feed.") from last_error

    def normalize(self, raw_records: list[dict[str, Any]]) -> list[NormalizedThreatItem]:
        normalized_items: list[NormalizedThreatItem] = []

        for raw_record in raw_records:
            cve_hint = raw_record.get("cveID") or raw_record.get("cve_id") or "<unknown-cve>"

            try:
                record = CisaKevRecord.model_validate(raw_record)
                normalized_items.append(self._normalize_record(record, raw_record))
            except ValidationError as exc:
                self.logger.warning("Skipping malformed CISA KEV record %s: %s", cve_hint, exc)

        self.logger.info(
            "Normalized %s/%s CISA KEV records into ThreatStream threat objects.",
            len(normalized_items),
            len(raw_records),
        )
        return normalized_items

    def _normalize_record(
        self,
        record: CisaKevRecord,
        raw_record: dict[str, Any],
    ) -> NormalizedThreatItem:
        first_seen = self._coerce_datetime(record.date_added)
        tags = self._build_tags(record)
        title = self._build_title(record)
        description = self._build_description(record)
        reference_url = sanitize_external_url(extract_first_url(record.notes)) or self.catalog_page_url
        confidence = 95

        score = self.scoring_engine.score(
            ThreatScoreInput(
                source=self.source,
                category=ThreatCategory.EXPLOITED_VULN,
                title=title,
                description=description,
                confidence=confidence,
                tags=tags,
                first_seen=first_seen,
                last_seen=first_seen,
                raw_payload=raw_record,
            )
        )

        return NormalizedThreatItem(
            id=generate_threat_id(self.source, IndicatorType.CVE, record.cve_id),
            source=self.source,
            indicator_type=IndicatorType.CVE,
            indicator_value=record.cve_id,
            title=title,
            description=description,
            category=ThreatCategory.EXPLOITED_VULN,
            threat_actor=None,
            target_country=None,
            first_seen=first_seen,
            last_seen=first_seen,
            tags=tags,
            confidence=confidence,
            severity=score.severity,
            risk_score=score.risk_score,
            reference_url=reference_url,
            raw_payload=raw_record,
        )

    def _build_title(self, record: CisaKevRecord) -> str:
        if record.vulnerability_name:
            vulnerability_name = normalize_whitespace(record.vulnerability_name)
            if record.cve_id in vulnerability_name.upper():
                return vulnerability_name
            return f"{record.cve_id} {vulnerability_name}"

        subject = join_text_parts([record.vendor_project, record.product])
        if subject:
            return f"{record.cve_id} {subject} Known Exploited Vulnerability"

        return f"{record.cve_id} Known Exploited Vulnerability"

    def _build_description(self, record: CisaKevRecord) -> str | None:
        ransomware_text = None
        if record.known_ransomware_campaign_use:
            ransomware_text = (
                "Known ransomware campaign use: "
                f"{normalize_whitespace(record.known_ransomware_campaign_use)}."
            )

        due_date_text = None
        if record.due_date is not None:
            due_date_text = f"CISA due date: {self._coerce_datetime(record.due_date).date().isoformat()}."

        notes_text = None
        stripped_notes = strip_urls(record.notes)
        if stripped_notes:
            notes_text = f"Notes: {stripped_notes}"

        required_action_text = None
        if record.required_action:
            required_action_text = f"Required action: {normalize_whitespace(record.required_action)}"

        return join_text_parts(
            [
                normalize_whitespace(record.short_description) if record.short_description else None,
                required_action_text,
                ransomware_text,
                due_date_text,
                notes_text,
            ]
        )

    def _build_tags(self, record: CisaKevRecord) -> list[str]:
        tags = {"kev", "cisa_kev", "actively_exploited"}

        text_blob = " ".join(
            part
            for part in [record.vulnerability_name or "", record.short_description or ""]
            if part
        ).lower()

        if "remote code execution" in text_blob or "code execution" in text_blob:
            tags.add("rce")
        if "command injection" in text_blob or "os command injection" in text_blob:
            tags.add("command_injection")
        if "code injection" in text_blob:
            tags.add("code_injection")
        if "privilege escalation" in text_blob:
            tags.add("privilege_escalation")
        if "sql injection" in text_blob:
            tags.add("sql_injection")
        if "authentication bypass" in text_blob or "improper authentication" in text_blob:
            tags.add("auth_bypass")
        if "deserialization" in text_blob:
            tags.add("deserialization")
        if "buffer overflow" in text_blob:
            tags.add("buffer_overflow")
        if "out-of-bounds" in text_blob or "out of bounds" in text_blob:
            tags.add("out_of_bounds")
        if "memory corruption" in text_blob:
            tags.add("memory_corruption")
        if "path traversal" in text_blob or "directory traversal" in text_blob:
            tags.add("path_traversal")
        if "hash disclosure" in text_blob:
            tags.add("hash_disclosure")
        if "spoofing" in text_blob:
            tags.add("spoofing")

        ransomware_signal = normalize_whitespace(record.known_ransomware_campaign_use or "").lower()
        if ransomware_signal == "known":
            tags.update({"ransomware", "ransomware_known"})
        elif ransomware_signal:
            tags.add(f"ransomware_use_{ransomware_signal.replace(' ', '_')}")

        for cwe in record.cwes:
            normalized_cwe = normalize_whitespace(cwe).lower()
            if normalized_cwe:
                tags.add(normalized_cwe)

        return sorted(tags)

    def _coerce_datetime(self, value: date | datetime) -> datetime:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)

        return datetime.combine(value, time.min, tzinfo=timezone.utc)
