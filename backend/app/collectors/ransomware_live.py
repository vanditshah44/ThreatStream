from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator
from urllib.parse import urlparse

import httpx

from app.collectors.base import CollectorError, FeedCollector
from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.enums import FeedSource, IndicatorType, ThreatCategory
from app.schemas.normalized_threat import NormalizedThreatItem
from app.scoring import ThreatScoreInput, ThreatScoringEngine
from app.utils.identifiers import generate_stable_id, generate_threat_id
from app.utils.network import sanitize_external_url, validate_feed_source_url
from app.utils.text import join_text_parts, normalize_whitespace


class RansomwareLiveCollector(FeedCollector):
    source = FeedSource.RANSOMWARE_LIVE

    def __init__(
        self,
        *,
        http_client: httpx.Client | None = None,
        scoring_engine: ThreatScoringEngine | None = None,
        recent_victims_url: str | None = None,
        timeout_seconds: float | None = None,
        max_retries: int | None = None,
    ) -> None:
        settings = get_settings()
        self.logger = get_logger(__name__)
        self.http_client = http_client
        self.scoring_engine = scoring_engine or ThreatScoringEngine()
        self.recent_victims_url = validate_feed_source_url(
            recent_victims_url or settings.ransomware_live_recent_victims_url,
            allowed_hosts={"api.ransomware.live"},
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
                    response = client.get(self.recent_victims_url)
                    response.raise_for_status()
                    payload = response.json()

                if isinstance(payload, list):
                    records = [record for record in payload if isinstance(record, dict)]
                elif isinstance(payload, dict):
                    candidate_lists = [
                        payload.get("data"),
                        payload.get("items"),
                        payload.get("victims"),
                        payload.get("events"),
                    ]
                    records = next(
                        (
                            [record for record in candidate if isinstance(record, dict)]
                            for candidate in candidate_lists
                            if isinstance(candidate, list)
                        ),
                        [],
                    )
                else:
                    raise ValueError("Unexpected ransomware.live payload type.")

                self.logger.info(
                    "Fetched %s ransomware.live victim records from %s.",
                    len(records),
                    self.recent_victims_url,
                )
                return records
            except (httpx.HTTPError, ValueError) as exc:
                last_error = exc
                self.logger.warning(
                    "ransomware.live fetch attempt %s/%s failed: %s",
                    attempt,
                    self.max_retries,
                    exc,
                )

        if last_error is not None:
            self.logger.error(
                "ransomware.live collector failed after %s attempts: %s",
                self.max_retries,
                last_error,
            )
        raise CollectorError("Unable to fetch or parse the ransomware.live feed.") from last_error

    def normalize(self, raw_records: list[dict[str, Any]]) -> list[NormalizedThreatItem]:
        normalized_items: list[NormalizedThreatItem] = []

        for raw_record in raw_records:
            record_hint = self._pick_text(raw_record, "url", "victim", "domain", "group") or "<unknown-event>"
            try:
                normalized_items.append(self._normalize_record(raw_record))
            except ValueError as exc:
                self.logger.warning("Skipping malformed ransomware.live record %s: %s", record_hint, exc)

        self.logger.info(
            "Normalized %s/%s ransomware.live records into ThreatStream threat objects.",
            len(normalized_items),
            len(raw_records),
        )
        return normalized_items

    def _normalize_record(self, raw_record: dict[str, Any]) -> NormalizedThreatItem:
        victim_name = self._pick_text(raw_record, "victim", "name", "target")
        threat_actor = self._pick_text(raw_record, "group", "threat_actor", "actor", "gang")
        if not victim_name and not threat_actor:
            raise ValueError("Record does not contain a victim or ransomware group.")

        event_url = self._pick_text(raw_record, "url", "event_url")
        claim_url = self._pick_text(raw_record, "claim_url", "post_url", "leak_url")
        domain = self._normalize_domain(self._pick_text(raw_record, "domain", "website", "site"))
        description = self._build_description(raw_record, victim_name, threat_actor, domain, claim_url)
        title = self._build_title(victim_name, threat_actor, domain)
        tags = self._build_tags(raw_record, threat_actor)
        first_seen = self._pick_datetime(raw_record, "attackdate", "attack_date", "published", "date")
        last_seen = self._pick_datetime(raw_record, "discovered", "updated", "created_at") or first_seen
        confidence = self._calculate_confidence(raw_record, domain, claim_url)
        indicator_type, indicator_value = self._derive_indicator(domain, event_url, victim_name, threat_actor)
        event_identity = event_url or claim_url or f"{victim_name or 'unknown'}:{threat_actor or 'unknown'}:{first_seen or last_seen}"
        threat_id = self._build_event_id(indicator_type, indicator_value, event_identity)

        score = self.scoring_engine.score(
            ThreatScoreInput(
                source=self.source,
                category=ThreatCategory.RANSOMWARE,
                title=title,
                description=description,
                confidence=confidence,
                tags=tags,
                first_seen=first_seen,
                last_seen=last_seen,
                raw_payload=raw_record,
            )
        )

        return NormalizedThreatItem(
            id=threat_id,
            source=self.source,
            indicator_type=indicator_type,
            indicator_value=indicator_value,
            title=title,
            description=description,
            category=ThreatCategory.RANSOMWARE,
            threat_actor=threat_actor,
            target_country=self._pick_text(raw_record, "country", "country_code"),
            first_seen=first_seen,
            last_seen=last_seen,
            tags=tags,
            confidence=confidence,
            severity=score.severity,
            risk_score=score.risk_score,
            reference_url=sanitize_external_url(event_url or claim_url),
            raw_payload=raw_record,
        )

    def _derive_indicator(
        self,
        domain: str | None,
        event_url: str | None,
        victim_name: str | None,
        threat_actor: str | None,
    ) -> tuple[IndicatorType, str]:
        if domain:
            return IndicatorType.DOMAIN, domain

        if event_url:
            return IndicatorType.RANSOMWARE_EVENT, event_url

        if victim_name and threat_actor:
            return IndicatorType.RANSOMWARE_EVENT, f"{victim_name} @ {threat_actor}"
        if victim_name:
            return IndicatorType.RANSOMWARE_EVENT, victim_name
        if threat_actor:
            return IndicatorType.RANSOMWARE_EVENT, threat_actor

        raise ValueError("Unable to derive a ransomware.live indicator.")

    def _build_event_id(
        self,
        indicator_type: IndicatorType,
        indicator_value: str,
        event_identity: str,
    ) -> str:
        if indicator_type == IndicatorType.DOMAIN:
            return generate_stable_id(self.source.value, indicator_type.value, indicator_value, event_identity)

        return generate_threat_id(self.source, indicator_type, event_identity)

    def _build_title(
        self,
        victim_name: str | None,
        threat_actor: str | None,
        domain: str | None,
    ) -> str:
        subject = victim_name or domain or "Unnamed victim"
        if threat_actor:
            return f"{threat_actor.title()} ransomware event for {subject}"
        return f"Ransomware event for {subject}"

    def _build_description(
        self,
        raw_record: dict[str, Any],
        victim_name: str | None,
        threat_actor: str | None,
        domain: str | None,
        claim_url: str | None,
    ) -> str | None:
        sector = self._pick_text(raw_record, "activity", "sector", "industry")
        country = self._pick_text(raw_record, "country", "country_code")
        infostealer_summary = self._summarize_infostealer(raw_record)
        description = self._pick_text(raw_record, "description", "details", "summary")
        extrainfos = self._pick_list(raw_record, "extrainfos", "extra_infos")
        duplicates = self._pick_list(raw_record, "duplicates", "duplicate_urls")
        press = self._pick_text(raw_record, "press", "news", "media")

        extra_summary = None
        if extrainfos:
            extra_summary = "Extra info count: " + str(len(extrainfos)) + "."

        duplicate_summary = None
        if duplicates:
            duplicate_summary = "Duplicate references: " + str(len(duplicates)) + "."

        return join_text_parts(
            [
                normalize_whitespace(description) if description else None,
                f"Victim: {normalize_whitespace(victim_name)}." if victim_name else None,
                f"Group: {normalize_whitespace(threat_actor)}." if threat_actor else None,
                f"Domain: {domain}." if domain else None,
                f"Sector: {normalize_whitespace(sector)}." if sector else None,
                f"Country: {normalize_whitespace(country)}." if country else None,
                f"Leak/claim URL present." if claim_url else None,
                infostealer_summary,
                f"Press reference: {normalize_whitespace(press)}." if press else None,
                extra_summary,
                duplicate_summary,
            ]
        )

    def _build_tags(self, raw_record: dict[str, Any], threat_actor: str | None) -> list[str]:
        tags = {"ransomware.live", "ransomware_event", "double_extortion"}

        sector = self._pick_text(raw_record, "activity", "sector", "industry")
        country = self._pick_text(raw_record, "country", "country_code")
        claim_url = self._pick_text(raw_record, "claim_url", "post_url", "leak_url")
        screenshot = self._pick_text(raw_record, "screenshot", "screen")
        duplicates = self._pick_list(raw_record, "duplicates", "duplicate_urls")
        press = self._pick_text(raw_record, "press", "news", "media")

        if threat_actor:
            tags.add(f"group_{normalize_whitespace(threat_actor).lower().replace(' ', '_')}")
        if sector:
            tags.add(f"sector_{normalize_whitespace(sector).lower().replace(' ', '_')}")
        if country:
            tags.add(f"country_{normalize_whitespace(country).lower()}")
        if self._has_infostealer_signal(raw_record):
            tags.add("infostealer")
        if claim_url:
            tags.add("leak_site")
        if screenshot:
            tags.add("screenshot")
        if press:
            tags.add("press")
        if duplicates:
            tags.add("duplicate_reference")

        return sorted(tags)

    def _calculate_confidence(
        self,
        raw_record: dict[str, Any],
        domain: str | None,
        claim_url: str | None,
    ) -> int:
        confidence = 80

        if domain:
            confidence += 5
        if claim_url:
            confidence += 5
        if self._pick_text(raw_record, "screenshot", "screen"):
            confidence += 4
        if self._has_infostealer_signal(raw_record):
            confidence += 3
        if self._pick_text(raw_record, "press", "news", "media"):
            confidence += 2
        if self._pick_text(raw_record, "description", "details", "summary"):
            confidence += 2
        if self._pick_list(raw_record, "duplicates", "duplicate_urls"):
            confidence += 1

        return max(60, min(96, confidence))

    def _normalize_domain(self, value: str | None) -> str | None:
        if not value:
            return None

        candidate = normalize_whitespace(value).lower().strip("/")
        parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
        candidate = parsed.netloc or parsed.path
        candidate = candidate.strip().strip("/")
        return candidate or None

    def _has_infostealer_signal(self, record: dict[str, Any]) -> bool:
        value = record.get("infostealer") or record.get("stealer")
        if isinstance(value, str):
            return bool(normalize_whitespace(value))
        if isinstance(value, dict):
            for metric_key in ("employees", "employees_url", "thirdparties", "thirdparties_domain", "users", "users_url"):
                metric_value = value.get(metric_key)
                if isinstance(metric_value, (int, float)) and metric_value > 0:
                    return True

            stats = value.get("infostealer_stats")
            if isinstance(stats, dict):
                return any(isinstance(count, (int, float)) and count > 0 for count in stats.values())
        return False

    def _summarize_infostealer(self, record: dict[str, Any]) -> str | None:
        value = record.get("infostealer") or record.get("stealer")
        if isinstance(value, str):
            normalized = normalize_whitespace(value)
            return f"Infostealer reference: {normalized}." if normalized else None

        if not isinstance(value, dict):
            return None

        metrics: list[str] = []
        for key, label in (
            ("employees", "employees"),
            ("users", "users"),
            ("thirdparties", "third parties"),
            ("employees_url", "employee URLs"),
            ("users_url", "user URLs"),
            ("thirdparties_domain", "third-party domains"),
        ):
            metric_value = value.get(key)
            if isinstance(metric_value, (int, float)) and metric_value > 0:
                metrics.append(f"{int(metric_value)} {label}")

        families = value.get("infostealer_stats")
        if isinstance(families, dict):
            family_names = sorted(
                family
                for family, count in families.items()
                if isinstance(family, str) and isinstance(count, (int, float)) and count > 0
            )
            if family_names:
                metrics.append("families: " + ", ".join(family_names[:3]))

        if not metrics:
            return None

        return "Infostealer exposure noted: " + "; ".join(metrics) + "."

    def _pick_text(self, record: dict[str, Any], *keys: str) -> str | None:
        for key in keys:
            value = record.get(key)
            if value is None:
                continue
            if isinstance(value, str):
                normalized = normalize_whitespace(value)
                if normalized:
                    return normalized
            elif isinstance(value, (int, float)):
                return str(value)
        return None

    def _pick_list(self, record: dict[str, Any], *keys: str) -> list[Any]:
        for key in keys:
            value = record.get(key)
            if isinstance(value, list):
                return value
            if value in (None, ""):
                continue
        return []

    def _pick_datetime(self, record: dict[str, Any], *keys: str) -> datetime | None:
        for key in keys:
            value = record.get(key)
            parsed = self._parse_datetime(value)
            if parsed is not None:
                return parsed
        return None

    def _parse_datetime(self, value: Any) -> datetime | None:
        if value is None or value == "":
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        if isinstance(value, str):
            candidate = normalize_whitespace(value).replace("Z", "+00:00")
            for parser in (
                lambda raw: datetime.fromisoformat(raw),
                lambda raw: datetime.strptime(raw, "%Y-%m-%d %H:%M:%S.%f"),
                lambda raw: datetime.strptime(raw, "%Y-%m-%d %H:%M:%S"),
                lambda raw: datetime.strptime(raw, "%Y-%m-%d"),
            ):
                try:
                    parsed = parser(candidate)
                    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
        return None
