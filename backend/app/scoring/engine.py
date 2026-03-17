from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from app.models.enums import FeedSource, Severity, ThreatCategory
from app.scoring.config import DEFAULT_SCORING_CONFIG, ScoringConfig


class ScorableThreatItem(Protocol):
    source: FeedSource
    category: ThreatCategory
    title: str
    description: str | None
    confidence: int
    tags: list[str]
    first_seen: datetime | None
    last_seen: datetime | None
    raw_payload: dict[str, Any] | list[Any] | None


@dataclass(frozen=True, slots=True)
class ThreatScoreInput:
    source: FeedSource
    category: ThreatCategory
    title: str
    description: str | None = None
    confidence: int = 50
    tags: list[str] = field(default_factory=list)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    raw_payload: dict[str, Any] | list[Any] | None = None


@dataclass(frozen=True, slots=True)
class ScoreContribution:
    factor: str
    points: int
    reason: str


@dataclass(frozen=True, slots=True)
class ThreatScoreResult:
    risk_score: int
    severity: Severity
    contributions: tuple[ScoreContribution, ...]


class ThreatScoringEngine:
    def __init__(self, config: ScoringConfig | None = None) -> None:
        self.config = config or DEFAULT_SCORING_CONFIG

    def score(
        self,
        item: ScorableThreatItem,
        reference_time: datetime | None = None,
    ) -> ThreatScoreResult:
        evaluated_at = ensure_aware_datetime(reference_time or datetime.now(timezone.utc))

        contributions = (
            ScoreContribution(
                factor="source_reliability",
                points=score_source_reliability(item.source, self.config),
                reason="Curated feeds and higher-fidelity sources get more base weight.",
            ),
            ScoreContribution(
                factor="category",
                points=score_category(item.category, self.config),
                reason="Threat categories carry different operational impact.",
            ),
            ScoreContribution(
                factor="recency",
                points=score_recency(item, evaluated_at, self.config),
                reason="More recent threats are usually more actionable.",
            ),
            ScoreContribution(
                factor="exploited_status",
                points=score_exploited_status(item, self.config),
                reason="Active exploitation is a strong indicator of near-term risk.",
            ),
            ScoreContribution(
                factor="ransomware_relevance",
                points=score_ransomware_relevance(item, self.config),
                reason="Ransomware-linked activity usually has high business impact.",
            ),
            ScoreContribution(
                factor="phishing_relevance",
                points=score_phishing_relevance(item, self.config),
                reason="Phishing directly maps to common analyst triage workflows.",
            ),
            ScoreContribution(
                factor="confidence",
                points=score_confidence(item.confidence, self.config),
                reason="Higher-confidence sightings should outrank ambiguous ones.",
            ),
            ScoreContribution(
                factor="critical_tags",
                points=score_critical_tags(item.tags, self.config),
                reason="Certain tags correlate with especially dangerous behavior.",
            ),
        )

        total_score = clamp(sum(contribution.points for contribution in contributions))
        severity = severity_for_score(total_score, self.config)

        return ThreatScoreResult(
            risk_score=total_score,
            severity=severity,
            contributions=contributions,
        )


def score_threat(
    item: ScorableThreatItem,
    config: ScoringConfig | None = None,
    reference_time: datetime | None = None,
) -> ThreatScoreResult:
    engine = ThreatScoringEngine(config=config)
    return engine.score(item, reference_time=reference_time)


def score_source_reliability(source: FeedSource, config: ScoringConfig) -> int:
    return config.source_reliability.get(source, 0)


def score_category(category: ThreatCategory, config: ScoringConfig) -> int:
    return config.category_weights.get(category, 0)


def score_recency(
    item: ScorableThreatItem,
    reference_time: datetime,
    config: ScoringConfig,
) -> int:
    seen_at = item.last_seen or item.first_seen
    if seen_at is None:
        return 0

    age_in_days = max(0.0, (reference_time - ensure_aware_datetime(seen_at)).total_seconds() / 86400)
    for band in config.recency_bands:
        if age_in_days <= band.max_age_days:
            return band.points

    return 0


def score_exploited_status(item: ScorableThreatItem, config: ScoringConfig) -> int:
    return config.exploited_bonus if has_exploitation_signal(item, config) else 0


def score_ransomware_relevance(item: ScorableThreatItem, config: ScoringConfig) -> int:
    if item.category == ThreatCategory.RANSOMWARE:
        return config.ransomware_bonus
    if has_positive_ransomware_signal(item, config):
        return round(config.ransomware_bonus * config.keyword_context_bonus_ratio)
    return 0


def score_phishing_relevance(item: ScorableThreatItem, config: ScoringConfig) -> int:
    if item.category == ThreatCategory.PHISHING:
        return config.phishing_bonus
    if matches_keywords(item, config.phishing_keywords):
        return round(config.phishing_bonus * config.keyword_context_bonus_ratio)
    return 0


def score_confidence(confidence: int, config: ScoringConfig) -> int:
    bounded_confidence = clamp(confidence)
    return round((bounded_confidence / 100) * config.confidence_max_points)


def score_critical_tags(tags: list[str], config: ScoringConfig) -> int:
    normalized_tags = {normalize_token(tag) for tag in tags}
    tag_points = sum(
        weight
        for tag, weight in config.critical_tag_weights.items()
        if normalize_token(tag) in normalized_tags
    )
    return min(tag_points, config.critical_tag_cap)


def severity_for_score(score: int, config: ScoringConfig) -> Severity:
    thresholds = config.severity_thresholds
    if score >= thresholds.critical_min:
        return Severity.CRITICAL
    if score >= thresholds.high_min:
        return Severity.HIGH
    if score >= thresholds.medium_min:
        return Severity.MEDIUM
    return Severity.LOW


def has_exploitation_signal(item: ScorableThreatItem, config: ScoringConfig) -> bool:
    normalized_tags = {normalize_token(tag) for tag in item.tags}
    exploited_tags = {normalize_token(tag) for tag in config.exploited_tag_signals}

    if normalized_tags.intersection(exploited_tags):
        return True

    if contains_signal_text(item.title, config.exploited_value_signals):
        return True

    if contains_signal_text(item.description, config.exploited_value_signals):
        return True

    return payload_has_exploitation_signal(item.raw_payload, config)


def payload_has_exploitation_signal(
    payload: dict[str, Any] | list[Any] | None,
    config: ScoringConfig,
) -> bool:
    if payload is None:
        return False

    normalized_keys = {normalize_token(key) for key in config.exploited_payload_keys}
    normalized_values = {normalize_token(value) for value in config.exploited_value_signals}
    return search_payload_for_signal(payload, normalized_keys, normalized_values)


def search_payload_for_signal(
    payload: dict[str, Any] | list[Any],
    target_keys: set[str],
    target_values: set[str],
) -> bool:
    if isinstance(payload, dict):
        for key, value in payload.items():
            normalized_key = normalize_token(str(key))
            if normalized_key in target_keys and is_truthy_signal(value, target_values):
                return True

            if isinstance(value, dict | list) and search_payload_for_signal(value, target_keys, target_values):
                return True
    elif isinstance(payload, list):
        for value in payload:
            if isinstance(value, dict | list) and search_payload_for_signal(value, target_keys, target_values):
                return True
            if isinstance(value, str) and contains_signal_text(value, target_values):
                return True

    return False


def matches_keywords(item: ScorableThreatItem, keywords: tuple[str, ...]) -> bool:
    normalized_keywords = {normalize_token(keyword) for keyword in keywords}

    text_candidates = [item.title, item.description or "", *item.tags]
    for candidate in text_candidates:
        normalized_candidate = normalize_token(candidate)
        if any(keyword in normalized_candidate for keyword in normalized_keywords):
            return True

    return False


def contains_signal_text(value: str | None, signals: tuple[str, ...] | set[str]) -> bool:
    if not value:
        return False

    normalized_value = normalize_token(value)
    return any(normalize_token(signal) in normalized_value for signal in signals)


def has_positive_ransomware_signal(item: ScorableThreatItem, config: ScoringConfig) -> bool:
    normalized_tags = {normalize_token(tag) for tag in item.tags}
    positive_tags = {normalize_token(tag) for tag in config.ransomware_positive_tags}
    negative_tags = {normalize_token(tag) for tag in config.ransomware_negative_tags}

    if normalized_tags.intersection(positive_tags):
        return True

    if payload_has_positive_ransomware_signal(item.raw_payload, config):
        return True

    if normalized_tags.intersection(negative_tags):
        return False

    title_or_description = " ".join(part for part in [item.title, item.description or ""] if part)
    if contains_signal_text(title_or_description, config.ransomware_keywords):
        return True

    return False


def payload_has_positive_ransomware_signal(
    payload: dict[str, Any] | list[Any] | None,
    config: ScoringConfig,
) -> bool:
    if payload is None:
        return False

    normalized_keys = {normalize_token(key) for key in config.ransomware_positive_payload_keys}
    normalized_values = {normalize_token(value) for value in config.ransomware_positive_values}
    return search_payload_for_signal(payload, normalized_keys, normalized_values)


def is_truthy_signal(value: Any, target_values: set[str]) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return value > 0
    if isinstance(value, str):
        normalized_value = normalize_token(value)
        if normalized_value in {"true", "yes", "y", "1", "present"}:
            return True
        return normalized_value in target_values
    return False


def normalize_token(value: str) -> str:
    collapsed = value.strip().lower().replace("_", " ").replace("-", " ")
    return " ".join(collapsed.split())


def clamp(value: int, minimum: int = 0, maximum: int = 100) -> int:
    return max(minimum, min(maximum, value))


def ensure_aware_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
