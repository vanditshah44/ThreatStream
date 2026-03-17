from __future__ import annotations

from dataclasses import dataclass, field

from app.models.enums import FeedSource, ThreatCategory


@dataclass(frozen=True, slots=True)
class RecencyBand:
    max_age_days: int
    points: int


@dataclass(frozen=True, slots=True)
class SeverityThresholds:
    medium_min: int = 40
    high_min: int = 65
    critical_min: int = 85


@dataclass(frozen=True, slots=True)
class ScoringConfig:
    source_reliability: dict[FeedSource, int] = field(
        default_factory=lambda: {
            FeedSource.CISA_KEV: 20,
            FeedSource.URLHAUS: 16,
            FeedSource.OPENPHISH: 15,
            FeedSource.RANSOMWARE_LIVE: 14,
        }
    )
    category_weights: dict[ThreatCategory, int] = field(
        default_factory=lambda: {
            ThreatCategory.VULNERABILITY: 14,
            ThreatCategory.EXPLOITED_VULN: 18,
            ThreatCategory.PHISHING: 12,
            ThreatCategory.MALWARE: 13,
            ThreatCategory.RANSOMWARE: 18,
            ThreatCategory.EXPLOIT: 16,
            ThreatCategory.IOC: 8,
            ThreatCategory.OTHER: 5,
        }
    )
    recency_bands: tuple[RecencyBand, ...] = (
        RecencyBand(max_age_days=1, points=15),
        RecencyBand(max_age_days=3, points=12),
        RecencyBand(max_age_days=7, points=9),
        RecencyBand(max_age_days=14, points=6),
        RecencyBand(max_age_days=30, points=3),
    )
    exploited_bonus: int = 20
    ransomware_bonus: int = 10
    phishing_bonus: int = 10
    keyword_context_bonus_ratio: float = 0.5
    confidence_max_points: int = 10
    critical_tag_weights: dict[str, int] = field(
        default_factory=lambda: {
            "zero day": 12,
            "rce": 10,
            "wormable": 10,
            "command injection": 7,
            "code injection": 7,
            "sql injection": 6,
            "auth bypass": 6,
            "privilege escalation": 6,
            "deserialization": 6,
            "credential theft": 8,
            "c2": 7,
            "command and control": 7,
            "botnet": 7,
            "stealer": 6,
            "loader": 6,
            "data leak": 6,
            "leak site": 6,
            "path traversal": 5,
            "buffer overflow": 4,
            "memory corruption": 4,
            "out of bounds": 4,
            "hash disclosure": 4,
            "spoofing": 3,
        }
    )
    critical_tag_cap: int = 15
    exploited_tag_signals: tuple[str, ...] = (
        "actively exploited",
        "active exploit",
        "known exploited",
        "kev",
        "in the wild",
    )
    exploited_payload_keys: tuple[str, ...] = (
        "exploited",
        "is exploited",
        "is_exploited",
        "actively exploited",
        "actively_exploited",
        "known exploited",
        "known_exploited",
        "known ransomware campaign use",
        "known_ransomware_campaign_use",
        "kev",
        "cisa kev",
        "cisa_kev",
    )
    exploited_value_signals: tuple[str, ...] = (
        "actively exploited",
        "known exploited",
        "exploited in the wild",
        "known ransomware campaign use",
    )
    ransomware_keywords: tuple[str, ...] = (
        "ransomware",
        "double extortion",
        "extortion",
        "leak site",
        "data leak",
    )
    ransomware_positive_tags: tuple[str, ...] = (
        "ransomware",
        "ransomware known",
        "known ransomware campaign use",
    )
    ransomware_negative_tags: tuple[str, ...] = (
        "ransomware use unknown",
        "ransomware unknown",
        "unknown ransomware campaign use",
        "ransomware use no",
        "ransomware use none",
    )
    ransomware_positive_payload_keys: tuple[str, ...] = (
        "known ransomware campaign use",
        "known_ransomware_campaign_use",
    )
    ransomware_positive_values: tuple[str, ...] = (
        "known",
        "true",
        "yes",
    )
    phishing_keywords: tuple[str, ...] = (
        "phishing",
        "credential theft",
        "credential harvest",
        "spoofing",
        "login lure",
        "impersonation",
    )
    severity_thresholds: SeverityThresholds = field(default_factory=SeverityThresholds)


DEFAULT_SCORING_CONFIG = ScoringConfig()
