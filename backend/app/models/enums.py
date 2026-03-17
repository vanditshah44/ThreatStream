from enum import StrEnum


class FeedSource(StrEnum):
    CISA_KEV = "cisa_kev"
    URLHAUS = "urlhaus"
    OPENPHISH = "openphish"
    RANSOMWARE_LIVE = "ransomware_live"


class IndicatorType(StrEnum):
    CVE = "cve"
    URL = "url"
    DOMAIN = "domain"
    RANSOMWARE_EVENT = "ransomware_event"
    HOSTNAME = "hostname"
    IP = "ip"
    EMAIL = "email"
    HASH = "hash"
    ORGANIZATION = "organization"


class ThreatCategory(StrEnum):
    VULNERABILITY = "vulnerability"
    EXPLOITED_VULN = "exploited_vuln"
    PHISHING = "phishing"
    MALWARE = "malware"
    RANSOMWARE = "ransomware"
    EXPLOIT = "exploit"
    IOC = "ioc"
    OTHER = "other"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FeedRunStatus(StrEnum):
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
