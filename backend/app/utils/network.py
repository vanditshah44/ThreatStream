from __future__ import annotations

from ipaddress import ip_address
from urllib.parse import urlparse, urlunparse


def sanitize_external_url(value: str | None) -> str | None:
    if value is None:
        return None

    normalized = value.strip()
    if not normalized:
        return None

    parsed = urlparse(normalized)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()

    if scheme not in {"http", "https"}:
        return None
    if not hostname or _is_local_or_private_host(hostname):
        return None
    if parsed.username or parsed.password:
        return None

    sanitized = parsed._replace(fragment="")
    return urlunparse(sanitized)


def validate_feed_source_url(
    value: str,
    *,
    allowed_hosts: set[str],
    allow_unsafe: bool = False,
) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError("Feed URL must not be empty.")

    parsed = urlparse(normalized)
    scheme = parsed.scheme.lower()
    hostname = (parsed.hostname or "").lower()

    if not scheme or not hostname:
        raise ValueError("Feed URL must be an absolute URL with a hostname.")
    if parsed.username or parsed.password:
        raise ValueError("Feed URL must not include embedded credentials.")

    if allow_unsafe:
        return normalized

    if scheme != "https":
        raise ValueError("Feed URL must use HTTPS unless ALLOW_UNSAFE_FEED_URLS is enabled.")
    if _is_local_or_private_host(hostname):
        raise ValueError("Feed URL must not target localhost or private network addresses.")
    if not _hostname_matches_allowlist(hostname, allowed_hosts):
        raise ValueError(f"Feed URL host '{hostname}' is not in the allowed host list.")

    return normalized


def _hostname_matches_allowlist(hostname: str, allowed_hosts: set[str]) -> bool:
    return any(hostname == allowed_host or hostname.endswith(f".{allowed_host}") for allowed_host in allowed_hosts)


def _is_local_or_private_host(hostname: str) -> bool:
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".local"):
        return True

    try:
        host_ip = ip_address(hostname)
    except ValueError:
        return False

    return not host_ip.is_global
