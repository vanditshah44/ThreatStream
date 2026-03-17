#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any
from urllib import error, parse, request

DEFAULT_BASE_URL = "https://api.threatstream.vanditshah.com"
DEFAULT_TIMEOUT_SECONDS = 120
SUPPORTED_SOURCES = ("cisa_kev", "urlhaus", "openphish", "ransomware_live")


def load_local_env(env_path: Path) -> dict[str, str]:
    if not env_path.exists():
        return {}

    env_values: dict[str, str] = {}
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue

        key, value = line.split("=", 1)
        env_values[key.strip()] = value.strip().strip("\"'")

    return env_values


def resolve_setting(name: str, local_env: dict[str, str], default: str | None = None) -> str | None:
    environment_value = os.environ.get(name)
    if environment_value is not None and environment_value.strip():
        return environment_value.strip()

    local_value = local_env.get(name)
    if local_value is not None and local_value.strip():
        return local_value.strip()

    return default


def build_refresh_url(base_url: str, source: str | None) -> str:
    normalized = base_url.rstrip("/")

    if normalized.endswith("/admin/refresh"):
        refresh_url = normalized
    elif normalized.endswith("/api/v1"):
        refresh_url = f"{normalized}/admin/refresh"
    elif normalized.endswith("/api"):
        refresh_url = f"{normalized}/v1/admin/refresh"
    else:
        refresh_url = f"{normalized}/api/v1/admin/refresh"

    if source is None:
        return refresh_url

    return f"{refresh_url}?{parse.urlencode({'source': source})}"


def trigger_refresh(url: str, token: str, timeout_seconds: int) -> dict[str, Any]:
    request_headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
    refresh_request = request.Request(url, headers=request_headers, method="POST")

    try:
        with request.urlopen(refresh_request, timeout=timeout_seconds) as response:
            response_body = response.read().decode("utf-8")
    except error.HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace")
        detail = extract_error_detail(response_body) or exc.reason
        raise RuntimeError(f"Refresh request failed with HTTP {exc.code}: {detail}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Unable to reach ThreatStream API: {exc.reason}") from exc

    try:
        payload = json.loads(response_body)
    except json.JSONDecodeError as exc:
        raise RuntimeError("ThreatStream API returned a non-JSON response.") from exc

    if not isinstance(payload, dict):
        raise RuntimeError("ThreatStream API returned an unexpected response shape.")

    return payload


def extract_error_detail(response_body: str) -> str | None:
    try:
        payload = json.loads(response_body)
    except json.JSONDecodeError:
        return response_body.strip() or None

    if isinstance(payload, dict):
        detail = payload.get("detail")
        if isinstance(detail, str):
            return detail
    return response_body.strip() or None


def print_summary(summary: dict[str, Any]) -> None:
    status = summary.get("status", "unknown")
    print(f"Refresh status: {status}")
    print(f"Started at: {summary.get('started_at', '-')}")
    print(f"Completed at: {summary.get('completed_at', '-')}")
    print(f"Total fetched: {summary.get('total_fetched', 0)}")
    print(f"Inserted: {summary.get('inserted', 0)}")
    print(f"Updated: {summary.get('updated', 0)}")

    failed_collectors = summary.get("failed_collectors", [])
    if failed_collectors:
        print("Failed collectors: " + ", ".join(str(source) for source in failed_collectors))
    else:
        print("Failed collectors: none")

    collector_runs = summary.get("collector_runs", [])
    if not collector_runs:
        return

    print("")
    print("Collector runs:")
    for collector_run in collector_runs:
        if not isinstance(collector_run, dict):
            continue

        source = collector_run.get("source", "unknown")
        collector_status = collector_run.get("status", "unknown")
        fetched = collector_run.get("fetched", 0)
        inserted = collector_run.get("inserted", 0)
        updated = collector_run.get("updated", 0)
        print(
            f"- {source}: {collector_status} "
            f"fetched={fetched} inserted={inserted} updated={updated}"
        )

        error_message = collector_run.get("error_message")
        if error_message:
            print(f"  error: {error_message}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Trigger the ThreatStream admin refresh route.")
    parser.add_argument(
        "--source",
        choices=SUPPORTED_SOURCES,
        help="Refresh only one source instead of running all collectors.",
    )
    parser.add_argument(
        "--base-url",
        help="ThreatStream base URL, API URL, or full admin refresh URL.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        help="HTTP timeout in seconds.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    local_env = load_local_env(Path(".env"))

    admin_api_token = resolve_setting("ADMIN_API_TOKEN", local_env)
    if admin_api_token is None:
        print("ADMIN_API_TOKEN is not set in your environment or .env file.", file=sys.stderr)
        return 1

    base_url = args.base_url or resolve_setting(
        "THREATSTREAM_ADMIN_BASE_URL",
        local_env,
        default=DEFAULT_BASE_URL,
    )
    if base_url is None:
        print("Unable to determine the ThreatStream base URL.", file=sys.stderr)
        return 1

    refresh_url = build_refresh_url(base_url, args.source)

    try:
        summary = trigger_refresh(refresh_url, admin_api_token, args.timeout)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    print_summary(summary)
    return 0 if summary.get("status") == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
