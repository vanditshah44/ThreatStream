from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_ROOT = BACKEND_DIR.parent
LOCAL_DEV_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
]


class Settings(BaseSettings):
    app_name: str = "ThreatStream API"
    app_env: str = "development"
    app_version: str = "0.1.0"
    debug: bool = False

    api_prefix: str = "/api"
    api_version: str = "v1"

    log_level: str = "INFO"
    admin_api_token: str | None = None

    database_url: str = f"sqlite:///{(BACKEND_DIR / 'threatstream.db').resolve().as_posix()}"
    database_echo: bool = False
    auto_create_tables: bool = True
    auto_repair_sqlite_schema: bool = False

    cors_origins: list[str] = Field(default_factory=list)
    allow_unsafe_feed_urls: bool = False
    http_timeout_seconds: float = 30.0
    http_max_retries: int = 2
    http_user_agent: str = "ThreatStream/0.1.0"

    cisa_kev_catalog_url: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    cisa_kev_catalog_page_url: str = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    urlhaus_api_base_url: str = "https://urlhaus-api.abuse.ch"
    urlhaus_auth_key: str | None = None
    urlhaus_recent_limit: int = 1000
    openphish_feed_url: str = "https://openphish.com/feed.txt"
    ransomware_live_recent_victims_url: str = "https://api.ransomware.live/v2/recentvictims"

    model_config = SettingsConfigDict(
        env_file=(BACKEND_DIR / ".env", REPO_ROOT / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, value: object) -> list[str]:
        if isinstance(value, str):
            normalized = value.strip()
            if not normalized:
                parsed_origins: list[str] = []
            elif normalized.startswith("["):
                loaded = json.loads(normalized)
                if not isinstance(loaded, list):
                    raise TypeError("CORS origins JSON must decode to a list.")
                parsed_origins = [str(origin).strip() for origin in loaded if str(origin).strip()]
            else:
                parsed_origins = [
                    origin.strip().strip('"').strip("'")
                    for origin in normalized.split(",")
                    if origin.strip()
                ]
        elif isinstance(value, list):
            parsed_origins = [str(origin).strip() for origin in value if str(origin).strip()]
        else:
            raise TypeError("CORS origins must be a comma-separated string or a list of strings.")

        seen: set[str] = set()
        deduplicated_origins: list[str] = []
        for origin in parsed_origins:
            if origin and origin not in seen:
                seen.add(origin)
                deduplicated_origins.append(origin)

        return deduplicated_origins

    @field_validator("debug", mode="before")
    @classmethod
    def parse_debug(cls, value: object) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on", "debug", "development"}:
                return True
            if normalized in {"0", "false", "no", "off", "release", "prod", "production"}:
                return False
        raise TypeError("DEBUG must be a boolean or a recognized debug/release string.")

    @field_validator("admin_api_token", mode="before")
    @classmethod
    def parse_admin_api_token(cls, value: object) -> str | None:
        if value in (None, ""):
            return None
        if isinstance(value, str):
            normalized = value.strip()
            return normalized or None
        raise TypeError("ADMIN_API_TOKEN must be a string.")

    @field_validator("database_url", mode="before")
    @classmethod
    def normalize_database_url(cls, value: object) -> str:
        if not isinstance(value, str):
            raise TypeError("DATABASE_URL must be a string.")

        normalized = value.strip()
        if not normalized:
            raise TypeError("DATABASE_URL must not be empty.")

        sqlite_prefix = "sqlite:///"
        if normalized.startswith(sqlite_prefix):
            path_fragment = normalized[len(sqlite_prefix) :]
            if path_fragment in {":memory:", ""}:
                return normalized

            if not Path(path_fragment).is_absolute():
                resolved_path = (BACKEND_DIR / path_fragment).resolve()
                return f"sqlite:///{resolved_path.as_posix()}"

        return normalized

    @model_validator(mode="after")
    def apply_security_defaults(self) -> Settings:
        is_dev_mode = self.debug or self.app_env.lower() in {"development", "dev", "local", "test"}

        if "*" in self.cors_origins:
            raise ValueError("Wildcard CORS origins are not allowed when credentials are enabled.")

        merged_origins = list(self.cors_origins)
        if is_dev_mode:
            merged_origins = [*merged_origins, *LOCAL_DEV_ORIGINS]

        seen: set[str] = set()
        deduplicated_origins: list[str] = []
        for origin in merged_origins:
            if origin and origin not in seen:
                seen.add(origin)
                deduplicated_origins.append(origin)

        self.cors_origins = deduplicated_origins
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
