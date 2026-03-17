from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.enums import FeedSource, IndicatorType, Severity, ThreatCategory
from app.models.base import Base
from app.models.threat_item import ThreatItem

settings = get_settings()
logger = get_logger(__name__)


def _build_engine() -> Engine:
    connect_args: dict[str, object] = {}
    if settings.database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False

    return create_engine(
        settings.database_url,
        echo=settings.database_echo,
        pool_pre_ping=True,
        future=True,
        connect_args=connect_args,
    )


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


def initialize_database() -> None:
    if settings.auto_create_tables:
        import app.models.feed_run  # noqa: F401
        import app.models.threat_item  # noqa: F401

        Base.metadata.create_all(bind=engine)
        if _sqlite_schema_requires_repair():
            if settings.auto_repair_sqlite_schema:
                logger.warning(
                    "SQLite threat_items schema drift detected. Applying automatic repair because "
                    "AUTO_REPAIR_SQLITE_SCHEMA is enabled."
                )
                _repair_sqlite_threat_items_schema()
            else:
                logger.warning(
                    "SQLite threat_items schema drift detected. Automatic repair is disabled; "
                    "use migrations or opt in with AUTO_REPAIR_SQLITE_SCHEMA=true if you "
                    "explicitly want the local table rebuilt."
                )


def get_db_session() -> Generator[Session, None, None]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _sqlite_schema_requires_repair() -> bool:
    if not settings.database_url.startswith("sqlite"):
        return False

    with engine.connect() as connection:
        row = connection.execute(
            text("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'threat_items'")
        ).fetchone()
        if row is None or row[0] is None:
            return False

        create_statement = row[0]
        expected_indicator_names = {member.name for member in IndicatorType}
        expected_source_names = {member.name for member in FeedSource}
        expected_category_names = {member.name for member in ThreatCategory}
        expected_severity_names = {member.name for member in Severity}

        return not (
            _enum_names_present(create_statement, expected_indicator_names)
            and _enum_names_present(create_statement, expected_source_names)
            and _enum_names_present(create_statement, expected_category_names)
            and _enum_names_present(create_statement, expected_severity_names)
        )


def _repair_sqlite_threat_items_schema() -> None:
    if not settings.database_url.startswith("sqlite"):
        return

    with engine.begin() as connection:
        backup_table_name = "threat_items_backup"
        connection.execute(text("DROP TABLE IF EXISTS threat_items_backup"))
        connection.execute(text(f"CREATE TABLE {backup_table_name} AS SELECT * FROM threat_items"))
        connection.execute(text("DROP TABLE threat_items"))
        Base.metadata.create_all(bind=connection, tables=[ThreatItem.__table__])

        column_names = [column.name for column in ThreatItem.__table__.columns]
        column_list = ", ".join(column_names)
        connection.execute(
            text(
                f"INSERT INTO threat_items ({column_list}) "
                f"SELECT {column_list} FROM {backup_table_name}"
            )
        )
        connection.execute(text(f"DROP TABLE {backup_table_name}"))


def _enum_names_present(create_statement: str, expected_names: set[str]) -> bool:
    return all(f"'{name}'" in create_statement for name in expected_names)
