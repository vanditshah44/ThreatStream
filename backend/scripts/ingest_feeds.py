from __future__ import annotations

import argparse

from app.core.config import get_settings
from app.core.database import SessionLocal, initialize_database
from app.core.logging import configure_logging, get_logger
from app.models.enums import FeedSource
from app.schemas.ingestion import IngestionSummaryResponse
from app.services.ingestion_service import IngestionService


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run ThreatStream feed ingestion.")
    parser.add_argument(
        "--source",
        choices=[source.value for source in FeedSource],
        help="Refresh a single feed source instead of running all collectors.",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    settings = get_settings()

    configure_logging(settings.log_level)
    logger = get_logger(__name__)
    initialize_database()

    ingestion_service = IngestionService()

    with SessionLocal() as session:
        if args.source:
            summary = ingestion_service.refresh_sources(session, [FeedSource(args.source)])
        else:
            summary = ingestion_service.refresh_all(session)

    response = IngestionSummaryResponse.from_summary(summary)
    logger.info(
        "Ingestion run finished with status=%s fetched=%s inserted=%s updated=%s failed_collectors=%s.",
        response.status,
        response.total_fetched,
        response.inserted,
        response.updated,
        [source.value for source in response.failed_collectors],
    )


if __name__ == "__main__":
    main()
