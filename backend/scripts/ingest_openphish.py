from __future__ import annotations

from app.core.config import get_settings
from app.core.database import SessionLocal, initialize_database
from app.core.logging import configure_logging, get_logger
from app.models.enums import FeedSource
from app.services.ingestion_service import IngestionService


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    logger = get_logger(__name__)
    initialize_database()

    ingestion_service = IngestionService()

    with SessionLocal() as session:
        run = ingestion_service.refresh_source(session, FeedSource.OPENPHISH)
        logger.info(
            "OpenPhish run finished with status=%s fetched=%s normalized=%s inserted=%s updated=%s upserted=%s.",
            run.status,
            run.items_fetched,
            run.items_normalized,
            run.items_inserted,
            run.items_updated,
            run.items_upserted,
        )


if __name__ == "__main__":
    main()
