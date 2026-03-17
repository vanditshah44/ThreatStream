from __future__ import annotations

from app.core.config import get_settings
from app.core.database import initialize_database
from app.core.logging import configure_logging, get_logger


def main() -> None:
    settings = get_settings()
    configure_logging(settings.log_level)
    logger = get_logger(__name__)

    initialize_database()
    logger.info("Database initialized using %s.", settings.database_url)


if __name__ == "__main__":
    main()
