from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import get_settings
from app.core.database import initialize_database
from app.core.logging import configure_logging, get_logger


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    logger = get_logger(__name__)

    logger.info(
        "Starting %s v%s in %s mode.",
        settings.app_name,
        settings.app_version,
        settings.app_env,
    )
    if settings.admin_api_token is None:
        logger.warning("ADMIN_API_TOKEN is not configured. Admin routes are disabled.")
    initialize_database()

    yield

    logger.info("Shutting down %s.", settings.app_name)


def create_application() -> FastAPI:
    settings = get_settings()

    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        debug=settings.debug,
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(api_router, prefix=settings.api_prefix)

    @application.get("/", tags=["meta"], summary="API root")
    def api_root() -> dict[str, str]:
        return {
            "service": settings.app_name,
            "version": settings.app_version,
            "environment": settings.app_env,
            "api_base": f"{settings.api_prefix}/{settings.api_version}",
            "health_url": f"{settings.api_prefix}/{settings.api_version}/health",
            "docs_url": "/docs",
        }

    @application.get(settings.api_prefix, tags=["meta"], summary="API prefix root")
    def api_prefix_root() -> dict[str, str]:
        return {
            "message": "ThreatStream API",
            "version": settings.api_version,
            "root": "/",
            "versioned_api": f"{settings.api_prefix}/{settings.api_version}",
        }

    @application.get(
        f"{settings.api_prefix}/{settings.api_version}",
        tags=["meta"],
        summary="Versioned API root",
    )
    def api_version_root() -> dict[str, str]:
        return {
            "message": "ThreatStream API v1",
            "health_url": f"{settings.api_prefix}/{settings.api_version}/health",
            "dashboard_summary_url": f"{settings.api_prefix}/{settings.api_version}/dashboard/summary",
            "threats_url": f"{settings.api_prefix}/{settings.api_version}/threats",
        }

    return application


app = create_application()
