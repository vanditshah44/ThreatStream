from fastapi import APIRouter

from app.api.dependencies import DatabaseSession
from app.schemas.health import HealthResponse
from app.services.health_service import HealthService

router = APIRouter(tags=["health"])

health_service = HealthService()


@router.get("/health", response_model=HealthResponse, summary="Health check")
def health_check(session: DatabaseSession) -> HealthResponse:
    return health_service.get_health(session)

