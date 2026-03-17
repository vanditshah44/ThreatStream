from datetime import datetime

from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    application: str
    version: str
    environment: str
    database_status: str
    checked_at: datetime

