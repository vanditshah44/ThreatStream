from sqlalchemy.orm import Session

from app.api.v1.routes.health import health_check


def test_health_check_returns_ok(db_session: Session) -> None:
    response = health_check(db_session)

    assert response.status in {"ok", "degraded"}
    assert response.application == "ThreatStream API"
