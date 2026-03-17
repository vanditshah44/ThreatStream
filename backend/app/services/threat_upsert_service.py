from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.logging import get_logger
from app.models.threat_item import ThreatItem
from app.schemas.normalized_threat import NormalizedThreatItem
from app.services.ingestion_models import UpsertResult


class ThreatUpsertService:
    def __init__(self) -> None:
        self.logger = get_logger(__name__)

    def upsert_many(self, session: Session, threats: Sequence[NormalizedThreatItem]) -> UpsertResult:
        if not threats:
            return UpsertResult(
                input_count=0,
                deduplicated_count=0,
                inserted_count=0,
                updated_count=0,
            )

        deduplicated_threats = self._deduplicate_threats(threats)
        threat_ids = list(deduplicated_threats.keys())
        existing_items = {
            item.id: item
            for item in session.scalars(select(ThreatItem).where(ThreatItem.id.in_(threat_ids))).all()
        }
        inserted_count = 0
        updated_count = 0

        try:
            for threat in deduplicated_threats.values():
                payload = threat.model_dump()
                existing_item = existing_items.get(threat.id)

                if existing_item is None:
                    session.add(ThreatItem(**payload))
                    inserted_count += 1
                    continue

                if self._apply_updates_if_changed(existing_item, payload):
                    updated_count += 1

            session.commit()
        except SQLAlchemyError:
            session.rollback()
            self.logger.exception("Threat upsert failed for %s items.", len(threats))
            raise

        result = UpsertResult(
            input_count=len(threats),
            deduplicated_count=len(deduplicated_threats),
            inserted_count=inserted_count,
            updated_count=updated_count,
        )
        self.logger.info(
            "Upserted %s threat items (inserted=%s updated=%s input_duplicates=%s).",
            result.processed_count,
            result.inserted_count,
            result.updated_count,
            result.duplicate_input_count,
        )
        return result

    def _deduplicate_threats(
        self,
        threats: Sequence[NormalizedThreatItem],
    ) -> dict[str, NormalizedThreatItem]:
        deduplicated: dict[str, NormalizedThreatItem] = {}
        for threat in threats:
            deduplicated[threat.id] = threat
        return deduplicated

    def _apply_updates_if_changed(
        self,
        existing_item: ThreatItem,
        payload: dict[str, object],
    ) -> bool:
        has_changes = False
        for field_name, value in payload.items():
            if not self._values_equal(getattr(existing_item, field_name), value):
                setattr(existing_item, field_name, value)
                has_changes = True
        return has_changes

    def _values_equal(self, left: object, right: object) -> bool:
        if isinstance(left, datetime) and isinstance(right, datetime):
            return self._normalize_datetime(left) == self._normalize_datetime(right)
        return left == right

    def _normalize_datetime(self, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)
