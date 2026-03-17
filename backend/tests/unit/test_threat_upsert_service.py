from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.threat_item import ThreatItem
from app.services.threat_upsert_service import ThreatUpsertService


def test_upsert_many_deduplicates_batch_ids_and_counts_inserts(
    db_session: Session,
    normalized_threat_factory,
) -> None:
    service = ThreatUpsertService()

    result = service.upsert_many(
        db_session,
        [
            normalized_threat_factory(id="same-id", title="First title"),
            normalized_threat_factory(id="same-id", title="Last title wins"),
            normalized_threat_factory(id="other-id", title="Other item"),
        ],
    )

    stored_items = db_session.scalars(select(ThreatItem).order_by(ThreatItem.id)).all()

    assert result.inserted_count == 2
    assert result.updated_count == 0
    assert result.processed_count == 2
    assert result.duplicate_input_count == 1
    assert len(stored_items) == 2
    assert stored_items[1].title == "Last title wins"


def test_upsert_many_counts_updates_against_existing_rows(
    db_session: Session,
    normalized_threat_factory,
) -> None:
    service = ThreatUpsertService()

    service.upsert_many(db_session, [normalized_threat_factory(id="existing-id", title="Original title")])
    result = service.upsert_many(
        db_session,
        [normalized_threat_factory(id="existing-id", title="Updated title")],
    )

    stored_item = db_session.scalar(select(ThreatItem).where(ThreatItem.id == "existing-id"))

    assert result.inserted_count == 0
    assert result.updated_count == 1
    assert result.processed_count == 1
    assert stored_item is not None
    assert stored_item.title == "Updated title"


def test_upsert_many_skips_noop_updates_for_identical_rows(
    db_session: Session,
    normalized_threat_factory,
) -> None:
    service = ThreatUpsertService()
    threat = normalized_threat_factory(id="same-id", title="Stable title")

    service.upsert_many(db_session, [threat])
    original_item = db_session.scalar(select(ThreatItem).where(ThreatItem.id == "same-id"))
    assert original_item is not None
    original_updated_at = original_item.updated_at

    result = service.upsert_many(db_session, [threat])

    stored_item = db_session.scalar(select(ThreatItem).where(ThreatItem.id == "same-id"))

    assert result.inserted_count == 0
    assert result.updated_count == 0
    assert result.processed_count == 0
    assert stored_item is not None
    assert stored_item.updated_at == original_updated_at
