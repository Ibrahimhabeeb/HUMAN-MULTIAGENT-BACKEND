from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from models import Event


def log_event(
    db: Session,
    participant_code: str,
    type: str,
    actor: str = "human",
    mode: str | None = None,
    detail: dict[str, Any] | None = None,
) -> Event:
    # Added to the caller's transaction, so it is saved together with the change it describes.
    event = Event(participant_code=participant_code, mode=mode, type=type, actor=actor, detail=detail or {})
    db.add(event)
    return event


def list_events(db: Session, participant_code: str) -> list[Event]:
    query = select(Event).where(Event.participant_code == participant_code).order_by(Event.id)
    return list(db.scalars(query))
