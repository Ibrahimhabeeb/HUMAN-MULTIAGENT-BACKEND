import hashlib
import secrets
from dataclasses import dataclass
from threading import Lock
from time import monotonic
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from config import get_settings
from models import Participant, StudySession
from schemas.study import Mode, TaskId
from services.errors import ConflictError

HEADER = "X-Session-Token"
_CONTEXT = "study_session_hash"


@dataclass
class Pending:
    pilot: bool
    screen: Literal["information", "consent"]
    task_id: TaskId


@dataclass
class TabSession:
    switch: Mode = "team"
    pending: Pending | None = None
    expires_at: float = 0


_pending: dict[str, TabSession] = {}
_pending_lock = Lock()
# Participant codes are allocated sequentially; consent is the only serialized operation.
consent_lock = Lock()


def reset_memory() -> None:
    _pending.clear()


def create(mode: Mode = "team") -> str:
    token = secrets.token_urlsafe(32)
    settings = get_settings()
    now = monotonic()
    with _pending_lock:
        for expired in [key for key, value in _pending.items() if value.expires_at <= now]:
            del _pending[expired]
        if len(_pending) >= settings.max_pending_sessions:
            raise ConflictError("The study is busy. Please try starting again shortly.")
        _pending[_hash(token)] = TabSession(switch=mode, expires_at=now + settings.pending_session_ttl_seconds)
    return token


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def bind(db: Session, token: str | None) -> bool:
    db.info.pop(_CONTEXT, None)
    if token is None or len(token) != 43:
        return False
    token_hash = _hash(token)
    record = db.get(StudySession, token_hash)
    if record is not None:
        participant = db.scalar(select(Participant).where(
            Participant.code == record.participant_code, Participant.status == "active"
        ))
        if participant is None:
            return False
    else:
        with _pending_lock:
            pending = _pending.get(token_hash)
            if pending is None or pending.expires_at <= monotonic():
                _pending.pop(token_hash, None)
                return False
    db.info[_CONTEXT] = token_hash
    return True


def current_hash(db: Session) -> str:
    token_hash = db.info.get(_CONTEXT)
    if token_hash is None:
        raise ConflictError("No browser session is selected")
    return token_hash


def tab(db: Session) -> TabSession:
    tab = _pending.get(current_hash(db))
    if tab is None:
        raise ConflictError("This browser session has already given consent")
    return tab


def participant(db: Session) -> Participant | None:
    record = db.get(StudySession, current_hash(db))
    if record is None:
        return None
    return db.scalar(select(Participant).where(
        Participant.code == record.participant_code, Participant.status == "active"
    ))


def forget_pending(db: Session) -> None:
    _pending.pop(current_hash(db), None)


def revoke(db: Session) -> None:
    forget_pending(db)
    record = db.get(StudySession, current_hash(db))
    if record is not None:
        db.delete(record)
