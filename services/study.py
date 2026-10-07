from dataclasses import dataclass
from typing import Literal

from sqlalchemy import select
from sqlalchemy.orm import Session

from models import ConsentRecord, Participant
from schemas.study import Mode, Screen
from services import content
from services.errors import ConflictError
from services.events import log_event


@dataclass
class _Pending:
    pilot: bool
    screen: Literal["information", "consent"]


class _Memory:
    # Kept in server memory, not the database: nothing about a person is stored before they consent.
    def __init__(self) -> None:
        self.switch: Mode = "team"
        self.pending: _Pending | None = None


_memory = _Memory()


def reset_memory() -> None:
    global _memory
    _memory = _Memory()


def active_participant(db: Session) -> Participant | None:
    return db.scalar(select(Participant).where(Participant.status == "active"))


def require_participant(db: Session) -> Participant:
    participant = active_participant(db)
    if participant is None:
        raise ConflictError("No participant session is active")
    return participant


def _screen_for(db: Session, participant: Participant) -> Screen:
    return "ide"


def get_state(db: Session) -> dict:
    participant = active_participant(db)
    if participant is not None:
        return {
            "screen": _screen_for(db, participant),
            "mode": participant.mode,
            "participant": participant.code,
            "pilot": participant.code.startswith("X"),
        }
    if _memory.pending is not None:
        return {"screen": _memory.pending.screen, "mode": _memory.switch, "pilot": _memory.pending.pilot}
    return {"screen": "start", "mode": _memory.switch}


# ---- before consent (memory only) ---------------------------------------------------


def start(db: Session, pilot: bool) -> None:
    if active_participant(db) is not None or _memory.pending is not None:
        raise ConflictError("A session is already in progress. Use Restart first.")
    _memory.pending = _Pending(pilot=pilot, screen="information")


def continue_to_consent() -> None:
    if _memory.pending is None or _memory.pending.screen != "information":
        raise ConflictError("The information sheet is not open")
    _memory.pending.screen = "consent"


def decline() -> None:
    if _memory.pending is None:
        raise ConflictError("There is no session to leave")
    _memory.pending = None


# ---- consent: the first moment anything is stored -------------------------------------


def _next_code(db: Session, pilot: bool) -> str:
    prefix = "X" if pilot else "P"
    codes = db.scalars(select(Participant.code).where(Participant.code.like(f"{prefix}%")))
    numbers = [int(code[1:]) for code in codes if code[1:].isdigit()]
    return f"{prefix}{max(numbers, default=0) + 1:02d}"


def give_consent(db: Session, consent_version: str) -> Participant:
    pending = _memory.pending
    if pending is None or pending.screen != "consent":
        raise ConflictError("The consent form is not open")
    current_version, _ = content.load("consent")
    if consent_version != current_version:
        raise ConflictError(f"Consent version {consent_version} is out of date (current: {current_version})")

    participant = Participant(code=_next_code(db, pending.pilot), mode=_memory.switch)
    db.add(participant)
    db.add(ConsentRecord(participant_code=participant.code, consent_version=consent_version))
    log_event(
        db,
        participant.code,
        "participant_created",
        mode=participant.mode,
        detail={"pilot": pending.pilot, "consent_version": consent_version},
    )
    db.commit()
    _memory.pending = None
    return participant


# ---- during the session -------------------------------------------------------------------


def switch_mode(db: Session, mode: Mode) -> None:
    participant = active_participant(db)
    if participant is None:
        _memory.switch = mode  # the researcher sets the starting mode before the next participant
        return
    if participant.mode == mode:
        return
    log_event(db, participant.code, "mode_switched", mode=mode, detail={"from": participant.mode, "to": mode})
    participant.mode = mode
    db.commit()


def finish(db: Session) -> None:
    participant = require_participant(db)
    if _screen_for(db, participant) != "thank_you":
        raise ConflictError("The participant has not reached the end of the study yet")
    participant.status = "complete"
    log_event(db, participant.code, "participant_finished")
    db.commit()
    _memory.switch = participant.mode


def restart(db: Session) -> None:
    _memory.pending = None
    participant = active_participant(db)
    if participant is None:
        return
    participant.status = "incomplete"  # their data is kept
    log_event(db, participant.code, "session_restarted", actor="researcher")
    db.commit()
    _memory.switch = participant.mode
