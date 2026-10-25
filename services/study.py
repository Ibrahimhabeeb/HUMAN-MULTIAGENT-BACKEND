from sqlalchemy import select
from sqlalchemy.orm import Session

from models import ConsentRecord, Participant, StudySession, SurveyResponse, Workspace
from models.common import as_utc, utc_now
from schemas.security_state import SecurityState
from schemas.study import Mode, Screen, TaskId
from services import content, sessions, workspace
from services.errors import ConflictError
from services.events import log_event


def reset_memory() -> None:
    sessions.reset_memory()


def active_participant(db: Session) -> Participant | None:
    return sessions.participant(db)


def require_participant(db: Session) -> Participant:
    participant = active_participant(db)
    if participant is None:
        raise ConflictError("No participant session is active")
    return participant


# ---- parts (one workspace per mode) ---------------------------------------------------------


def _workspaces(db: Session, code: str) -> dict[str, Workspace]:
    rows = db.scalars(select(Workspace).where(Workspace.participant_code == code).order_by(Workspace.part))
    return {ws.mode: ws for ws in rows}


def _open_mode(db: Session, participant: Participant, mode: Mode, task_id: TaskId = "A") -> Workspace:
    existing = _workspaces(db, participant.code)
    if mode in existing:
        return existing[mode]
    if any(ws.done_at is None for ws in existing.values()):
        raise ConflictError("Click Done on the current part before starting the other mode")
    ws = Workspace(
        participant_code=participant.code,
        mode=mode,
        task_id=next(iter(existing.values())).task_id if existing else task_id,
        part=len(existing) + 1,
        security_state=SecurityState().model_dump(mode="json") if mode == "team" else {},
        notes="",
    )
    db.add(ws)
    db.flush()
    workspace.create_from_starter(ws)
    log_event(db, participant.code, "part_started", mode=mode, detail={"part": ws.part, "task_id": ws.task_id})
    return ws


def _mark_done(db: Session, ws: Workspace) -> None:
    ws.done_at = utc_now()
    ws.done_reason = "done"
    saved = workspace.snapshot(ws, "done")
    seconds = int((ws.done_at - as_utc(ws.started_at)).total_seconds())
    log_event(
        db,
        ws.participant_code,
        "part_done",
        mode=ws.mode,
        detail={"part": ws.part, "task_id": ws.task_id, "seconds": seconds, "snapshot": saved.name},
    )
    db.commit()


def current_workspace(db: Session) -> Workspace:
    participant = require_participant(db)
    ws = _workspaces(db, participant.code).get(participant.mode)
    if ws is None:
        raise ConflictError("No part is open")
    return ws


def editable_workspace(db: Session) -> Workspace:
    ws = current_workspace(db)
    if ws.done_at is not None:
        raise ConflictError("This part is finished and can no longer be changed")
    return ws


def done(db: Session) -> None:
    _mark_done(db, editable_workspace(db))


# ---- which screen to show ---------------------------------------------------------------------


def _questionnaire_submitted(db: Session, participant: Participant) -> bool:
    query = select(SurveyResponse.id).where(SurveyResponse.participant_code == participant.code).limit(1)
    return db.scalar(query) is not None


def _screen_for(db: Session, participant: Participant, parts: dict[str, Workspace]) -> Screen:
    if _questionnaire_submitted(db, participant):
        return "thank_you"
    if len(parts) == 2 and all(ws.done_at is not None for ws in parts.values()):
        return "questionnaire"
    current = parts.get(participant.mode)
    if current is not None and current.done_at is not None:
        return "part_complete"
    return "ide"


def get_state(db: Session) -> dict:
    participant = active_participant(db)
    if participant is None:
        tab = sessions.tab(db)
        if tab.pending is not None:
            task_id = tab.pending.task_id
            return {
                "screen": tab.pending.screen,
                "mode": tab.switch,
                "pilot": tab.pending.pilot,
                "task": {"id": task_id, "label": workspace.task_label(task_id)},
            }
        return {"screen": "start", "mode": tab.switch}

    parts = _workspaces(db, participant.code)
    current = parts.get(participant.mode)
    return {
        "screen": _screen_for(db, participant, parts),
        "mode": participant.mode,
        "participant": participant.code,
        "pilot": participant.code.startswith("X"),
        "part": current.part if current else None,
        "task": {"id": current.task_id, "label": workspace.task_label(current.task_id)} if current else None,
        "parts": [
            {
                "part": ws.part,
                "mode": ws.mode,
                "task_id": ws.task_id,
                "task_label": workspace.task_label(ws.task_id),
                "done": ws.done_at is not None,
            }
            for ws in sorted(parts.values(), key=lambda w: w.part)
        ],
    }


# ---- before consent (memory only) ---------------------------------------------------------------


def start(db: Session, pilot: bool, task_id: TaskId = "A") -> None:
    if active_participant(db) is not None or sessions.tab(db).pending is not None:
        raise ConflictError("A session is already in progress. Use Restart first.")
    sessions.tab(db).pending = sessions.Pending(pilot=pilot, screen="information", task_id=task_id)


def continue_to_consent(db: Session) -> None:
    if sessions.tab(db).pending is None or sessions.tab(db).pending.screen != "information":
        raise ConflictError("The information sheet is not open")
    sessions.tab(db).pending.screen = "consent"


def decline(db: Session) -> None:
    if sessions.tab(db).pending is None:
        raise ConflictError("There is no session to leave")
    sessions.tab(db).pending = None


# ---- consent: the first moment anything is stored ---------------------------------------------------


def _next_code(db: Session, pilot: bool) -> str:
    prefix = "X" if pilot else "P"
    codes = db.scalars(select(Participant.code).where(Participant.code.like(f"{prefix}%")))
    numbers = [int(code[1:]) for code in codes if code[1:].isdigit()]
    return f"{prefix}{max(numbers, default=0) + 1:02d}"


def give_consent(db: Session, consent_version: str) -> Participant:
    with sessions.consent_lock:
        return _give_consent(db, consent_version)


def _give_consent(db: Session, consent_version: str) -> Participant:
    pending = sessions.tab(db).pending
    if pending is None or pending.screen != "consent":
        raise ConflictError("The consent form is not open")
    current_version, _ = content.load("consent")
    if consent_version != current_version:
        raise ConflictError(f"Consent version {consent_version} is out of date (current: {current_version})")

    try:
        participant = Participant(code=_next_code(db, pending.pilot), mode=sessions.tab(db).switch)
        db.add(participant)
        db.add(ConsentRecord(participant_code=participant.code, consent_version=consent_version))
        log_event(
            db,
            participant.code,
            "participant_created",
            mode=participant.mode,
            detail={"pilot": pending.pilot, "consent_version": consent_version},
        )
        db.add(StudySession(token_hash=sessions.current_hash(db), participant_code=participant.code))
        _open_mode(db, participant, participant.mode, pending.task_id)
        db.commit()
    except Exception:
        db.rollback()
        raise
    sessions.forget_pending(db)
    return participant


# ---- during the session ------------------------------------------------------------------------------


def switch_mode(db: Session, mode: Mode) -> None:
    participant = active_participant(db)
    if participant is None:
        sessions.tab(db).switch = mode  # the researcher sets the starting mode before the next participant
        return
    if participant.mode == mode:
        return
    try:
        _open_mode(db, participant, mode)
        log_event(db, participant.code, "mode_switched", mode=mode, detail={"from": participant.mode, "to": mode})
        participant.mode = mode
        db.commit()
    except Exception:
        db.rollback()
        raise


def finish(db: Session) -> Mode:
    participant = require_participant(db)
    if _screen_for(db, participant, _workspaces(db, participant.code)) != "thank_you":
        raise ConflictError("The participant has not reached the end of the study yet")
    participant.status = "complete"
    log_event(db, participant.code, "participant_finished")
    sessions.revoke(db)
    db.commit()
    return participant.mode


def restart(db: Session) -> Mode:
    participant = active_participant(db)
    if participant is None:
        mode = sessions.tab(db).switch
        sessions.revoke(db)
        return mode
    participant.status = "incomplete"  # their data is kept
    log_event(db, participant.code, "session_restarted", actor="researcher")
    sessions.revoke(db)
    db.commit()
    return participant.mode
