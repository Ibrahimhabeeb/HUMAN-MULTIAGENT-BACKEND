from sqlalchemy import select
from sqlalchemy.orm import Session

from models import ConsentRecord, Participant, StudySession, SurveyResponse, Workspace
from models.common import as_utc, utc_now
from schemas.study import Mode, Screen, TaskId
from services import content, runner, sessions, state_service, workspace
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
    if any(ws.task_id == task_id for ws in existing.values()):
        raise ConflictError("Choose a different task for the second part")
    ws = Workspace(
        participant_code=participant.code,
        mode=mode,
        task_id=task_id,
        part=len(existing) + 1,
        notes="",
    )
    db.add(ws)
    db.flush()
    workspace.create_from_starter(ws)
    # The task's unit tests are listed from the start, open until they have run (stored in single mode too).
    state_service.record_tests(ws, *runner.test_functions(workspace.folder(ws)), source="system")
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
    if ws.done_at is not None:
        raise ConflictError("This part is finished and can no longer be opened")
    return ws


def editable_workspace(db: Session) -> Workspace:
    ws = current_workspace(db)
    if ws.done_at is not None:
        raise ConflictError("This part is finished and can no longer be changed")
    return ws


def done(db: Session) -> None:
    ws = editable_workspace(db)
    # The Test/Verifier runs the unit tests on the final code. In single mode the results are only logged.
    runner.run_tests(db, ws, trigger="finish")
    _mark_done(db, ws)


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


def next_task_choices(db: Session) -> set[str] | None:
    """Task IDs already used at the handoff; None outside that screen."""
    participant = active_participant(db)
    if participant is None:
        return None
    parts = _workspaces(db, participant.code)
    if _screen_for(db, participant, parts) != "part_complete":
        return None
    return {ws.task_id for ws in parts.values()}


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
    screen = _screen_for(db, participant, parts)
    visible_parts = [] if screen == "part_complete" else (
        [current] if screen == "ide" and current is not None and current.part == 2
        else sorted(parts.values(), key=lambda ws: ws.part)
    )
    return {
        "screen": screen,
        "mode": participant.mode,
        "participant": participant.code,
        "pilot": participant.code.startswith("X"),
        "part": current.part if current else None,
        "task": {"id": current.task_id, "label": workspace.task_label(current.task_id)} if current and screen != "part_complete" else None,
        "needs_next_task": screen == "part_complete" and len(parts) == 1,
        "parts": [
            {
                "part": ws.part,
                "mode": ws.mode,
                "task_id": ws.task_id,
                "task_label": workspace.task_label(ws.task_id),
                "done": ws.done_at is not None,
            }
            for ws in visible_parts
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
        db.flush()  # saved first: PostgreSQL checks that every row below points at an existing participant
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
    existing = _workspaces(db, participant.code)
    current = existing.get(participant.mode)
    target = existing.get(mode)
    if current is None or current.done_at is None:
        raise ConflictError("Finish the current part before changing mode")
    if target is None:
        raise ConflictError("Choose a different task to start the second part")
    if target.done_at is not None or target.part != 2:
        raise ConflictError("A completed part cannot be reopened")
    try:
        log_event(db, participant.code, "mode_switched", mode=mode, detail={"from": participant.mode, "to": mode})
        participant.mode = mode
        db.commit()
    except Exception:
        db.rollback()
        raise


def start_part_two(db: Session, task_id: TaskId) -> None:
    participant = require_participant(db)
    existing = _workspaces(db, participant.code)
    if len(existing) != 1:
        raise ConflictError("The second part has already started")
    first = next(iter(existing.values()))
    if first.done_at is None:
        raise ConflictError("Finish the first part before choosing another task")
    if task_id == first.task_id:
        raise ConflictError("Choose a different task for the second part")
    next_mode: Mode = "single" if first.mode == "team" else "team"
    try:
        _open_mode(db, participant, next_mode, task_id)
        participant.mode = next_mode
        log_event(db, participant.code, "mode_switched", mode=next_mode, detail={"from": first.mode, "to": next_mode})
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
