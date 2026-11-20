"""Recoverable assessment of frozen submissions; never requires participant credentials."""

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from config import get_settings
from models import Event, Workspace
from services import runner, security_assessment, workspace
from services.events import log_event
from services.paths import resolve_inside


def _latest(db: Session, ws: Workspace, kind: str, snapshot: str) -> Event | None:
    events = db.scalars(select(Event).where(
        Event.participant_code == ws.participant_code, Event.mode == ws.mode, Event.type == kind,
    ).order_by(Event.id.desc()))
    return next((event for event in events if event.detail.get("snapshot") == snapshot), None)


def assess(db: Session, ws: Workspace, snapshot: Path, *, retry_errors=False) -> bool:
    if not retry_errors and _latest(db, ws, "submission_assessed", snapshot.name) is not None:
        return True
    unit = _latest(db, ws, "tests_run", snapshot.name)
    if unit is None or (retry_errors and unit.detail.get("status") in {"error", "timed_out"}):
        unit_result = runner.run_tests(db, ws, trigger="finish", saved_snapshot=snapshot)
    else:
        unit_result = unit.detail
    security = security_assessment.assess(db, ws, snapshot, retry_errors=retry_errors)
    finished = all(value.get("status") in {"passed", "failed", "no_tests"} for value in (unit_result, security))
    if finished and _latest(db, ws, "submission_assessed", snapshot.name) is None:
        log_event(db, ws.participant_code, "submission_assessed", actor="system", mode=ws.mode,
                  detail={"workspace_id": ws.id, "snapshot": snapshot.name})
        db.commit()
    return finished


def recover(db: Session, ws: Workspace, *, retry_errors=False) -> bool:
    event = db.scalar(select(Event).where(
        Event.participant_code == ws.participant_code, Event.mode == ws.mode, Event.type == "part_done",
    ).order_by(Event.id.desc()))
    if event is None or ws.done_at is None:
        return False
    root = Path(get_settings().snapshots_dir) / workspace.folder(ws).name
    snapshot = resolve_inside(root, event.detail["snapshot"])
    if not snapshot.is_dir():
        return False
    return assess(db, ws, snapshot, retry_errors=retry_errors)
