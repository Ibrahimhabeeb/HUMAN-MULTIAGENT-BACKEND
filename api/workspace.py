from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.errors import run
from db import get_db
from schemas.security_state import (
    Mitigation,
    MitigationStatus,
    Risk,
    RiskStatus,
    RiskStatusUpdate,
    SecurityState,
    Severity,
    StateItem,
)
from schemas.workspace import FileWrite, FolderCreate, Notes, NotesWrite, RenameRequest
from services import state_service as state
from services import study, workspace
from services.state_service import Category

# Everything here acts on the current participant's open part, so no ids are needed in the URLs.
router = APIRouter(prefix="/workspace", tags=["workspace"])

Db = Annotated[Session, Depends(get_db)]


# ---- files ------------------------------------------------------------------------------------


@router.get("/files")
def list_files(db: Db) -> dict:
    return run(lambda: workspace.list_files(study.current_workspace(db)))


@router.post("/files/rename", status_code=204)
def rename_path(db: Db, body: RenameRequest) -> None:
    run(lambda: workspace.rename_path(db, study.editable_workspace(db), body.from_path, body.to_path))


@router.post("/folders", status_code=201)
def create_folder(db: Db, body: FolderCreate) -> dict:
    return run(lambda: workspace.create_folder(db, study.editable_workspace(db), body.path))


@router.get("/files/{path:path}")
def read_file(db: Db, path: str) -> dict:
    return run(lambda: workspace.read_file(study.current_workspace(db), path))


@router.put("/files/{path:path}")
def write_file(db: Db, path: str, body: FileWrite) -> dict:
    return run(lambda: workspace.write_file(db, study.editable_workspace(db), path, body.content))


@router.delete("/files/{path:path}", status_code=204)
def delete_path(db: Db, path: str) -> None:
    run(lambda: workspace.delete_path(db, study.editable_workspace(db), path))


# ---- notes box (single mode) --------------------------------------------------------------------


@router.get("/notes")
def get_notes(db: Db) -> Notes:
    return Notes(text=run(lambda: study.current_workspace(db)).notes)


@router.put("/notes")
def save_notes(db: Db, body: NotesWrite) -> Notes:
    return Notes(text=run(lambda: workspace.save_notes(db, study.editable_workspace(db), body.text)))


# ---- shared security state (team mode) ------------------------------------------------------------


@router.get("/state")
def get_state(db: Db) -> SecurityState:
    return run(lambda: state.get_state(study.current_workspace(db)))


@router.get("/risks")
def list_risks(db: Db, status: RiskStatus | None = None, severity: Severity | None = None) -> list[Risk]:
    return run(lambda: state.list_risks(study.current_workspace(db), status, severity))


@router.get("/risks/{risk_id}")
def get_risk(db: Db, risk_id: str) -> Risk:
    return run(lambda: state.get_risk(study.current_workspace(db), risk_id))


@router.patch("/risks/{risk_id}/status")
def set_risk_status(db: Db, risk_id: str, body: RiskStatusUpdate) -> Risk:
    return run(lambda: state.set_risk_status(db, study.editable_workspace(db), risk_id, body.status, body.rationale))


@router.get("/mitigations")
def list_mitigations(db: Db, risk_id: str | None = None, status: MitigationStatus | None = None) -> list[Mitigation]:
    return run(lambda: state.list_mitigations(study.current_workspace(db), risk_id, status))


@router.get("/mitigations/{mitigation_id}")
def get_mitigation(db: Db, mitigation_id: str) -> Mitigation:
    return run(lambda: state.get_mitigation(study.current_workspace(db), mitigation_id))


# Returned as a plain dict so each item keeps all of its own fields instead of only the shared ones.
@router.post("/state/{category}/{item_id}/approve")
def approve(db: Db, category: Category, item_id: str) -> dict:
    item: StateItem = run(lambda: state.set_approval(db, study.editable_workspace(db), category, item_id, True))
    return item.model_dump(mode="json")


@router.post("/state/{category}/{item_id}/reject")
def reject(db: Db, category: Category, item_id: str) -> dict:
    item: StateItem = run(lambda: state.set_approval(db, study.editable_workspace(db), category, item_id, False))
    return item.model_dump(mode="json")
