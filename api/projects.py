from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.errors import run
from db import get_db
from schemas.project import (
    FilesReplace,
    FileWrite,
    FolderCreate,
    ProjectCreate,
    ProjectInfo,
    RenameRequest,
)
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
from schemas.session import SessionInfo
from services import projects, workspace
from services import state_service as state
from services.state_service import Category

router = APIRouter(prefix="/projects", tags=["projects"])

Db = Annotated[Session, Depends(get_db)]

# Reads need only the project. Changes also need ?session_id=..., the live session they come from.
# Everything arriving here comes from the human; agents call the services directly.


# ---- projects and their sessions ------------------------------------------------------


@router.post("", status_code=201)
def create_project(db: Db, body: ProjectCreate) -> ProjectInfo:
    return ProjectInfo.model_validate(run(lambda: projects.create_project(db, body)))


@router.get("")
def list_projects(db: Db, user_id: str | None = None) -> list[ProjectInfo]:
    return [ProjectInfo.model_validate(p) for p in projects.list_projects(db, user_id)]


@router.get("/{project_id}")
def get_project(db: Db, project_id: str) -> ProjectInfo:
    return ProjectInfo.model_validate(run(lambda: projects.get_project(db, project_id)))


@router.post("/{project_id}/sessions", status_code=201)
def start_session(db: Db, project_id: str) -> SessionInfo:
    return SessionInfo.model_validate(run(lambda: projects.start_session(db, project_id)))


@router.get("/{project_id}/sessions")
def list_sessions(db: Db, project_id: str) -> list[SessionInfo]:
    return [SessionInfo.model_validate(s) for s in run(lambda: projects.list_sessions(db, project_id))]


# ---- files -------------------------------------------------------------------------------


@router.get("/{project_id}/files")
def list_files(db: Db, project_id: str) -> dict:
    return run(lambda: workspace.list_files(db, project_id))


@router.put("/{project_id}/files")
def replace_files(db: Db, project_id: str, session_id: str, body: FilesReplace) -> dict:
    return run(lambda: workspace.replace_files(db, project_id, session_id, body.files))


@router.post("/{project_id}/files/rename", status_code=204)
def rename_path(db: Db, project_id: str, session_id: str, body: RenameRequest) -> None:
    run(lambda: workspace.rename_path(db, project_id, session_id, body.from_path, body.to_path))


@router.post("/{project_id}/folders", status_code=201)
def create_folder(db: Db, project_id: str, session_id: str, body: FolderCreate) -> dict:
    return run(lambda: workspace.create_folder(db, project_id, session_id, body.path))


@router.get("/{project_id}/files/{path:path}")
def read_file(db: Db, project_id: str, path: str) -> dict:
    return run(lambda: workspace.read_file(db, project_id, path))


@router.put("/{project_id}/files/{path:path}")
def write_file(db: Db, project_id: str, path: str, session_id: str, body: FileWrite) -> dict:
    return run(lambda: workspace.write_file(db, project_id, session_id, path, body.content))


@router.delete("/{project_id}/files/{path:path}", status_code=204)
def delete_path(db: Db, project_id: str, path: str, session_id: str) -> None:
    run(lambda: workspace.delete_path(db, project_id, session_id, path))


# ---- security state ----------------------------------------------------------------------


@router.get("/{project_id}/state")
def get_state(db: Db, project_id: str) -> SecurityState:
    return run(lambda: state.get_state(db, project_id))


@router.get("/{project_id}/risks")
def list_risks(
    db: Db, project_id: str, status: RiskStatus | None = None, severity: Severity | None = None
) -> list[Risk]:
    return run(lambda: state.list_risks(db, project_id, status, severity))


@router.get("/{project_id}/risks/{risk_id}")
def get_risk(db: Db, project_id: str, risk_id: str) -> Risk:
    return run(lambda: state.get_risk(db, project_id, risk_id))


@router.patch("/{project_id}/risks/{risk_id}/status")
def set_risk_status(db: Db, project_id: str, risk_id: str, session_id: str, body: RiskStatusUpdate) -> Risk:
    return run(lambda: state.set_risk_status(db, project_id, session_id, risk_id, body.status, body.rationale))


@router.get("/{project_id}/mitigations")
def list_mitigations(
    db: Db, project_id: str, risk_id: str | None = None, status: MitigationStatus | None = None
) -> list[Mitigation]:
    return run(lambda: state.list_mitigations(db, project_id, risk_id, status))


@router.get("/{project_id}/mitigations/{mitigation_id}")
def get_mitigation(db: Db, project_id: str, mitigation_id: str) -> Mitigation:
    return run(lambda: state.get_mitigation(db, project_id, mitigation_id))


# Returned as a plain dict so each item keeps all of its own fields (a risk keeps its
# description, a mitigation its risk_id) instead of being cut down to the shared ones.
@router.post("/{project_id}/{category}/{item_id}/approve")
def approve(db: Db, project_id: str, category: Category, item_id: str, session_id: str) -> dict:
    item: StateItem = run(lambda: state.set_approval(db, project_id, session_id, category, item_id, True))
    return item.model_dump(mode="json")


@router.post("/{project_id}/{category}/{item_id}/reject")
def reject(db: Db, project_id: str, category: Category, item_id: str, session_id: str) -> dict:
    item: StateItem = run(lambda: state.set_approval(db, project_id, session_id, category, item_id, False))
    return item.model_dump(mode="json")

