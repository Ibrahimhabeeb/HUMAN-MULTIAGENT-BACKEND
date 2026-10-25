from typing import Annotated, Any

from fastapi import APIRouter, Body, HTTPException

from api.dependencies import Db
from api.errors import run
from schemas.linting import LintRequest, LintResult
from schemas.runner import RunResult
from schemas.security_state import Category, HumanCategory, SecurityState
from schemas.workspace import FileWrite, FolderCreate, Notes, NotesWrite, RenameRequest
from services import linting, runner, state_service, study, workspace

# The session header selects the participant's open part; participant ids are not accepted in URLs.
router = APIRouter(prefix="/workspace", tags=["workspace"])



@router.post("/lint")
def lint_file(db: Db, body: LintRequest) -> LintResult:
    try:
        return run(lambda: linting.check(study.current_workspace(db), body.path, body.content))
    except linting.LintUnavailableError as error:
        raise HTTPException(status_code=503, detail=str(error)) from error


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
# Items are returned as plain dicts so each keeps all of its own fields.


@router.get("/state")
def get_state(db: Db) -> SecurityState:
    return run(lambda: state_service.load(study.current_workspace(db)))


@router.get("/state/{category}")
def list_items(db: Db, category: Category) -> list[dict]:
    state = run(lambda: state_service.load(study.current_workspace(db)))
    return [item.model_dump(mode="json") for item in getattr(state, category)]


@router.get("/state/{category}/{item_id}")
def get_item(db: Db, category: Category, item_id: str) -> dict:
    state = run(lambda: state_service.load(study.current_workspace(db)))
    return run(lambda: state_service.find(state, category, item_id)).model_dump(mode="json")


@router.post("/state/{category}", status_code=201)
def add_item(db: Db, category: HumanCategory, body: Annotated[dict[str, Any], Body()]) -> dict:
    item = run(lambda: state_service.human_add(db, study.editable_workspace(db), category, body))
    return item.model_dump(mode="json")


@router.patch("/state/{category}/{item_id}")
def edit_item(db: Db, category: HumanCategory, item_id: str, body: Annotated[dict[str, Any], Body()]) -> dict:
    item = run(lambda: state_service.human_edit(db, study.editable_workspace(db), category, item_id, body))
    return item.model_dump(mode="json")


@router.delete("/state/{category}/{item_id}", status_code=204)
def delete_item(db: Db, category: HumanCategory, item_id: str) -> None:
    run(lambda: state_service.human_delete(db, study.editable_workspace(db), category, item_id))


# ---- tests --------------------------------------------------------------------------------------


@router.post("/tests/run")
def run_tests(db: Db) -> RunResult:
    return RunResult.model_validate(run(lambda: runner.run_tests(db, study.editable_workspace(db))))
