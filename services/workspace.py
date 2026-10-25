import json
import shutil
from collections.abc import Iterator
from pathlib import Path

from sqlalchemy.orm import Session

from config import get_settings
from models import Workspace
from services.errors import ConflictError, NotFoundError
from services.events import log_event
from services.paths import MAX_FILES, clean_path, resolve_inside

# Created by running tests; never shown, copied or snapshotted.
IGNORED = {"__pycache__", ".pytest_cache"}
_ignore = shutil.ignore_patterns(*IGNORED)


def _directory_name(ws: Workspace) -> str:
    return f"{ws.participant_code}_{ws.task_id}_{ws.mode}"


def folder(ws: Workspace) -> Path:
    root = Path(get_settings().workspaces_dir)
    current = root / _directory_name(ws)
    legacy = root / f"{ws.participant_code}_{ws.task_id}"
    # Keep older sessions readable without moving or overwriting participant data.
    legacy_task = "A" if ws.part == 1 else "B"
    return legacy if ws.task_id == legacy_task and not current.exists() and legacy.is_dir() else current


def task_info(task_id: str) -> dict[str, str]:
    tasks_file = Path(get_settings().starter_dir) / "tasks.json"
    tasks = json.loads(tasks_file.read_text(encoding="utf-8")) if tasks_file.is_file() else {}
    task = tasks.get(task_id, {})
    return {"id": task_id, "label": task.get("label", f"task {task_id}"), "cwe": task.get("cwe", "")}


def task_label(task_id: str) -> str:
    return task_info(task_id)["label"]


def create_from_starter(ws: Workspace) -> None:
    source = Path(get_settings().starter_dir) / f"task_{ws.task_id}"
    if not source.is_dir():
        raise NotFoundError(f"Starter task {source} is missing")
    destination = Path(get_settings().workspaces_dir) / _directory_name(ws)
    if destination.exists():
        raise ConflictError(f"Workspace {destination} already exists")
    shutil.copytree(source, destination, ignore=_ignore)


def snapshot(ws: Workspace, reason: str) -> Path:
    base = Path(get_settings().snapshots_dir) / folder(ws).name
    base.mkdir(parents=True, exist_ok=True)
    number = sum(1 for p in base.iterdir() if p.is_dir()) + 1
    destination = base / f"{number:02d}_{reason}"
    shutil.copytree(folder(ws), destination, ignore=_ignore)
    return destination


# ---- reading ------------------------------------------------------------------------------


def _entries(root: Path) -> Iterator[tuple[str, Path]]:
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if not any(part in IGNORED for part in relative.parts):
            yield relative.as_posix(), path


def list_files(ws: Workspace) -> dict:
    # Flat map, same shape the frontend uses: {"app": {"type": "folder"}, "app/auth.py": {"type": "file", ...}}
    files: dict = {}
    for relative, path in _entries(folder(ws)):
        if path.is_dir():
            files[relative] = {"type": "folder"}
        else:
            files[relative] = {"type": "file", "content": path.read_text(encoding="utf-8", errors="replace")}
    return files


def read_file(ws: Workspace, path: str) -> dict:
    target = resolve_inside(folder(ws), path)
    if not target.is_file():
        raise NotFoundError(f"File {path} not found")
    return {"type": "file", "content": target.read_text(encoding="utf-8", errors="replace")}


# ---- changing (only through an open, unfinished part) ------------------------------------


def _check_parents_are_folders(root: Path, target: Path) -> None:
    for parent in target.parents:
        if parent == root:
            return
        if parent.is_file():
            raise ConflictError(f"{parent.relative_to(root).as_posix()} is a file, so it cannot contain other files")


def _log(db: Session, ws: Workspace, type: str, detail: dict) -> None:
    log_event(db, ws.participant_code, type, mode=ws.mode, detail=detail)
    db.commit()


def write_text(ws: Workspace, path: str, content: str) -> bool:
    """Writes a file into the workspace; returns True if it was created. Does not log or commit."""
    root = folder(ws).resolve()
    target = resolve_inside(root, path)
    if target.is_dir():
        raise ConflictError(f"{path} is a folder")
    _check_parents_are_folders(root, target)
    created = not target.exists()
    if created and sum(1 for _ in _entries(root)) >= MAX_FILES:
        raise ConflictError(f"A workspace can have at most {MAX_FILES} files and folders")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8", newline="")
    return created


def write_file(db: Session, ws: Workspace, path: str, content: str) -> dict:
    created = write_text(ws, path, content)
    _log(db, ws, "file_created" if created else "file_saved", {"path": clean_path(path), "chars": len(content)})
    return {"type": "file", "content": content}


def create_folder(db: Session, ws: Workspace, path: str) -> dict:
    root = folder(ws).resolve()
    target = resolve_inside(root, path)
    if target.exists():
        raise ConflictError(f"{path} already exists")
    _check_parents_are_folders(root, target)
    target.mkdir(parents=True)
    _log(db, ws, "folder_created", {"path": clean_path(path)})
    return {"type": "folder"}


def delete_path(db: Session, ws: Workspace, path: str) -> None:
    target = resolve_inside(folder(ws), path)
    if not target.exists():
        raise NotFoundError(f"{path} not found")
    if target.is_dir():
        shutil.rmtree(target)
    else:
        target.unlink()
    _log(db, ws, "file_deleted", {"path": clean_path(path)})


def rename_path(db: Session, ws: Workspace, from_path: str, to_path: str) -> None:
    root = folder(ws).resolve()
    source, target = resolve_inside(root, from_path), resolve_inside(root, to_path)
    if not source.exists():
        raise NotFoundError(f"{from_path} not found")
    if target.exists():
        raise ConflictError(f"{to_path} already exists")
    if target.is_relative_to(source):
        raise ConflictError("Cannot move a folder into itself")
    _check_parents_are_folders(root, target)
    target.parent.mkdir(parents=True, exist_ok=True)
    source.rename(target)
    _log(db, ws, "file_renamed", {"from": clean_path(from_path), "to": clean_path(to_path)})


# ---- notes box (single mode) ---------------------------------------------------------------


def save_notes(db: Session, ws: Workspace, text: str) -> str:
    if ws.mode != "single":
        raise ConflictError("The notes box is only used in single mode")
    ws.notes = text
    _log(db, ws, "notes_saved", {"chars": len(text)})
    return text
