from collections.abc import Generator
from contextlib import contextmanager

from sqlalchemy.orm import Session

from schemas.project import FileNode, FolderNode
from services.errors import ConflictError, NotFoundError
from services.paths import MAX_FILES, clean_path, ensure_parents, normalise_files
from services.projects import get_project, open_session


@contextmanager
def _edit_files(db: Session, project_id: str, session_id: str) -> Generator[dict]:
    project = get_project(db, project_id)
    open_session(db, project_id, session_id)
    files = dict(project.files)
    yield files
    if len(files) > MAX_FILES:
        raise ConflictError(f"A project can have at most {MAX_FILES} files and folders")
    project.files = files
    db.commit()


def list_files(db: Session, project_id: str) -> dict:
    return get_project(db, project_id).files


def read_file(db: Session, project_id: str, path: str) -> dict:
    node = get_project(db, project_id).files.get(clean_path(path))
    if node is None or node["type"] != "file":
        raise NotFoundError(f"File {path} not found")
    return node


def write_file(db: Session, project_id: str, session_id: str, path: str, content: str) -> dict:
    path = clean_path(path)
    with _edit_files(db, project_id, session_id) as files:
        if files.get(path, {}).get("type") == "folder":
            raise ConflictError(f"{path} is a folder")
        ensure_parents(files, path)
        files[path] = FileNode(content=content).model_dump()
    return files[path]


def create_folder(db: Session, project_id: str, session_id: str, path: str) -> dict:
    path = clean_path(path)
    with _edit_files(db, project_id, session_id) as files:
        if path in files:
            raise ConflictError(f"{path} already exists")
        ensure_parents(files, path)
        files[path] = FolderNode().model_dump()
    return files[path]


def _is_within(path: str, ancestor: str) -> bool:
    return path == ancestor or path.startswith(ancestor + "/")


def delete_path(db: Session, project_id: str, session_id: str, path: str) -> int:
    path = clean_path(path)
    with _edit_files(db, project_id, session_id) as files:
        if path not in files:
            raise NotFoundError(f"{path} not found")
        removed = [p for p in files if _is_within(p, path)]
        for p in removed:
            del files[p]
    return len(removed)


def rename_path(db: Session, project_id: str, session_id: str, from_path: str, to_path: str) -> None:
    from_path, to_path = clean_path(from_path), clean_path(to_path)
    with _edit_files(db, project_id, session_id) as files:
        if from_path not in files:
            raise NotFoundError(f"{from_path} not found")
        if to_path in files:
            raise ConflictError(f"{to_path} already exists")
        if _is_within(to_path, from_path):
            raise ConflictError("Cannot move a folder into itself")
        moved = {p: files.pop(p) for p in [p for p in files if _is_within(p, from_path)]}
        for old, node in moved.items():
            files[to_path + old[len(from_path) :]] = node
        ensure_parents(files, to_path)


def replace_files(db: Session, project_id: str, session_id: str, nodes: dict[str, FolderNode | FileNode]) -> dict:
    new_files = normalise_files(nodes)
    with _edit_files(db, project_id, session_id) as files:
        files.clear()
        files.update(new_files)
    return new_files
