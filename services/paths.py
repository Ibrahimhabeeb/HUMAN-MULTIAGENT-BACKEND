from schemas.project import FileNode, FolderNode
from services.errors import ConflictError, InvalidPathError

MAX_FILES = 1000
MAX_PATH_LENGTH = 300
_FORBIDDEN_CHARS = set('\\:*?"<>|')


def clean_path(path: str) -> str:
    # Project paths are relative, "/"-separated, and may never climb out of the project
    # (no "..", no leading "/"). The runner will write these files to disk later.
    p = path.strip()
    if not p or len(p) > MAX_PATH_LENGTH:
        raise InvalidPathError("Path must be 1-300 characters")
    if p.startswith("/") or any(c in _FORBIDDEN_CHARS or ord(c) < 32 for c in p):
        raise InvalidPathError(f"Invalid characters in path: {path!r}")
    if any(part in ("", ".", "..") for part in p.split("/")):
        raise InvalidPathError(f"Invalid path segment in: {path!r}")
    return p


def parents_of(path: str) -> list[str]:
    parts = path.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]


def ensure_parents(files: dict, path: str) -> None:
    for parent in parents_of(path):
        if files.get(parent, {}).get("type") == "file":
            raise ConflictError(f"{parent} is a file, so it cannot contain {path}")
        files.setdefault(parent, {"type": "folder"})


def normalise_files(nodes: dict[str, FolderNode | FileNode]) -> dict:
    if len(nodes) > MAX_FILES:
        raise InvalidPathError(f"A project can have at most {MAX_FILES} files and folders")
    files: dict = {}
    for raw_path, node in nodes.items():
        path = clean_path(raw_path)
        files[path] = node.model_dump() 
    for path in list(files):
        ensure_parents(files, path)
    return files
