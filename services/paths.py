from pathlib import Path

from services.errors import InvalidPathError

MAX_FILES = 1000
MAX_PATH_LENGTH = 300
_FORBIDDEN_CHARS = set('\\:*?"<>|')


def clean_path(path: str) -> str:
    # Workspace paths are relative, "/"-separated, and may never climb out of the workspace
    # (no "..", no leading "/").
    p = path.strip()
    if not p or len(p) > MAX_PATH_LENGTH:
        raise InvalidPathError("Path must be 1-300 characters")
    if p.startswith("/") or any(c in _FORBIDDEN_CHARS or ord(c) < 32 for c in p):
        raise InvalidPathError(f"Invalid characters in path: {path!r}")
    if any(part in ("", ".", "..") for part in p.split("/")):
        raise InvalidPathError(f"Invalid path segment in: {path!r}")
    return p


def resolve_inside(root: Path, path: str) -> Path:
    # Second line of defence: the resolved location (after links etc.) must still be inside the root.
    root = root.resolve()
    target = (root / clean_path(path)).resolve()
    if not target.is_relative_to(root):
        raise InvalidPathError(f"Path escapes the workspace: {path!r}")
    return target
