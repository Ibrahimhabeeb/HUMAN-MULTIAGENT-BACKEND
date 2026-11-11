from threading import Lock

import jedi

from models import Workspace
from schemas.completion import CompletionItem, CompletionResult
from services import workspace
from services.errors import InvalidInputError, InvalidPathError, NotFoundError
from services.paths import clean_path, resolve_inside

_jedi_lock = Lock()


def suggest(ws: Workspace, path: str, content: str, line: int, column: int) -> CompletionResult:
    path = clean_path(path)
    target = resolve_inside(workspace.folder(ws), path)
    if not path.endswith(".py"):
        raise InvalidPathError("Completions are available only for Python files")
    if not target.is_file():
        raise NotFoundError(f"File {path} not found")

    lines = content.split("\n")
    if line > len(lines) or column > len(lines[line - 1].rstrip("\r")) + 1:
        raise InvalidInputError("Cursor position is outside the document")

    # Jedi inspects the unsaved buffer statically; it does not run participant code.
    with _jedi_lock:
        script = jedi.Script(code=content, path=target, project=jedi.Project(path=workspace.folder(ws).resolve()))
        items = [
            CompletionItem(name=item.name, type=item.type, description=item.description)
            for item in script.complete(line=line, column=column - 1)[:100]
        ]
    return CompletionResult(items=items)
