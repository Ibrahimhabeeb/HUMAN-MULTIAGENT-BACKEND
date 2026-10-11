import json
import os
import subprocess
import sys

from pydantic import ValidationError

from models import Workspace
from schemas.linting import Diagnostic, LintResult
from services import workspace
from services.errors import InvalidPathError, NotFoundError
from services.paths import clean_path, resolve_inside


class LintUnavailableError(Exception):
    pass


def check(ws: Workspace, path: str, content: str) -> LintResult:
    path = clean_path(path)
    target = resolve_inside(workspace.folder(ws), path)
    if not path.endswith(".py"):
        raise InvalidPathError("Only Python (.py) files can be linted")
    if not target.is_file():
        raise NotFoundError(f"File {path} not found")

    # Inspect the unsaved buffer, never execute it, save it, or apply Ruff fixes.
    # Isolated mode also prevents participant config from changing the study's rules.
    command = [
        sys.executable, "-m", "ruff", "check", "--isolated", "--no-cache", "--no-fix",
        "--output-format", "json", "--select", "E4,E7,E9,F", "--stdin-filename", str(target), "-",
    ]
    env = {k: v for k, v in os.environ.items() if not k.startswith(("PYTHON", "RUFF_"))}
    try:
        result = subprocess.run(
            command, input=content, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=10, env=env, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise LintUnavailableError("Python linting is unavailable. Try checking again.") from error
    if result.returncode not in (0, 1):
        raise LintUnavailableError("Python linting could not start. Check Ruff is installed in the backend environment.")
    try:
        issues = json.loads(result.stdout)
        diagnostics = [
            Diagnostic.model_validate({
                **issue,
                "severity": "warning" if issue["code"] in {"F401", "F841"} else "error",
            })
            for issue in issues
        ]
    except (ValueError, TypeError, KeyError, ValidationError) as error:
        raise LintUnavailableError("Python linting returned an unreadable result. Try checking again.") from error
    return LintResult(path=path, diagnostics=diagnostics)
