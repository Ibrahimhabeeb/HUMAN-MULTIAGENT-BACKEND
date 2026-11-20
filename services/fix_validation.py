"""Checks applied to a model-written Python edit before it changes a workspace."""

import ast
import json
import os
import subprocess
import sys
from collections import Counter


def _public_definitions(source: str) -> set[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return set()
    return {
        node.name
        for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and not node.name.startswith("_")
    }


def invalid_python_edit(path: str, before: str, after: str) -> str | None:
    """Reject newly introduced Python errors while tolerating pre-existing ones."""
    if not path.lower().endswith(".py"):
        return None
    try:
        ast.parse(after, filename=path)
    except SyntaxError as error:
        return f"{path} would have invalid Python syntax at line {error.lineno}: {error.msg}"

    removed = _public_definitions(before) - _public_definitions(after)
    if removed:
        return f"{path} would lose existing class or function definitions: {', '.join(sorted(removed))}"

    try:
        after_issues = _ruff_issues(path, after)
        if not after_issues:
            return None
        before_issues = _ruff_issues(path, before)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return "Python validation could not run; the edit was not applied"

    existing = Counter((issue["code"], issue["message"]) for issue in before_issues)
    for issue in after_issues:
        key = issue["code"], issue["message"]
        if existing[key]:
            existing[key] -= 1
            continue
        row = issue.get("location", {}).get("row", "?")
        return f"{path} would introduce {issue['code']} at line {row}: {issue['message']}"
    return None


def _ruff_issues(path: str, source: str) -> list[dict]:
    command = [
        sys.executable, "-m", "ruff", "check", "--isolated", "--no-cache", "--no-fix",
        "--output-format", "json", "--select", "E9,F821,F822,F823", "--stdin-filename", path, "-",
    ]
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("PYTHON", "RUFF_"))}
    result = subprocess.run(
        command, input=source, capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=10, check=False, env=environment,
    )
    if result.returncode not in (0, 1):
        raise ValueError("Ruff did not complete")
    return json.loads(result.stdout)
