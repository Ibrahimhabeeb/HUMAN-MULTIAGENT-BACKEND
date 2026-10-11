import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest

from config import get_settings
from models import Event
from services import linting, study, workspace


def lint(client, content, path="app/auth.py"):
    return client.post("/workspace/lint", json={"path": path, "content": content})


def test_lint_requires_a_session(client):
    assert lint(client, "print('ok')").status_code == 409


@pytest.mark.parametrize("mode", ["team", "single"])
def test_lint_checks_unsaved_code_in_both_modes_without_changing_or_running_it(client, db, enrol, mode, tmp_path):
    enrol(mode=mode)
    ws = study.current_workspace(db)
    original = workspace.read_file(ws, "app/auth.py")
    events_before = db.query(Event).count()
    sentinel = tmp_path / "must-not-exist"
    response = lint(client, f"from pathlib import Path\nPath({str(sentinel)!r}).touch()\nprint(undefined_name)\n")
    assert response.status_code == 200
    result = response.json()
    assert result["path"] == "app/auth.py"
    issue = next(i for i in result["diagnostics"] if i["code"] == "F821")
    assert issue["location"] == {"row": 3, "column": 7}
    assert issue["severity"] == "error"
    assert workspace.read_file(ws, "app/auth.py") == original
    assert db.query(Event).count() == events_before
    assert not sentinel.exists()
    assert not (workspace.folder(ws) / ".ruff_cache").exists()
    assert not Path(get_settings().snapshots_dir).exists()


def test_indentation_and_syntax_errors_have_positions(client, team):
    response = lint(client, "    value = 1\n")
    issue = response.json()["diagnostics"][0]
    assert issue["code"] == "invalid-syntax"
    assert issue["message"] == "Unexpected indentation"
    assert issue["location"]["row"] == 1
    assert issue["severity"] == "error"


def test_unused_import_is_a_warning_and_clean_code_clears_results(client, team):
    result = lint(client, "import os\n").json()
    assert [(i["code"], i["severity"]) for i in result["diagnostics"]] == [("F401", "warning")]
    assert lint(client, "value = 1\nprint(value)\n").json()["diagnostics"] == []


@pytest.mark.parametrize("path", ["../secret.py", "/tmp/outside.py", "C:/secret.py", "app\\auth.py", "app/../auth.py", "README.md"])
def test_lint_rejects_invalid_and_non_python_paths(client, team, path):
    assert lint(client, "print('ok')", path).status_code == 422


def test_lint_rejects_missing_files_and_oversized_buffers(client, team):
    assert lint(client, "print('ok')", "app/missing.py").status_code == 404
    assert lint(client, "x" * 1_000_001).status_code == 422


def test_lint_ignores_participant_config_and_uses_backend_interpreter(client, db, team, monkeypatch):
    ws = study.current_workspace(db)
    (workspace.folder(ws) / "ruff.toml").write_text('lint.ignore = ["F821"]\n', encoding="utf-8")
    monkeypatch.setenv("PYTHONHOME", "broken-python")
    monkeypatch.setenv("PYTHONPATH", "untrusted-modules")
    monkeypatch.setenv("RUFF_OUTPUT_FORMAT", "full")
    real_run = subprocess.run
    spy = Mock(wraps=real_run)
    monkeypatch.setattr(linting.subprocess, "run", spy)
    result = lint(client, "print(missing_name)\n").json()
    assert result["diagnostics"][0]["code"] == "F821"
    args, kwargs = spy.call_args
    assert args[0][:4] == [sys.executable, "-m", "ruff", "check"]
    assert "--no-fix" in args[0] and "--isolated" in args[0]
    assert not any(key in kwargs["env"] for key in ("PYTHONHOME", "PYTHONPATH", "RUFF_OUTPUT_FORMAT"))
    assert kwargs["input"] == "print(missing_name)\n"


@pytest.mark.parametrize("failure", ["timeout", "missing", "malformed"])
def test_lint_failures_are_not_reported_as_clean_code(client, team, monkeypatch, failure):
    def fail(*args, **kwargs):
        if failure == "timeout":
            raise subprocess.TimeoutExpired("ruff", 10)
        return subprocess.CompletedProcess([], 2 if failure == "missing" else 0, stdout="not JSON", stderr="")

    monkeypatch.setattr(linting.subprocess, "run", fail)
    response = lint(client, "print('ok')")
    assert response.status_code == 503
    assert "linting" in response.json()["detail"]
