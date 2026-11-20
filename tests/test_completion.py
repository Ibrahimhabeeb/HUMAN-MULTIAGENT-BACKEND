from pathlib import Path

import pytest

from config import get_settings
from models import Event
from services import study, workspace


def complete(client, content, *, path="app/auth.py", line=1, column=None):
    if column is None:
        column = len(content.split("\n")[line - 1]) + 1
    return client.post("/workspace/completions", json={
        "path": path, "content": content, "line": line, "column": column,
    })


def test_completions_require_an_open_study_part(client):
    assert complete(client, "value").status_code == 409


@pytest.mark.parametrize("mode", ["team", "single"])
def test_completions_suggest_variables_and_typed_methods_without_saving(client, db, enrol, tmp_path, mode):
    enrol(mode=mode)
    ws = study.current_workspace(db)
    original = workspace.read_file(ws, "app/auth.py")
    events_before = db.query(Event).count()
    sentinel = tmp_path / "must-not-exist"
    source = f"from pathlib import Path\nPath({str(sentinel)!r}).touch()\naccount_name: str = 'alice'\naccount_n"

    names = {item["name"] for item in complete(client, source, line=4).json()["items"]}
    assert "account_name" in names

    source += "ame.up"
    methods = {item["name"] for item in complete(client, source, line=4).json()["items"]}
    assert "upper" in methods
    assert workspace.read_file(ws, "app/auth.py") == original
    assert db.query(Event).count() == events_before
    assert not sentinel.exists()
    assert not Path(get_settings().snapshots_dir).exists()


def test_completions_resolve_classes_in_the_current_task(client, enrol):
    enrol(task_id="E")
    source = "from app.models import Account\naccount = Account(email='alice@example.test')\naccount.em"
    names = {item["name"] for item in complete(client, source, path="app/account.py", line=3).json()["items"]}
    assert "email" in names


@pytest.mark.parametrize("path", ["../secret.py", "/tmp/outside.py", "C:/secret.py", "app\\auth.py", "README.md"])
def test_completions_reject_invalid_and_non_python_paths(client, team, path):
    assert complete(client, "value", path=path).status_code == 422


def test_completions_reject_missing_files_large_buffers_and_invalid_positions(client, team):
    assert complete(client, "value", path="app/missing.py").status_code == 404
    assert complete(client, "x" * 100_001).status_code == 422
    assert complete(client, "value", line=1, column=99).status_code == 422
    assert complete(client, "value", line=2, column=1).status_code == 422
