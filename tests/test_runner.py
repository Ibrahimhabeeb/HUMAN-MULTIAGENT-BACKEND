import sys
from pathlib import Path
from unittest.mock import patch

from config import get_settings
from models import Event, UnitTestRecord
from services import runner

VULNERABILITY = {"description": "Query built from user input", "severity": "High", "file": "app/auth.py"}
PASSING = "def test_ok():\n    assert True\n"


def write(client, path, content):
    return client.put(f"/workspace/files/{path}", json={"content": content})


def run_tests(client):
    return client.post("/workspace/tests/run")


def test_reports_each_test_of_the_workspace(client, db, single, study_dirs):
    write(client, "tests/test_extra.py", PASSING)
    result = run_tests(client).json()

    assert result["status"] == "failed"  # the starter's functions are still stubs
    outcomes = {(t["file"], t["name"]): t["outcome"] for t in result["tests"]}
    assert outcomes == {
        ("tests/test_extra.py", "test_ok"): "passed",
        ("tests/test_functional.py", "test_registered_user_can_log_in"): "failed",
        ("tests/test_functional.py", "test_wrong_password_is_refused"): "failed",
        ("tests/test_functional.py", "test_username_must_be_unique"): "failed",
    }
    assert result["counts"] == {"passed": 1, "failed": 3, "error": 0, "skipped": 0}
    assert result["message"] == "1 passed, 3 failed"

    logged = db.query(Event).filter(Event.type == "tests_run").one()
    assert logged.detail["counts"] == result["counts"]
    assert (study_dirs / "snapshots" / "P01_A_single" / logged.detail["snapshot"] / "tests" / "test_extra.py").is_file()


def test_says_so_when_there_are_no_tests(client, single):
    client.delete("/workspace/files/tests/test_functional.py")
    result = run_tests(client).json()
    assert (result["status"], result["message"], result["tests"]) == ("no_tests", "There are no tests to run yet.", [])


def test_a_broken_test_file_is_reported(client, single):
    write(client, "tests/test_broken.py", "def test_x(:\n")
    result = run_tests(client).json()
    assert result["status"] == "error"
    assert "could not be collected" in result["message"]
    assert [t["outcome"] for t in result["tests"] if t["file"] == "tests/test_broken.py"] == ["error"]


def test_the_participants_code_gets_no_secrets(client, single, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-not-for-participants")
    write(client, "tests/test_env.py", "import os\n\n\ndef test_no_key():\n    assert 'OPENAI_API_KEY' not in os.environ\n")
    result = run_tests(client).json()
    assert [t["outcome"] for t in result["tests"] if t["file"] == "tests/test_env.py"] == ["passed"]


def test_slow_tests_are_stopped(client, single, monkeypatch):
    monkeypatch.setattr(get_settings(), "test_timeout_seconds", 2)
    write(client, "tests/test_slow.py", "import time\n\n\ndef test_slow():\n    time.sleep(30)\n")
    result = run_tests(client).json()
    assert result["status"] == "timed_out"


def unit_tests(client):
    return {t["name"]: (t["id"], t["status"], t["message"]) for t in client.get("/workspace/state").json()["tests"]}


def test_team_mode_keeps_each_unit_tests_latest_result(client, db, team):
    functional = ["test_registered_user_can_log_in", "test_wrong_password_is_refused", "test_username_must_be_unique"]
    before = unit_tests(client)
    assert {name: status for name, (_, status, _) in before.items()} == dict.fromkeys(functional, "open")

    run_tests(client)  # the starter's endpoints answer 501, so every test fails
    after = unit_tests(client)
    assert {name: (test_id, status) for name, (test_id, status, _) in after.items()} == {
        name: (before[name][0], "failed") for name in functional  # same ids: the run replaced each result
    }
    assert "501" in after["test_wrong_password_is_refused"][2]
    run = db.query(Event).filter(Event.type == "tests_run").one()
    assert (run.actor, run.detail["trigger"]) == ("human", "button")

    write(client, "tests/test_extra.py", "def test_ok():\n    assert False\n")  # the developer's own tests count too
    run_tests(client)
    assert unit_tests(client)["test_ok"][1] == "failed"
    write(client, "tests/test_extra.py", PASSING)
    run_tests(client)
    assert unit_tests(client)["test_ok"][1:] == ("passed", None)

    write(client, "app/auth.py", "import nonexistent_workspace_dependency\n")  # test_functional.py can't run at all
    run_tests(client)
    latest = unit_tests(client)
    assert latest["test_wrong_password_is_refused"][1:] == (
        "failed", "ModuleNotFoundError in app/auth.py:1: No module named 'nonexistent_workspace_dependency'",
    )
    assert latest["test_ok"][1] == "open"  # pytest runs nothing when a file can't be collected
    client.delete("/workspace/files/tests/test_extra.py")
    run_tests(client)
    assert "test_ok" not in unit_tests(client)


def test_single_mode_keeps_unit_test_results_without_showing_them(client, db, single):
    run_tests(client)
    rows = db.query(UnitTestRecord).all()
    assert len(rows) == 3 and {(row.source, row.status) for row in rows} == {("system", "failed")}
    assert client.get("/workspace/state").status_code == 409  # still not shown in single mode


def test_a_test_file_that_cannot_be_read_keeps_its_tests_as_failed(client, team):
    write(client, "tests/test_functional.py", "def test_x(:\n")
    run_tests(client)
    statuses = {name: status for name, (_, status, _) in unit_tests(client).items()}
    assert set(statuses.values()) == {"failed"} and len(statuses) == 3


def test_a_finished_part_cannot_run_tests(client, single):
    client.post("/study/done")
    assert run_tests(client).status_code == 409


def test_source_indentation_error_points_to_the_source_not_pytest(client, single):
    content = "GENERIC_LOGIN_ERROR = 'Invalid username or password'\n\n    time_limit = 15\n"
    write(client, "app/auth.py", content)
    result = run_tests(client).json()
    assert result["status"] == "error"
    assert result["counts"]["passed"] == result["counts"]["failed"] == 0
    assert "Tests could not be collected" in result["message"]
    (case,) = result["tests"]
    assert case["file"] == "tests/test_functional.py"
    assert case["message"] == "IndentationError in app/auth.py:3: unexpected indent"
    assert client.get("/workspace/files/app/auth.py").json()["content"] == content


def test_missing_workspace_import_is_identified_as_an_import_error(client, single):
    write(client, "app/auth.py", "import nonexistent_workspace_dependency\n")
    result = run_tests(client).json()
    assert result["status"] == "error"
    assert result["tests"][0]["message"] == (
        "ModuleNotFoundError in app/auth.py:1: No module named 'nonexistent_workspace_dependency'"
    )


def test_valid_login_code_can_use_bcrypt_in_the_workspace_environment(client, single):
    write(client, "app/auth.py", '''import sqlite3

import bcrypt
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.db import get_db

router = APIRouter(prefix="/auth")


class Credentials(BaseModel):
    username: str
    password: str


@router.post("/register", status_code=201)
def register(body: Credentials, conn: sqlite3.Connection = Depends(get_db)):
    hashed = bcrypt.hashpw(body.password.encode(), bcrypt.gensalt(rounds=4)).decode()
    try:
        cursor = conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (body.username, hashed))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=409, detail="Username already taken")
    return {"id": cursor.lastrowid, "username": body.username}


@router.post("/login")
def login(body: Credentials, conn: sqlite3.Connection = Depends(get_db)):
    row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (body.username,)).fetchone()
    if row is None or not bcrypt.checkpw(body.password.encode(), row["password_hash"].encode()):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    return {"message": "Logged in"}
''')
    result = run_tests(client).json()
    assert result["status"] == "passed"
    assert result["counts"] == {"passed": 3, "failed": 0, "error": 0, "skipped": 0}


def test_workspace_tests_use_the_server_python_and_ignore_inherited_python_paths(client, single, monkeypatch):
    monkeypatch.setenv("PYTHONHOME", "not-a-python-installation")
    monkeypatch.setenv("PYTHONPATH", "not-the-workspace")
    original = runner.subprocess.run
    with patch.object(runner.subprocess, "run", wraps=original) as launch:
        response = run_tests(client)
    assert response.status_code == 200
    command = launch.call_args.args[0]
    assert Path(command[0]) == Path(sys.executable)
    assert command[1:3] == ["-m", "pytest"]
    env = launch.call_args.kwargs["env"]
    assert "PYTHONHOME" not in env and "PYTHONPATH" not in env
    assert response.json()["counts"]["failed"] == 3  # functional tests ran, not an environment startup error
