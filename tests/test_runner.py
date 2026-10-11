import sys
from pathlib import Path
from unittest.mock import patch

from config import get_settings
from models import Event
from services import approvals, runner, study

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
    }
    assert result["counts"] == {"passed": 1, "failed": 2, "error": 0, "skipped": 0}
    assert result["message"] == "1 passed, 2 failed"

    logged = db.query(Event).filter(Event.type == "tests_run").one()
    assert logged.detail["counts"] == result["counts"]
    assert (study_dirs / "snapshots" / "P01_A" / logged.detail["snapshot"] / "tests" / "test_extra.py").is_file()


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


def test_team_mode_keeps_each_security_tests_latest_result(client, db, team):
    client.post("/workspace/state/vulnerabilities", json=VULNERABILITY)
    test = {"path": "tests/test_security_login.py", "content": PASSING, "vulnerability_ids": ["V1"]}
    approval = approvals.request_approval(db, study.editable_workspace(db), "verifier", "propose_test", test)
    client.post(f"/approvals/{approval.id}/decide", json={"decision": "approve"})

    def latest():
        (security_test,) = client.get("/workspace/state").json()["tests"]
        return security_test["vulnerability_ids"], security_test["passed"], security_test["result"]

    run_tests(client)
    assert latest() == (["V1"], True, "1 of 1 tests passed")
    write(client, "tests/test_security_login.py", "def test_ok():\n    assert False\n")
    run_tests(client)
    assert latest() == (["V1"], False, "0 of 1 tests passed")
    client.delete("/workspace/files/tests/test_security_login.py")
    run_tests(client)
    assert latest() == (["V1"], None, "No result in the latest run")


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
    write(client, "app/auth.py", '''import bcrypt


def register_user(conn, username, password):
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=4)).decode()
    conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hashed))
    conn.commit()


def login(conn, username, password):
    row = conn.execute("SELECT password_hash FROM users WHERE username = ?", (username,)).fetchone()
    if row and bcrypt.checkpw(password.encode(), row["password_hash"].encode()):
        return True, "Logged in"
    return False, "Invalid username or password"
''')
    result = run_tests(client).json()
    assert result["status"] == "passed"
    assert result["counts"] == {"passed": 2, "failed": 0, "error": 0, "skipped": 0}


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
    assert response.json()["counts"]["failed"] == 2  # functional tests ran, not an environment startup error
