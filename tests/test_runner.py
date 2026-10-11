from config import get_settings
from models import Event
from services import approvals, study

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
    assert result["status"] == "failed"
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
