import base64
import io
import json
from pathlib import Path
from urllib.error import URLError

import pytest
from pydantic import SecretStr, ValidationError

from config import Settings, get_settings
from models import Event, Participant, SurveyResponse
from services import runner, sandbox, sessions, study, workspace


def production_settings(tmp_path):
    return {
        "_env_file": None, "app_env": "production", "database_url": "postgresql+psycopg://study:example@db/study",
        "llm_model": "openai:test-model", "llm_api_key": "example-key", "test_runner_url": "http://runner:9000",
        "test_runner_token": "example-token", "allowed_hosts": ["study.example.com"],
        "workspaces_dir": str(tmp_path / "workspaces"), "snapshots_dir": str(tmp_path / "snapshots"),
    }


@pytest.mark.parametrize("changes", [
    {"database_url": "sqlite:///data.db"}, {"test_runner_url": None}, {"test_runner_token": None},
    {"allowed_hosts": ["*"]}, {"llm_model": None}, {"workspaces_dir": "relative/path"},
])
def test_production_rejects_unsafe_or_missing_settings(tmp_path, changes):
    with pytest.raises(ValidationError):
        Settings(**(production_settings(tmp_path) | changes))


def test_production_configuration_is_explicit(tmp_path):
    assert Settings(**production_settings(tmp_path)).app_env == "production"


def test_production_never_falls_back_to_local_execution(tmp_path, monkeypatch):
    monkeypatch.setattr(get_settings(), "app_env", "production")
    monkeypatch.setattr(get_settings(), "test_runner_url", None)
    monkeypatch.setattr(runner.subprocess, "run", lambda *args, **kwargs: pytest.fail("Local code execution attempted"))
    code, cases, output = runner._pytest(tmp_path)
    assert code == 3 and cases == []
    assert "No code was executed" in output


def test_private_runner_result_uses_existing_test_result_format(tmp_path, monkeypatch):
    monkeypatch.setattr(get_settings(), "test_runner_url", "http://runner:9000")
    monkeypatch.setattr(sandbox, "run", lambda folder: {
        "code": 0, "report": '<testsuite><testcase file="tests/test_one.py" name="test_one"/></testsuite>',
        "output": "1 passed",
    })
    code, cases, output = runner._pytest(tmp_path)
    assert code == 0 and output == "1 passed"
    assert (cases[0].file, cases[0].name, cases[0].outcome) == ("tests/test_one.py", "test_one", "passed")


def test_runner_failure_does_not_trigger_local_execution(tmp_path, monkeypatch):
    monkeypatch.setattr(get_settings(), "test_runner_url", "http://runner:9000")

    def unavailable(folder):
        raise URLError("internal transport details")

    monkeypatch.setattr(sandbox, "run", unavailable)
    monkeypatch.setattr(runner.subprocess, "run", lambda *args, **kwargs: pytest.fail("Local code execution attempted"))
    code, cases, output = runner._pytest(tmp_path)
    assert code == 3 and cases == []
    assert "unavailable" in output and "internal transport" not in output


def test_runner_upload_contains_only_files_and_uses_private_authentication(tmp_path, monkeypatch):
    (tmp_path / "app").mkdir()
    (tmp_path / "app/code.py").write_text("value = 1", encoding="utf-8")
    monkeypatch.setattr(get_settings(), "test_runner_url", "http://runner:9000")
    monkeypatch.setattr(get_settings(), "test_runner_token", SecretStr("private-test-token"))

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "http://runner:9000/run"
            assert request.get_header("Authorization") == "Bearer private-test-token"
            payload = json.loads(request.data)
            assert set(payload) == {"files"}
            assert payload["files"] == [{"path": "app/code.py", "content": base64.b64encode(b"value = 1").decode()}]
            return io.BytesIO(b'{"code":0,"report":"<testsuite/>","output":"done"}')

    monkeypatch.setattr(sandbox, "build_opener", lambda *args: Opener())
    assert sandbox.run(tmp_path)["code"] == 0


def test_runner_rejects_oversized_workspace_before_network_request(tmp_path, monkeypatch):
    monkeypatch.setattr(get_settings(), "test_runner_url", "http://runner:9000")
    monkeypatch.setattr(get_settings(), "test_runner_token", SecretStr("private-test-token"))
    monkeypatch.setattr(sandbox, "MAX_INPUT_BYTES", 3)
    (tmp_path / "large.py").write_text("1234", encoding="utf-8")
    with pytest.raises(ValueError, match="input limit"):
        sandbox.run(tmp_path)


def test_unit_tests_use_a_copy_of_the_recorded_snapshot(client, db, team, monkeypatch):
    ws = study.current_workspace(db)
    original = workspace.read_file(ws, "app/auth.py")["content"]

    def inspect_execution(folder):
        workspace.write_text(ws, "app/auth.py", "# an edit arriving after the snapshot\n")
        assert (folder / "app/auth.py").read_text(encoding="utf-8") == original
        (folder / "app/auth.py").write_text("# changed by test code", encoding="utf-8")
        return 0, [], ""

    monkeypatch.setattr(runner, "_pytest", inspect_execution)
    runner.run_tests(db, ws)
    event = db.query(Event).filter(Event.type == "tests_run").one()
    saved = Path(get_settings().snapshots_dir) / workspace.folder(ws).name / event.detail["snapshot"]
    assert (saved / "app/auth.py").read_text(encoding="utf-8") == original
    assert workspace.read_file(ws, "app/auth.py")["content"].startswith("# an edit arriving")


def test_pending_sessions_expire_without_expiring_consented_sessions(client, db, team, monkeypatch):
    clock = [100.0]
    monkeypatch.setattr(sessions, "monotonic", lambda: clock[0])
    monkeypatch.setattr(get_settings(), "pending_session_ttl_seconds", 60)
    token = sessions.create()
    clock[0] = 161.0
    assert not sessions.bind(db, token)
    assert client.get("/study/state").json()["participant"] == team["participant"]


def test_pending_session_cap_returns_a_clear_error(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "max_pending_sessions", 1)
    response = client.post("/study/session", json={"mode": "team"})
    assert response.status_code == 409
    assert "busy" in response.json()["detail"]


def test_readiness_checks_database_without_a_participant_session(client):
    assert client.get("/ready").json() == {"status": "ready"}


def test_survey_export_excludes_sample_participants(db, sample_questionnaire, tmp_path):
    import export

    db.add(Participant(code="SYN001", status="complete", mode="team"))
    db.add(SurveyResponse(participant_code="SYN001", condition="team", item="confidence", value="5", value_num=5))
    db.commit()
    assert export.export(db, tmp_path / "survey.csv", include_pilots=True) == 0
