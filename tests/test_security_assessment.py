import json
import shutil
from pathlib import Path

import pytest
from test_starter_tasks import REFERENCES, TARGETS, UNSAFE_REFERENCES

from config import get_settings
from models import Event, UnitTestRecord, Workspace
from services import security_assessment, workspace

STORAGE_SAFE = '''
from pathlib import Path
STORAGE_DIR = Path(__file__).resolve().parent.parent / "files"

def list_files():
    return sorted(path.name for path in STORAGE_DIR.iterdir() if path.is_file())

def download(filename):
    root = STORAGE_DIR.resolve()
    target = (root / filename).resolve()
    if not target.is_relative_to(root):
        raise PermissionError("File unavailable")
    return target.read_bytes()
'''
STORAGE_UNSAFE = '''
from pathlib import Path
STORAGE_DIR = Path(__file__).resolve().parent.parent / "files"

def list_files():
    return sorted(path.name for path in STORAGE_DIR.iterdir() if path.is_file())

def download(filename):
    return (STORAGE_DIR / filename).read_bytes()
'''


@pytest.mark.parametrize("task_id", list(TARGETS))
@pytest.mark.parametrize("secure", [True, False])
def test_private_suites_distinguish_safe_and_vulnerable_code(tmp_path, task_id, secure):
    source = Path(get_settings().starter_dir) / f"task_{task_id}"
    snapshot = tmp_path / "submission"
    shutil.copytree(source, snapshot)
    if task_id == "B":
        code = STORAGE_SAFE if secure else STORAGE_UNSAFE
    else:
        code = REFERENCES[task_id] if secure else UNSAFE_REFERENCES[task_id]
    if task_id == "D" and not secure:
        code += "\ndef export_preferences(settings):\n    return pickle.dumps(settings)\n"
    (snapshot / TARGETS[task_id][0]).write_text(code, encoding="utf-8")
    before = {path.relative_to(snapshot): path.read_bytes() for path in snapshot.rglob("*") if path.is_file()}
    result = security_assessment.evaluate_snapshot(snapshot, task_id)
    assert result["status"] == ("passed" if secure else "failed"), result
    assert result["all_passed"] is secure
    assert sum(result["counts"].values()) == result["expected"]
    assert result["counts"]["error"] == 0
    assert result["counts"]["skipped"] == 0
    assert result["not_run"] == 0
    assert len(result["suite_sha256"]) == 64
    assert before == {path.relative_to(snapshot): path.read_bytes() for path in snapshot.rglob("*") if path.is_file()}


@pytest.mark.parametrize("mode", ["team", "single"])
def test_finish_queues_hidden_checks_without_public_or_agent_results(client, db, enrol, mode, assess_pending):
    enrol(mode=mode, task_id="C")
    ws = db.query(Workspace).one()
    files = client.get("/workspace/files").json()
    assert not any("security_tests" in name or "test_security" in name for name in files)
    public = client.post("/workspace/tests/run").json()
    assert sum(public["counts"].values()) == 3
    assert db.query(Event).filter(Event.type == security_assessment.EVENT_TYPE).count() == 0
    response = client.post("/study/done")
    assert response.status_code == 200
    assert response.json()["screen"] == "part_complete"
    assert "security_tests_run" not in response.text
    assert db.query(Event).filter(Event.type == security_assessment.EVENT_TYPE).count() == 0
    assess_pending()
    assert db.query(UnitTestRecord).count() == 3
    event = db.query(Event).filter(Event.type == security_assessment.EVENT_TYPE).one()
    assert event.mode == mode
    assert event.actor == "system"
    assert event.detail["task_id"] == "C"
    assert event.detail["expected"] == 12
    assert event.detail["all_passed"] is False
    assert event.detail["snapshot"].endswith("_done")
    saved = Path(get_settings().snapshots_dir) / workspace.folder(ws).name / event.detail["snapshot"]
    assert not any("test_security" in path.name for path in saved.rglob("*"))
    from agents.context import build_context
    context = build_context(ws)
    assert "security_tests_run" not in str(context)
    assert not any("test_security" in name for name in context.files)


def test_timeout_and_missing_source_never_count_as_a_security_pass(tmp_path, monkeypatch):
    snapshot = tmp_path / "submission"
    (snapshot / "app").mkdir(parents=True)
    monkeypatch.setattr(security_assessment.runner, "_pytest", lambda folder: (None, [], "timed out"))
    result = security_assessment.evaluate_snapshot(snapshot, "B")
    assert result["status"] == "timed_out"
    assert result["expected"] == result["not_run"] == 8
    assert result["all_passed"] is False
    missing = security_assessment.evaluate_snapshot(tmp_path / "missing", "C")
    assert missing["status"] == "error"
    assert missing["expected"] == missing["not_run"] == 12
    assert missing["all_passed"] is False


def test_repeated_assessment_of_the_same_submission_is_idempotent(client, db, team, monkeypatch, assess_pending):
    result = {
        "suite_version": "1", "suite_sha256": "a" * 64, "expected": 12,
        "counts": {"passed": 12, "failed": 0, "error": 0, "skipped": 0},
        "tests": [{"name": "test_example", "outcome": "passed"}],
        "status": "passed", "all_passed": True, "not_run": 0, "output": "",
    }
    calls = []

    def evaluate(snapshot, task_id):
        calls.append(task_id)
        return result.copy()

    monkeypatch.setattr(security_assessment, "evaluate_snapshot", evaluate)
    client.post("/study/done")
    assess_pending()
    ws = db.query(Workspace).one()
    event = db.query(Event).filter(Event.type == security_assessment.EVENT_TYPE).one()
    saved = Path(get_settings().snapshots_dir) / workspace.folder(ws).name / event.detail["snapshot"]
    security_assessment.assess(db, ws, saved)
    assert calls == ["A"]
    assert db.query(Event).filter(Event.type == security_assessment.EVENT_TYPE).count() == 1


def test_finish_retains_a_failed_assessment_in_the_database(client, db, team, monkeypatch, tmp_path, assess_pending):
    monkeypatch.setattr(security_assessment, "SUITES", tmp_path / "missing-suites")
    assert client.post("/study/done").status_code == 200
    assess_pending()
    event = db.query(Event).filter(Event.type == security_assessment.EVENT_TYPE).one()
    assert event.detail["status"] == "error"
    assert event.detail["all_passed"] is False
    assert event.detail["workspace_id"] == db.query(Workspace).one().id


def test_hidden_suite_catalogue_covers_every_task():
    catalogue = json.loads((security_assessment.SUITES / "manifest.json").read_text())
    assert set(catalogue["tasks"]) == set(TARGETS)
    assert sum(spec["expected"] for spec in catalogue["tasks"].values()) == 77
