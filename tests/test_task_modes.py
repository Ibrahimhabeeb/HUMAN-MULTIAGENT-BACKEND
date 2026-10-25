from pathlib import Path

import pytest

import withdraw
from config import get_settings
from models import Event, Participant, Workspace
from services import approvals, content, study, workspace


@pytest.mark.parametrize("task_id, source", [
    ("A", "app/auth.py"), ("B", "app/storage.py"), ("C", "app/comments.py"),
    ("D", "app/preferences.py"), ("E", "app/account.py"),
])
@pytest.mark.parametrize("first_mode", ["team", "single"])
def test_chosen_task_has_two_independent_mode_attempts(client, db, enrol, task_id, source, first_mode):
    first = enrol(mode=first_mode, task_id=task_id)
    second_mode = "single" if first_mode == "team" else "team"
    original = client.get(f"/workspace/files/{source}").json()["content"]
    assert first["task"]["id"] == task_id
    client.put(f"/workspace/files/{source}", json={"content": "# first attempt"})
    client.put("/workspace/files/tests/test_first_attempt.py", json={"content": "def test_first():\n    assert True\n"})
    ws = study.current_workspace(db)
    if first_mode == "team":
        approvals.request_approval(db, ws, "threat_modeller", "propose_assumption", {"text": "First attempt only"})
    else:
        client.put("/workspace/notes", json={"text": "First attempt notes"})
    assert client.post("/study/done").json()["screen"] == "part_complete"

    study.reset_memory()  # the selected task comes from persisted part 1, not server memory
    second = client.post("/study/mode", json={"mode": second_mode}).json()
    assert (second["screen"], second["part"], second["mode"], second["task"]) == ("ide", 2, second_mode, first["task"])
    assert client.get(f"/workspace/files/{source}").json()["content"] == original
    assert client.get("/workspace/files/tests/test_first_attempt.py").status_code == 404
    assert client.get("/approvals").json() == []
    assert client.get("/chat").json() == {"team" if second_mode == "team" else "assistant": []}
    if second_mode == "single":
        assert client.get("/workspace/notes").json()["text"] == ""
    else:
        state = client.get("/workspace/state").json()
        assert state["assumptions"] == [] and state["vulnerabilities"] == [] and state["tests"] == []
    client.put(f"/workspace/files/{source}", json={"content": "# second attempt"})
    rows = db.query(Workspace).order_by(Workspace.part).all()
    assert workspace.folder(rows[0]) != workspace.folder(rows[1])
    assert workspace.read_file(rows[0], source)["content"] == "# first attempt"
    assert workspace.read_file(rows[1], source)["content"] == "# second attempt"

    assert client.post("/study/mode", json={"mode": first_mode}).json()["screen"] == "part_complete"
    assert client.get(f"/workspace/files/{source}").json()["content"] == "# first attempt"
    assert client.put(f"/workspace/files/{source}", json={"content": "cannot overwrite"}).status_code == 409
    assert client.post("/study/mode", json={"mode": second_mode}).json()["screen"] == "ide"
    done = client.post("/study/done").json()
    assert done["screen"] == "questionnaire"
    assert [(part["mode"], part["task_id"]) for part in done["parts"]] == [(first_mode, task_id), (second_mode, task_id)]
    snapshot_root = Path(get_settings().snapshots_dir)
    assert (snapshot_root / f"P01_{task_id}_{first_mode}" / "01_done" / source).read_text(encoding="utf-8") == "# first attempt"
    assert (snapshot_root / f"P01_{task_id}_{second_mode}" / "01_done" / source).read_text(encoding="utf-8") == "# second attempt"


@pytest.mark.parametrize("task_id", ["A", "B", "C", "D", "E"])
def test_task_selection_before_consent_stores_nothing(client, db, study_dirs, task_id):
    initial = client.get("/study/state").json()
    assert initial["available_tasks"] == [workspace.task_info(task) for task in ["A", "B", "C", "D", "E"]]
    assert [task["cwe"] for task in initial["available_tasks"]] == ["CWE-89", "CWE-22", "CWE-79", "CWE-502", "CWE-352"]
    state = client.post("/study/start", json={"pilot": True, "task_id": task_id}).json()
    assert state["task"] == {"id": task_id, "label": workspace.task_label(task_id)}
    assert client.get("/study/state").json()["task"] == state["task"]
    client.post("/study/continue")
    assert db.query(Participant).count() == 0
    assert db.query(Event).count() == 0
    assert not (study_dirs / "workspaces").exists()
    assert client.post("/study/consent", json={"consent_version": content.load("consent")[0]}).json()["task"]["id"] == task_id


@pytest.mark.parametrize("task_id", ["F", "../task_A", "", None])
def test_unknown_tasks_are_rejected_without_creating_a_session(client, db, task_id):
    assert client.post("/study/start", json={"task_id": task_id}).status_code == 422
    assert client.get("/study/state").json()["screen"] == "start"
    assert db.query(Participant).count() == 0


def test_legacy_first_attempt_remains_readable_and_does_not_collide_with_the_new_mode(client, db, team):
    ws = study.current_workspace(db)
    current = workspace.folder(ws)
    legacy = current.with_name("P01_A")
    current.rename(legacy)
    assert workspace.folder(ws) == legacy
    client.put("/workspace/files/app/auth.py", json={"content": "# legacy participant code"})
    client.post("/study/done")
    second = client.post("/study/mode", json={"mode": "single"}).json()
    assert second["task"]["id"] == "A"
    second_ws = study.current_workspace(db)
    assert workspace.folder(second_ws).name == "P01_A_single"
    assert "def login" in workspace.read_file(second_ws, "app/auth.py")["content"]
    assert (legacy / "app/auth.py").read_text(encoding="utf-8") == "# legacy participant code"
    assert (Path(get_settings().snapshots_dir) / "P01_A" / "01_done" / "app/auth.py").is_file()
    missing = workspace.folder(second_ws).with_name("missing-second-attempt")
    workspace.folder(second_ws).rename(missing)
    assert workspace.folder(second_ws).name == "P01_A_single"  # never read the first mode as a fallback


def test_previously_assigned_legacy_second_task_is_preserved(client, db, team):
    client.post("/study/done")
    # An existing record from the previous A-then-B workflow must not be rewritten.
    old = Workspace(participant_code="P01", mode="single", task_id="B", part=2, security_state={}, notes="Old notes")
    db.add(old)
    db.flush()
    workspace.create_from_starter(old)
    canonical = workspace.folder(old)
    legacy = canonical.with_name("P01_B")
    canonical.rename(legacy)
    db.commit()
    state = client.post("/study/mode", json={"mode": "single"}).json()
    assert state["task"]["id"] == "B"
    assert workspace.folder(old) == legacy
    assert client.get("/workspace/notes").json()["text"] == "Old notes"
    assert client.get("/workspace/files/app/storage.py").status_code == 200


def test_withdraw_removes_both_mode_workspaces_and_snapshots(client, db, team):
    client.post("/study/done")
    client.post("/study/mode", json={"mode": "single"})
    client.post("/study/done")
    client.post("/study/restart")
    removed = withdraw.withdraw(db, "P01")
    assert len(removed) == 4
    assert {path.name for path in removed} == {"P01_A_team", "P01_A_single"}
    assert all(not path.exists() for path in removed)
