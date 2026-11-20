from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event as ThreadEvent

import pytest

from config import get_settings
from models import Event
from services import runner, study, submissions, workspace
from services.errors import ConflictError

SAFE_COMMENT = '''import html
def render_comment(author, text):
    return f'<article class="comment"><h3>{html.escape(author)}</h3><p>{html.escape(text)}</p></article>'
'''


def test_frozen_submission_assessment_can_resume_and_is_idempotent(client, db, enrol):
    enrol(task_id="C")
    ws = study.current_workspace(db)
    workspace.write_text(ws, "app/comments.py", SAFE_COMMENT)
    saved = study._mark_done(db, ws)
    assert db.query(Event).filter_by(type="submission_assessment_pending").count() == 1
    assert db.query(Event).filter_by(type="tests_run").count() == 0
    assert submissions.recover(db, ws)
    assert submissions.recover(db, ws)
    assert db.query(Event).filter_by(type="tests_run").count() == 1
    assert db.query(Event).filter_by(type="security_tests_run").count() == 1
    assert db.query(Event).filter_by(type="submission_assessed").count() == 1
    assert db.query(Event).filter_by(type="tests_run").one().detail["snapshot"] == saved.name
    assert db.query(Event).filter_by(type="security_tests_run").one().detail["snapshot"] == saved.name


def test_failed_assessments_can_be_retried_on_the_same_code(client, db, enrol, monkeypatch):
    enrol(task_id="C")
    ws = study.current_workspace(db)
    workspace.write_text(ws, "app/comments.py", SAFE_COMMENT)
    saved = study._mark_done(db, ws)
    original = runner._pytest
    monkeypatch.setattr(runner, "_pytest", lambda folder: (3, [], "Runner unavailable"))
    assert not submissions.recover(db, ws)
    assert db.query(Event).filter_by(type="submission_assessed").count() == 0
    monkeypatch.setattr(runner, "_pytest", original)
    assert submissions.recover(db, ws, retry_errors=True)
    assert db.query(Event).filter_by(type="tests_run").count() == 2
    assert db.query(Event).filter_by(type="security_tests_run").count() == 2
    assert all(row.detail["snapshot"] == saved.name for row in db.query(Event).filter_by(type="tests_run"))


def test_workspace_byte_quota_is_checked_before_writes_and_snapshots(client, db, team, monkeypatch):
    ws = study.current_workspace(db)
    original_size = workspace.workspace_size(ws)
    monkeypatch.setattr(workspace, "MAX_WORKSPACE_BYTES", original_size + 10)
    workspace.write_text(ws, "extra.txt", "12345")
    workspace.write_text(ws, "extra.txt", "123456")
    with pytest.raises(ConflictError, match="2 MiB"):
        workspace.write_text(ws, "another.txt", "12345")
    assert not (workspace.folder(ws) / "another.txt").exists()
    (workspace.folder(ws) / "extra.txt").write_text("x" * 20, encoding="utf-8")
    with pytest.raises(ConflictError, match="2 MiB"):
        workspace.snapshot(ws, "tests")
    assert not list(Path(get_settings().snapshots_dir).rglob("*"))


def test_a_save_waiting_for_final_capture_is_rejected_after_completion(concurrent_client, enrol, monkeypatch):
    enrol(task_id="C")
    captured, save_ready, release = ThreadEvent(), ThreadEvent(), ThreadEvent()
    original_snapshot = workspace._snapshot
    original_write = workspace.write_file

    def pause_capture(ws, reason):
        if reason == "done":
            captured.set()
            assert release.wait(10)
        return original_snapshot(ws, reason)

    def observe_save(*args):
        save_ready.set()
        return original_write(*args)

    monkeypatch.setattr(workspace, "_snapshot", pause_capture)
    monkeypatch.setattr(workspace, "write_file", observe_save)
    with ThreadPoolExecutor(max_workers=2) as pool:
        finish = pool.submit(concurrent_client.post, "/study/done")
        assert captured.wait(10)
        save = pool.submit(concurrent_client.put, "/workspace/files/app/comments.py", json={"content": "# late edit"})
        try:
            assert save_ready.wait(10)
        finally:
            release.set()
        assert finish.result(timeout=30).status_code == 200
        assert save.result(timeout=10).status_code == 409
