import hashlib
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from conftest import StudyClient
from fastapi.testclient import TestClient
from sqlalchemy import select

from main import app
from models import Event, Participant, StudySession, SurveyResponse
from services import approvals, chat, content, sessions, study


def enrol_tab(client, mode="team", task="A"):
    for path, body in [
        ("/study/mode", {"mode": mode}),
        ("/study/start", {"pilot": False, "task_id": task}),
        ("/study/continue", None),
        ("/study/consent", {"consent_version": content.load("consent")[0]}),
    ]:
        response = client.post(path, json=body) if body is not None else client.post(path)
        assert response.status_code == 200, response.text
    return response.json()


def finish_tab(client):
    mode = client.get("/study/state").json()["mode"]
    assert client.post("/study/done").status_code == 200
    assert client.post("/study/mode", json={"mode": "single" if mode == "team" else "team"}).status_code == 200
    assert client.post("/study/done").json()["screen"] == "questionnaire"


def test_bootstrap_and_pending_sessions_store_no_participant_data(client, db):
    token = client.headers[sessions.HEADER]
    assert len(token) == 43
    other = StudyClient(app)
    assert other.headers[sessions.HEADER] != token
    client.post("/study/mode", json={"mode": "single"})
    client.post("/study/start", json={"task_id": "B"})
    other.post("/study/start", json={"task_id": "A"})
    client.post("/study/continue")
    first = client.get("/study/state").json()
    second = other.get("/study/state").json()
    assert (first["screen"], first["mode"], first["task"]["id"]) == ("consent", "single", "B")
    assert (second["screen"], second["mode"], second["task"]["id"]) == ("information", "team", "A")
    assert not db.scalars(select(Participant)).all()
    assert not db.scalars(select(StudySession)).all()
    assert not db.scalars(select(Event)).all()
    client.post("/study/restart")
    assert other.get("/study/state").json() == second


@pytest.mark.parametrize("method,path,body", [
    ("GET", "/study/state", None),
    ("POST", "/study/start", {"task_id": "A"}),
    ("POST", "/study/consent", {"consent_version": "v1"}),
    ("POST", "/study/done", None),
    ("POST", "/study/restart", None),
    ("GET", "/workspace/files", None),
    ("PUT", "/workspace/files/app/auth.py", {"content": "not allowed"}),
    ("GET", "/workspace/notes", None),
    ("GET", "/workspace/state", None),
    ("POST", "/workspace/tests/run", None),
    ("GET", "/chat", None),
    ("POST", "/chat/team", {"content": "not allowed"}),
    ("GET", "/approvals", None),
    ("POST", "/study/questionnaire", {"answers": []}),
])
def test_missing_or_unknown_token_never_selects_an_active_participant(client, team, method, path, body):
    anonymous = TestClient(app)
    for headers in [{}, {sessions.HEADER: "P01"}, {sessions.HEADER: "x" * 43}]:
        response = anonymous.request(method, path, json=body, headers=headers)
        assert response.status_code == 401, response.text
        assert team["participant"] not in response.text


def test_two_active_participants_have_isolated_files_messages_and_approvals(client, db):
    first = enrol_tab(client)
    other = StudyClient(app)
    second = enrol_tab(other, mode="single", task="B")
    assert first["participant"] != second["participant"]
    assert len(db.scalars(select(Participant).where(Participant.status == "active")).all()) == 2

    client.get("/study/state")
    ws = study.current_workspace(db)
    chat.add_message(db, ws, "team", "human", "Only the first participant")
    approval = approvals.request_approval(db, ws, "threat_modeller", "propose_assumption", {"text": "Private assumption"})
    db.commit()
    client.put("/workspace/files/private.txt", json={"content": "first participant only"})
    assert other.get("/workspace/files/private.txt").status_code == 404
    assert other.get("/chat").json() == {"assistant": []}
    assert other.get("/approvals").json() == []
    assert other.get(f"/approvals/{approval.id}").status_code == 404
    assert other.post(f"/approvals/{approval.id}/decide", json={"decision": "approve"}).status_code == 404
    assert other.post("/chat/follow-ups/999999").status_code == 404
    assert other.post("/workspace/notes", json={"text": "wrong method"}).status_code == 405
    other.put("/workspace/notes", json={"text": "second participant notes"})
    assert other.get("/workspace/notes").json()["text"] == "second participant notes"
    assert client.get("/workspace/notes").json()["text"] == ""
    assert client.get("/workspace/files/private.txt").json()["content"] == "first participant only"


def test_only_token_hash_is_persisted_and_consented_session_survives_memory_reset(client, db):
    state = enrol_tab(client)
    token = client.headers[sessions.HEADER]
    records = db.scalars(select(StudySession)).all()
    assert len(records) == 1
    assert records[0].token_hash == hashlib.sha256(token.encode()).hexdigest()
    assert records[0].participant_code == state["participant"]
    assert token not in repr([event.detail for event in db.scalars(select(Event))])
    assert records[0].token_hash not in repr([event.detail for event in db.scalars(select(Event))])
    study.reset_memory()
    response = client.get("/study/state")
    assert response.json() == state
    assert response.headers["Cache-Control"] == "no-store"
    client.post("/study/done")
    assert client.post("/study/mode", json={"mode": "single"}).json()["task"]["id"] == "A"


def test_finish_and_restart_revoke_only_their_own_token(client, db, sample_questionnaire):
    first = enrol_tab(client)
    other = StudyClient(app)
    second = enrol_tab(other, mode="single")
    old_token = client.headers[sessions.HEADER]
    finish_tab(client)
    assert other.get("/study/state").json()["screen"] == "ide"
    assert other.get("/study/questionnaire").status_code == 409
    assert other.post("/study/questionnaire", json={"answers": []}).status_code == 409
    assert client.post("/study/questionnaire", json={"answers": []}).json()["screen"] == "thank_you"
    assert client.post("/study/finish").json()["screen"] == "start"
    assert client.headers[sessions.HEADER] != old_token
    assert TestClient(app).get("/study/state", headers={sessions.HEADER: old_token}).status_code == 401
    assert other.get("/study/state").json()["participant"] == second["participant"]
    assert db.scalar(select(Participant).where(Participant.code == first["participant"])).status == "complete"
    assert db.scalars(select(SurveyResponse).where(SurveyResponse.participant_code == first["participant"])).all()

    other_token = other.headers[sessions.HEADER]
    assert other.post("/study/restart").json()["screen"] == "start"
    assert other.headers[sessions.HEADER] != other_token
    assert TestClient(app).get("/workspace/files", headers={sessions.HEADER: other_token}).status_code == 401
    assert not db.scalars(select(StudySession)).all()
    assert db.scalar(select(Participant).where(Participant.code == second["participant"])).status == "incomplete"
    assert client.get("/study/state").json()["participant"] is None


def test_legacy_active_records_are_not_adopted_by_a_new_tab(client, db):
    db.add(Participant(code="P01"))
    db.commit()
    assert client.get("/study/state").json()["participant"] is None
    assert enrol_tab(client)["participant"] == "P02"


def test_concurrent_consent_allocates_distinct_participants(concurrent_client):
    other = StudyClient(app)
    for tab in [concurrent_client, other]:
        tab.post("/study/start", json={"task_id": "A"})
        tab.post("/study/continue")
    barrier = Barrier(2)

    def consent(tab):
        barrier.wait(timeout=5)
        return tab.post("/study/consent", json={"consent_version": content.load("consent")[0]})

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(consent, [concurrent_client, other]))
    assert [response.status_code for response in responses] == [200, 200]
    assert len({response.json()["participant"] for response in responses}) == 2
