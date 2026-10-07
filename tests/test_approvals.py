from pathlib import Path

import pytest
from pydantic import ValidationError

from config import get_settings
from models import Approval, Event
from services import approvals, study
from services.errors import ConflictError

RISK = {"description": "SQL injection in login", "severity": "High", "cwe": "CWE-89"}
TEST_FILE = {"path": "tests/test_security.py", "content": "def test_x():\n    assert True\n", "risk_ids": ["R1"]}
FIX = {
    "finding": "F1",
    "file": "app/auth.py",
    "location": "login(), the SELECT query",
    "code": 'cur.execute("SELECT * FROM users WHERE username = ?", (username,))',
    "why": "Placeholders stop user input changing the SQL.",
}


@pytest.fixture
def propose(db):
    # What an agent's tool call does: ask for approval instead of making the change.
    def _propose(actor, action_type, proposal):
        return approvals.request_approval(db, study.editable_workspace(db), actor, action_type, proposal).id

    return _propose


def decide(client, approval_id, decision, proposal=None):
    return client.post(f"/approvals/{approval_id}/decide", json={"decision": decision, "proposal": proposal})


def state(client):
    return client.get("/workspace/state").json()


def test_a_proposal_changes_nothing_until_approved(client, team, propose):
    approval_id = propose("threat_modeller", "propose_risk", RISK)
    assert state(client)["risks"] == []
    pending = client.get("/approvals?status=pending").json()
    assert [(a["id"], a["actor"], a["action_type"]) for a in pending] == [(approval_id, "threat_modeller", "propose_risk")]


def test_approve_applies_the_proposal(client, team, propose):
    approval_id = propose("threat_modeller", "propose_risk", RISK)
    decided = decide(client, approval_id, "approve").json()
    assert (decided["status"], decided["result"]) == ("approved", {"item_id": "R1"})
    risk = state(client)["risks"][0]
    assert (risk["source"], risk["approval_id"]) == ("threat_modeller", approval_id)


def test_reject_applies_nothing(client, team, propose):
    approval_id = propose("threat_modeller", "propose_risk", RISK)
    assert decide(client, approval_id, "reject").json()["status"] == "rejected"
    assert state(client)["risks"] == []


def test_edit_then_approve_applies_the_edited_version(client, team, propose):
    approval_id = propose("threat_modeller", "propose_risk", RISK)
    decided = decide(client, approval_id, "edit", {**RISK, "severity": "Critical"}).json()
    assert decided["status"] == "edited"
    assert (decided["proposal"]["severity"], decided["final_proposal"]["severity"]) == ("High", "Critical")
    assert state(client)["risks"][0]["severity"] == "Critical"


def test_an_invalid_edit_is_refused_and_stays_pending(client, team, propose):
    approval_id = propose("threat_modeller", "propose_risk", RISK)
    assert decide(client, approval_id, "edit", {**RISK, "severity": "Extreme"}).status_code == 422
    assert client.get(f"/approvals/{approval_id}").json()["status"] == "pending"


def test_each_proposal_is_decided_once(client, team, propose):
    approval_id = propose("threat_modeller", "propose_risk", RISK)
    decide(client, approval_id, "approve")
    assert decide(client, approval_id, "reject").status_code == 409
    assert decide(client, approval_id, "approve").status_code == 409
    assert len(state(client)["risks"]) == 1


def test_fix_suggestions_are_approve_or_reject_only_and_never_applied(client, team, propose):
    original = client.get("/workspace/files/app/auth.py").json()["content"]
    approval_id = propose("reviewer", "suggest_fix", FIX)
    assert decide(client, approval_id, "edit", FIX).status_code == 409
    decided = decide(client, approval_id, "approve").json()
    assert (decided["status"], decided["result"]) == ("approved", None)
    assert client.get("/workspace/files/app/auth.py").json()["content"] == original


def test_approved_test_file_is_added_and_linked_to_its_risks(client, db, team, propose):
    decide(client, propose("threat_modeller", "propose_risk", RISK), "approve")
    approval_id = propose("verifier", "propose_test", TEST_FILE)
    assert not Path(get_settings().workspaces_dir, "P01_A", "tests", "test_security.py").exists()

    decide(client, approval_id, "approve")
    assert client.get("/workspace/files/tests/test_security.py").json()["content"] == TEST_FILE["content"]
    link = state(client)["tests"][0]
    assert (link["path"], link["risk_ids"], link["approval_id"]) == ("tests/test_security.py", ["R1"], approval_id)
    created = db.query(Event).filter(Event.type == "file_created").one()
    assert created.actor == "system"


def test_a_test_for_an_unknown_risk_is_refused_and_writes_nothing(client, team, propose):
    approval_id = propose("verifier", "propose_test", TEST_FILE)
    assert decide(client, approval_id, "approve").status_code == 404
    assert client.get(f"/approvals/{approval_id}").json()["status"] == "pending"
    assert client.get("/workspace/files/tests/test_security.py").status_code == 404


def test_mark_resolved_updates_the_finding(client, team, propose):
    decide(client, propose("reviewer", "propose_finding", {"description": "f-string SQL", "severity": "High"}), "approve")
    decide(client, propose("reviewer", "mark_resolved", {"item_id": "F1", "reason": "Now uses placeholders"}), "approve")
    assert state(client)["findings"][0]["status"] == "fixed"


def test_invalid_proposals_are_refused_when_requested(team, propose):
    with pytest.raises(ValidationError):
        propose("threat_modeller", "propose_risk", {"description": "x", "severity": "Huge"})
    with pytest.raises(ValidationError):
        propose("verifier", "propose_test", {**TEST_FILE, "path": "../evil.py"})


def test_single_mode_allows_only_fixes_and_tests(client, single, propose):
    with pytest.raises(ConflictError):
        propose("assistant", "propose_risk", RISK)
    approval_id = propose("assistant", "propose_test", {**TEST_FILE, "risk_ids": []})
    decide(client, approval_id, "approve")
    assert client.get("/workspace/files/tests/test_security.py").status_code == 200


def test_requests_and_decisions_are_logged(client, db, team, propose):
    approval_id = propose("threat_modeller", "propose_risk", RISK)
    decide(client, approval_id, "approve")
    requested = db.query(Event).filter(Event.type == "approval_requested").one()
    approved = db.query(Event).filter(Event.type == "action_approved").one()
    assert requested.actor == "threat_modeller"
    assert approved.detail["proposer"] == "threat_modeller"
    assert approved.detail["action_type"] == "propose_risk"
    assert approved.detail["decision_seconds"] >= 0


def test_approvals_are_stored_in_the_database(db, team, propose):
    approval_id = propose("threat_modeller", "propose_risk", RISK)
    db.expire_all()
    assert db.get(Approval, approval_id).status == "pending"


def test_finished_part_cannot_decide(client, team, propose):
    approval_id = propose("threat_modeller", "propose_risk", RISK)
    client.post("/study/done")
    assert decide(client, approval_id, "approve").status_code == 409
