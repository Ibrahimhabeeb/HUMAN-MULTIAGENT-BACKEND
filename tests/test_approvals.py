from pathlib import Path

import pytest
from pydantic import ValidationError

from config import get_settings
from models import Approval, Event
from services import approvals, study
from services.errors import ConflictError

ASSUMPTION = {"text": "Only the login form takes input from users"}
RISK = {"description": "SQL injection in login", "severity": "High", "cwe": "CWE-89"}
VULNERABILITY = {"description": "f-string SQL", "severity": "High", "file": "app/auth.py", "line": 5}
TEST_FILE = {"path": "tests/test_security.py", "content": "def test_x():\n    assert True\n", "vulnerability_ids": ["V1"]}
FIX = {
    "vulnerability": "V1",
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


def decide(client, approval_id, decision):
    return client.post(f"/approvals/{approval_id}/decide", json={"decision": decision})


def state(client):
    return client.get("/workspace/state").json()


def test_a_proposal_changes_nothing_until_approved(client, team, propose):
    approval_id = propose("threat_modeller", "propose_assumption", ASSUMPTION)
    assert state(client)["assumptions"] == []
    pending = client.get("/approvals?status=pending").json()
    assert [(a["id"], a["actor"], a["action_type"]) for a in pending] == [
        (approval_id, "threat_modeller", "propose_assumption")
    ]


def test_approve_applies_the_proposal(client, team, propose):
    approval_id = propose("threat_modeller", "propose_assumption", ASSUMPTION)
    decided = decide(client, approval_id, "approve").json()
    assert (decided["status"], decided["result"]) == ("approved", {"item_id": "A1"})
    assumption = state(client)["assumptions"][0]
    assert (assumption["source"], assumption["approval_id"]) == ("threat_modeller", approval_id)


def test_reject_applies_nothing(client, team, propose):
    approval_id = propose("threat_modeller", "propose_assumption", ASSUMPTION)
    assert decide(client, approval_id, "reject").json()["status"] == "rejected"
    assert state(client)["assumptions"] == []


def test_proposals_are_only_approved_or_rejected_never_edited(client, team, propose):
    approval_id = propose("threat_modeller", "propose_assumption", ASSUMPTION)
    edit = {"decision": "edit", "proposal": {"text": "Something else"}}
    assert client.post(f"/approvals/{approval_id}/decide", json=edit).status_code == 422
    assert client.get(f"/approvals/{approval_id}").json()["status"] == "pending"
    decided = decide(client, approval_id, "approve").json()
    assert decided["final_proposal"] == decided["proposal"]  # applied exactly as proposed


def test_each_proposal_is_decided_once(client, team, propose):
    approval_id = propose("threat_modeller", "propose_assumption", ASSUMPTION)
    decide(client, approval_id, "approve")
    assert decide(client, approval_id, "reject").status_code == 409
    assert decide(client, approval_id, "approve").status_code == 409
    assert len(state(client)["assumptions"]) == 1


def test_suggested_risks_go_straight_into_the_state_without_a_decision(client, db, team, propose):
    approval_id = propose("threat_modeller", "propose_risk", RISK)
    suggested = client.get(f"/approvals/{approval_id}").json()
    assert (suggested["status"], suggested["result"]) == ("suggested", {"item_id": "R1"})
    risk = state(client)["risks"][0]
    assert (risk["id"], risk["source"], risk["approval_id"]) == ("R1", "threat_modeller", approval_id)

    assert client.get("/approvals?status=pending").json() == []  # nothing is waiting for the developer
    assert decide(client, approval_id, "approve").status_code == 409
    assert decide(client, approval_id, "reject").status_code == 409
    added = db.query(Event).filter(Event.type == "state_item_added").one()
    assert (added.actor, added.detail) == ("threat_modeller", {"category": "risks", "id": "R1", "approval_id": approval_id})
    assert db.query(Event).filter(Event.type == "approval_requested").count() == 0


def test_an_approved_fix_never_changes_the_code(client, team, propose):
    original = client.get("/workspace/files/app/auth.py").json()["content"]
    approval_id = propose("reviewer", "suggest_fix", FIX)
    assert decide(client, approval_id, "approve").json()["status"] == "approved"
    assert client.get("/workspace/files/app/auth.py").json()["content"] == original


def test_an_approved_fix_becomes_a_mitigation_for_its_vulnerability(client, team, propose):
    decide(client, propose("reviewer", "propose_vulnerability", VULNERABILITY), "approve")
    assert decide(client, propose("reviewer", "suggest_fix", FIX), "approve").json()["result"] == {"item_id": "M1"}
    mitigation = state(client)["mitigations"][0]
    assert (mitigation["vulnerability_id"], mitigation["source"], mitigation["status"]) == ("V1", "reviewer", "planned")
    assert (mitigation["file"], mitigation["location"], mitigation["code"]) == (FIX["file"], FIX["location"], FIX["code"])
    assert mitigation["description"] == FIX["why"]


def test_a_fix_for_something_not_in_the_state_becomes_an_unlinked_mitigation(client, team, propose):
    decide(client, propose("reviewer", "suggest_fix", {**FIX, "vulnerability": "SQL injection in login"}), "approve")
    assert state(client)["mitigations"][0]["vulnerability_id"] is None


def test_approved_test_file_is_added_and_linked_to_its_vulnerabilities(client, db, team, propose):
    decide(client, propose("reviewer", "propose_vulnerability", VULNERABILITY), "approve")
    approval_id = propose("verifier", "propose_test", TEST_FILE)
    assert not Path(get_settings().workspaces_dir, "P01_A", "tests", "test_security.py").exists()

    decide(client, approval_id, "approve")
    assert client.get("/workspace/files/tests/test_security.py").json()["content"] == TEST_FILE["content"]
    test = state(client)["tests"][0]
    assert (test["path"], test["vulnerability_ids"], test["approval_id"]) == ("tests/test_security.py", ["V1"], approval_id)
    assert (test["source"], test["passed"], test["result"]) == ("verifier", None, None)  # not run yet
    created = db.query(Event).filter(Event.type == "file_created").one()
    assert created.actor == "system"


def test_deleting_a_vulnerability_removes_it_from_the_tests_for_it(client, team, propose):
    decide(client, propose("reviewer", "propose_vulnerability", VULNERABILITY), "approve")
    decide(client, propose("verifier", "propose_test", TEST_FILE), "approve")
    assert client.delete("/workspace/state/vulnerabilities/V1").status_code == 204
    assert state(client)["tests"][0]["vulnerability_ids"] == []


def test_a_test_for_an_unknown_vulnerability_is_refused_and_writes_nothing(client, team, propose):
    approval_id = propose("verifier", "propose_test", TEST_FILE)
    assert decide(client, approval_id, "approve").status_code == 404
    assert client.get(f"/approvals/{approval_id}").json()["status"] == "pending"
    assert client.get("/workspace/files/tests/test_security.py").status_code == 404


def test_mark_resolved_updates_the_vulnerability_or_risk(client, team, propose):
    decide(client, propose("reviewer", "propose_vulnerability", VULNERABILITY), "approve")
    propose("threat_modeller", "propose_risk", RISK)  # a suggested risk is in the state straight away
    decide(client, propose("reviewer", "mark_resolved", {"item_id": "V1", "reason": "Now uses placeholders"}), "approve")
    decide(client, propose("reviewer", "mark_resolved", {"item_id": "R1", "reason": "Every query uses them"}), "approve")
    assert (state(client)["vulnerabilities"][0]["status"], state(client)["risks"][0]["status"]) == ("fixed", "mitigated")


def test_invalid_proposals_are_refused_when_requested(team, propose):
    with pytest.raises(ValidationError):
        propose("threat_modeller", "propose_risk", {"description": "x", "severity": "Huge"})
    with pytest.raises(ValidationError):
        propose("verifier", "propose_test", {**TEST_FILE, "path": "../evil.py"})


def test_single_mode_allows_only_fixes_and_tests(client, single, propose):
    with pytest.raises(ConflictError):
        propose("assistant", "propose_risk", RISK)
    approval_id = propose("assistant", "propose_test", {**TEST_FILE, "vulnerability_ids": []})
    decide(client, approval_id, "approve")
    assert client.get("/workspace/files/tests/test_security.py").status_code == 200
    fix = {**FIX, "vulnerability": "SQL injection"}
    assert decide(client, propose("assistant", "suggest_fix", fix), "approve").json()["result"] is None  # no state


def test_requests_and_decisions_are_logged(client, db, team, propose):
    approval_id = propose("threat_modeller", "propose_assumption", ASSUMPTION)
    decide(client, approval_id, "approve")
    requested = db.query(Event).filter(Event.type == "approval_requested").one()
    approved = db.query(Event).filter(Event.type == "action_approved").one()
    assert requested.actor == "threat_modeller"
    assert approved.detail["proposer"] == "threat_modeller"
    assert approved.detail["action_type"] == "propose_assumption"
    assert approved.detail["decision_seconds"] >= 0


def test_approvals_are_stored_in_the_database(db, team, propose):
    approval_id = propose("threat_modeller", "propose_assumption", ASSUMPTION)
    db.expire_all()
    assert db.get(Approval, approval_id).status == "pending"


def test_finished_part_cannot_decide(client, team, propose):
    approval_id = propose("threat_modeller", "propose_assumption", ASSUMPTION)
    client.post("/study/done")
    assert decide(client, approval_id, "approve").status_code == 409
