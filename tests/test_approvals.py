import pytest
from pydantic import ValidationError

from models import Approval, Event
from services import approvals, study
from services.errors import ConflictError

ASSUMPTION = {"text": "Only the login form takes input from users"}
RISK = {"description": "SQL injection in login", "severity": "High", "cwe": "CWE-89"}
VULNERABILITY = {"description": "f-string SQL", "severity": "High", "file": "app/auth.py", "line": 5}
TEST_FILE = {"path": "tests/test_security.py", "content": "def test_x():\n    assert True\n"}
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
    decide(client, propose("reviewer", "propose_vulnerability", VULNERABILITY), "approve")
    original = client.get("/workspace/files/app/auth.py").json()["content"]
    approval_id = propose("reviewer", "suggest_fix", FIX)
    assert decide(client, approval_id, "approve").json()["status"] == "approved"
    assert client.get("/workspace/files/app/auth.py").json()["content"] == original


def test_a_legacy_pending_finding_can_be_approved_without_its_risk(client, db, team, propose):
    approval_id = propose("reviewer", "propose_vulnerability", VULNERABILITY)
    approval = db.get(Approval, approval_id)
    legacy_proposal = {**approval.proposal, "risk_id": "R99"}
    approval.proposal = legacy_proposal
    db.commit()

    decided = decide(client, approval_id, "approve")
    assert decided.status_code == 200
    assert decided.json()["proposal"] == decided.json()["final_proposal"] == legacy_proposal
    vulnerability = state(client)["vulnerabilities"][0]
    assert vulnerability["description"] == VULNERABILITY["description"]
    assert "risk_id" not in vulnerability
    assert state(client)["risks"] == []


def test_an_approved_fix_becomes_a_mitigation_for_its_vulnerability(client, team, propose):
    decide(client, propose("reviewer", "propose_vulnerability", VULNERABILITY), "approve")
    assert decide(client, propose("reviewer", "suggest_fix", FIX), "approve").json()["result"] == {"item_id": "M1"}
    mitigation = state(client)["mitigations"][0]
    assert (mitigation["vulnerability_id"], mitigation["source"], mitigation["status"]) == ("V1", "reviewer", "planned")
    assert (mitigation["file"], mitigation["location"], mitigation["code"]) == (FIX["file"], FIX["location"], FIX["code"])
    assert mitigation["description"] == FIX["why"]


@pytest.mark.parametrize("target", ["SQL injection in login", "V99"])
def test_a_fix_without_an_existing_vulnerability_cannot_be_approved(client, team, propose, target):
    approval_id = propose("reviewer", "suggest_fix", {**FIX, "vulnerability": target})
    assert decide(client, approval_id, "approve").status_code == 404
    assert client.get(f"/approvals/{approval_id}").json()["status"] == "pending"
    assert state(client)["mitigations"] == []
    assert decide(client, approval_id, "reject").status_code == 200


def test_a_fix_cannot_be_approved_after_its_vulnerability_is_deleted(client, team, propose):
    decide(client, propose("reviewer", "propose_vulnerability", VULNERABILITY), "approve")
    approval_id = propose("reviewer", "suggest_fix", FIX)
    assert client.delete("/workspace/state/vulnerabilities/V1").status_code == 204
    assert decide(client, approval_id, "approve").status_code == 404
    assert client.get(f"/approvals/{approval_id}").json()["status"] == "pending"
    assert state(client)["mitigations"] == []


def test_a_vulnerability_is_kept_as_accepted_or_rejected(client, db, team, propose):
    decide(client, propose("reviewer", "propose_vulnerability", VULNERABILITY), "approve")
    rejected = decide(client, propose("reviewer", "propose_vulnerability", {**VULNERABILITY, "line": 9}), "reject").json()
    assert [(v["id"], v["line"], v["status"]) for v in state(client)["vulnerabilities"]] == [
        ("V1", 5, "accepted"), ("V2", 9, "rejected"),
    ]
    assert (rejected["status"], rejected["result"]) == ("rejected", {"item_id": "V2"})
    jobs = [m for m in client.get("/chat").json()["team"] if m["data"].get("kind") == "vulnerability_follow_up"]
    assert [job["data"]["vulnerability_id"] for job in jobs] == ["V1"]  # only an accepted one gets a fix


def test_risks_have_no_status(client, team, propose):
    propose("threat_modeller", "propose_risk", RISK)  # a suggested risk is in the state straight away
    (risk,) = state(client)["risks"]
    assert "status" not in risk and "rationale" not in risk


def test_mark_resolved_marks_a_mitigation_implemented(client, team, propose):
    decide(client, propose("reviewer", "propose_vulnerability", VULNERABILITY), "approve")
    decide(client, propose("reviewer", "suggest_fix", FIX), "approve")
    assert state(client)["mitigations"][0]["status"] == "planned"
    decide(client, propose("reviewer", "mark_resolved", {"item_id": "M1", "reason": "The query now uses placeholders"}), "approve")
    assert state(client)["mitigations"][0]["status"] == "implemented"
    with pytest.raises(ValidationError):  # only a mitigation can be marked
        propose("reviewer", "mark_resolved", {"item_id": "V1", "reason": "Now uses placeholders"})


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


@pytest.mark.parametrize("action", ["propose_assumption", "propose_risk", "propose_vulnerability", "mark_resolved"])
def test_single_mode_cannot_request_security_state_changes(client, db, single, propose, action):
    with pytest.raises(ConflictError, match="not available in single mode"):
        propose("assistant", action, {})
    assert client.get("/approvals").json() == []
    assert study.current_workspace(db).security_state == {}


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
