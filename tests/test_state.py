import pytest

from schemas.security_state import EvidenceCreate, MitigationCreate, RiskCreate
from services import state_service as state
from services.errors import NotFoundError, StateRuleError


@pytest.fixture
def agents(db, pid, sid):
    # What the agents will do: call the service directly, under their own name.
    class Agents:
        def risk(self, severity="High"):
            data = RiskCreate(description="SQL injection in login", severity=severity, cwe="CWE-89")
            return state.add_risk(db, pid, sid, data, "threat_modeller")

        def mitigation(self, risk_id="R1"):
            data = MitigationCreate(risk_id=risk_id, description="Use parameterised queries")
            return state.add_mitigation(db, pid, sid, data, "reviewer")

        def evidence(self, passed=True, risk_ids=("R1",)):
            data = EvidenceCreate(text="pytest -q", kind="test", passed=passed, risk_ids=list(risk_ids))
            return state.add_evidence(db, pid, sid, data, "verifier")

    return Agents()


@pytest.fixture
def api(client, pid, sid):
    class Api:
        def get(self, path):
            return client.get(f"/projects/{pid}{path}")

        def approve(self, category, item_id):
            return client.post(f"/projects/{pid}/{category}/{item_id}/approve?session_id={sid}")

        def reject(self, category, item_id):
            return client.post(f"/projects/{pid}/{category}/{item_id}/reject?session_id={sid}")

        def status(self, risk_id, status, rationale=None):
            body = {"status": status, "rationale": rationale}
            return client.patch(f"/projects/{pid}/risks/{risk_id}/status?session_id={sid}", json=body)

    return Api()


def test_there_is_no_endpoint_for_the_human_to_create_risks(client, pid, sid, api):
    response = client.post(f"/projects/{pid}/risks?session_id={sid}", json={"description": "xxx", "severity": "High"})
    assert response.status_code == 405
    assert api.get("/risks").json() == []


def test_agent_items_get_ids_and_wait_for_approval(agents):
    first, second = agents.risk(), agents.risk()
    assert (first.id, second.id) == ("R1", "R2")
    assert first.source == "threat_modeller"
    assert first.human_approved is None


def test_state_belongs_to_the_project_not_the_session(client, pid, agents, api):
    agents.risk()
    client.post(f"/projects/{pid}/sessions")  # a new conversation on the same project
    assert api.get("/risks").json()[0]["id"] == "R1"


def test_projects_do_not_share_state(client, agents):
    agents.risk()
    other = client.post("/projects", json={"name": "other"}).json()["id"]
    assert client.get(f"/projects/{other}/risks").json() == []


def test_read_and_filter(agents, api):
    agents.risk(severity="High")
    agents.risk(severity="Low")
    api.approve("risks", "R2")
    api.status("R2", "accepted", "Low impact for the prototype")

    assert api.get("/risks/R1").json()["cwe"] == "CWE-89"
    assert api.get("/risks/R9").status_code == 404
    assert [r["id"] for r in api.get("/risks?severity=High").json()] == ["R1"]
    assert [r["id"] for r in api.get("/risks?status=accepted").json()] == ["R2"]


def test_approve_and_reject(agents, api):
    agents.risk()
    agents.risk()
    approved = api.approve("risks", "R1").json()
    assert approved["human_approved"] is True and approved["description"] == "SQL injection in login"
    assert api.reject("risks", "R2").json()["human_approved"] is False
    assert api.approve("risks", "R9").status_code == 404
    assert api.approve("secrets", "R1").status_code == 422


def test_mitigation_rules(agents, api):
    with pytest.raises(NotFoundError):
        agents.mitigation("R7")
    agents.risk()
    api.reject("risks", "R1")
    with pytest.raises(StateRuleError):
        agents.mitigation("R1")


def test_list_mitigations(agents, api):
    agents.risk()
    agents.risk()
    agents.mitigation("R1")
    agents.mitigation("R2")
    assert api.reject("mitigations", "M2").json()["status"] == "rejected"

    assert [m["id"] for m in api.get("/mitigations?risk_id=R1").json()] == ["M1"]
    assert [m["id"] for m in api.get("/mitigations?status=rejected").json()] == ["M2"]
    assert api.get("/mitigations?risk_id=R9").status_code == 404
    assert api.get("/mitigations/M9").status_code == 404


def test_full_path_to_verified(agents, api):
    agents.risk()
    agents.mitigation()
    assert api.status("R1", "mitigated").status_code == 409  # mitigation not approved yet

    api.approve("mitigations", "M1")
    assert api.status("R1", "mitigated").json()["status"] == "mitigated"
    assert api.get("/mitigations/M1").json()["status"] == "implemented"

    assert api.status("R1", "verified").status_code == 409  # no evidence yet
    agents.evidence(passed=False)
    assert api.status("R1", "verified").status_code == 409  # only failing evidence
    agents.evidence(passed=True)
    assert api.status("R1", "verified").json()["status"] == "verified"
    assert api.get("/mitigations/M1").json()["status"] == "verified"


def test_a_failed_rule_changes_nothing(agents, api):
    agents.risk()
    agents.mitigation()
    api.status("R1", "mitigated")
    assert api.get("/risks/R1").json()["status"] == "identified"
    assert api.get("/mitigations/M1").json()["status"] == "proposed"


def test_accepting_needs_a_rationale(agents, api):
    agents.risk()
    assert api.status("R1", "accepted").status_code == 409
    assert api.status("R1", "accepted", "Out of scope").json()["rationale"] == "Out of scope"


def test_evidence_must_reference_existing_risks(agents):
    with pytest.raises(NotFoundError):
        agents.evidence(risk_ids=["R5"])
