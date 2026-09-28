import pytest
from fastapi.testclient import TestClient

from api.state import reset_state
from main import app

client = TestClient(app)


@pytest.fixture(autouse=True)
def fresh_state():
    reset_state()


def test_state_starts_empty():
    state = client.get("/state").json()
    assert state["feature"] == "User Login"
    assert state["risks"] == []
    assert state["mitigations"] == []


def test_adding_a_risk_assigns_an_id_and_stores_it():
    response = client.post(
        "/state/risks",
        json={"description": "SQL injection in login", "severity": "High", "cwe": "CWE-89"},
    )
    assert response.status_code == 201
    risk = response.json()
    assert risk["id"] == "R1"
    assert risk["status"] == "identified"
    assert risk["cwe"] == "CWE-89"
    assert client.get("/state").json()["risks"][0]["id"] == "R1"


def test_ids_count_up():
    client.post("/state/risks", json={"description": "first risk", "severity": "Low"})
    second = client.post("/state/risks", json={"description": "second risk", "severity": "Low"})
    assert second.json()["id"] == "R2"


def test_human_risks_are_approved_but_agent_risks_wait_for_approval():
    by_human = client.post("/state/risks", json={"description": "manual risk", "severity": "Low"})
    by_agent = client.post(
        "/state/risks",
        json={"description": "agent risk", "severity": "Low", "source": "threat_modeller"},
    )
    assert by_human.json()["human_approved"] is True
    assert by_agent.json()["human_approved"] is None


def test_client_cannot_set_its_own_id_or_approval():
    response = client.post(
        "/state/risks",
        json={
            "description": "agent risk",
            "severity": "Low",
            "source": "reviewer",
            "id": "R99",
            "human_approved": True,
        },
    )
    risk = response.json()
    assert risk["id"] == "R1"
    assert risk["human_approved"] is None


@pytest.mark.parametrize(
    "bad_field",
    [
        {"severity": "Extreme"},
        {"cwe": "89"},
        {"source": "hacker"},
        {"line": 0},
        {"description": "x"},
    ],
)
def test_invalid_risks_are_rejected(bad_field):
    body = {"description": "valid description", "severity": "High", **bad_field}
    response = client.post("/state/risks", json=body)
    assert response.status_code == 422
    assert client.get("/state").json()["risks"] == []
