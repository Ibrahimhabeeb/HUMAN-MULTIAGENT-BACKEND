import logging

import pytest

from models import Event, MitigationRecord, VulnerabilityRecord
from services import study

RISK = {"description": "SQL injection in login", "severity": "High", "cwe": "CWE-89"}
VULNERABILITY = {"description": "f-string SQL", "severity": "High", "file": "app/auth.py", "line": 5}
MITIGATION = {"vulnerability_id": "V1", "description": "Parameterised queries"}


def add(client, category, body):
    return client.post(f"/workspace/state/{category}", json=body)


def test_human_adds_items_directly_without_approval(client, db, team):
    risk = add(client, "risks", RISK).json()
    assert (risk["id"], risk["source"], risk["approval_id"]) == ("R1", "human", None)
    assert "status" not in risk  # a risk is a concern to keep in view, with no status
    assert client.get("/workspace/state").json()["risks"][0]["id"] == "R1"
    added = db.query(Event).filter(Event.type == "state_item_added").one()
    assert added.detail == {"category": "risks", "id": "R1"}


def test_all_four_human_categories(client, team):
    add(client, "risks", RISK)
    assert add(client, "assumptions", {"text": "Users table is in SQLite"}).json()["id"] == "A1"
    assert add(client, "vulnerabilities", VULNERABILITY).json()["id"] == "V1"
    assert add(client, "mitigations", MITIGATION).json()["id"] == "M1"


def test_mitigation_links_must_point_at_existing_vulnerabilities(client, team):
    assert add(client, "mitigations", MITIGATION).status_code == 404
    assert add(client, "vulnerabilities", VULNERABILITY).status_code == 201  # no risk is needed
    assert add(client, "mitigations", MITIGATION).status_code == 201


@pytest.mark.parametrize("target", [None, ""])
def test_a_mitigation_cannot_be_added_without_a_vulnerability(client, team, target):
    response = add(client, "mitigations", {**MITIGATION, "vulnerability_id": target})
    assert response.status_code == 409
    assert client.get("/workspace/state").json()["mitigations"] == []


@pytest.mark.parametrize("target,status", [(None, 409), ("", 409), ("V99", 404)])
def test_a_mitigation_cannot_be_edited_to_remove_or_break_its_link(client, team, target, status):
    add(client, "vulnerabilities", VULNERABILITY)
    mitigation = add(client, "mitigations", MITIGATION).json()
    assert client.patch("/workspace/state/mitigations/M1", json={"vulnerability_id": target}).status_code == status
    assert client.get("/workspace/state/mitigations/M1").json() == mitigation


def test_each_item_is_a_row_and_a_mitigation_points_at_its_vulnerability(client, db, team):
    add(client, "vulnerabilities", VULNERABILITY)
    add(client, "mitigations", MITIGATION)
    (vulnerability,) = db.query(VulnerabilityRecord).all()
    (mitigation,) = db.query(MitigationRecord).all()
    assert (vulnerability.ref, vulnerability.status, vulnerability.line) == ("V1", "accepted", 5)
    assert (mitigation.ref, mitigation.vulnerability_id, mitigation.status) == ("M1", vulnerability.id, "planned")
    assert client.get("/workspace/state/mitigations/M1").json()["vulnerability_id"] == "V1"  # shown by its id

    assert client.delete("/workspace/state/mitigations/M1").status_code == 204
    assert db.query(MitigationRecord).count() == 0  # really deleted
    assert study.current_workspace(db).state_counters["mitigations"] == 1
    assert add(client, "mitigations", MITIGATION).json()["id"] == "M2"  # ids are never reused


def test_tests_are_not_added_by_hand(client, team):
    assert add(client, "tests", {"path": "tests/test_x.py"}).status_code == 422
    assert add(client, "evidence", {"text": "it works", "passed": True}).status_code == 422  # no such category


def test_invalid_items_are_rejected(client, team):
    assert add(client, "risks", {"description": "x", "severity": "High"}).status_code == 422
    assert add(client, "risks", {**RISK, "cwe": "89"}).status_code == 422


def test_human_edits_status_and_fields_but_not_identity(client, team):
    add(client, "vulnerabilities", VULNERABILITY)
    edited = client.patch(
        "/workspace/state/vulnerabilities/V1",
        json={"status": "rejected", "severity": "Low", "id": "V99", "source": "verifier"},
    ).json()
    assert (edited["id"], edited["source"], edited["status"], edited["severity"]) == ("V1", "human", "rejected", "Low")
    assert client.patch("/workspace/state/vulnerabilities/V1", json={"status": "done"}).status_code == 422
    add(client, "mitigations", MITIGATION)
    assert client.patch("/workspace/state/mitigations/M1", json={"status": "implemented"}).json()["status"] == "implemented"


def test_delete_keeps_links_consistent_and_ids_are_never_reused(client, team):
    add(client, "risks", RISK)
    add(client, "vulnerabilities", VULNERABILITY)
    add(client, "mitigations", MITIGATION)
    assert client.delete("/workspace/state/risks/R1").status_code == 204  # findings are independent of risks
    assert client.get("/workspace/state/vulnerabilities/V1").status_code == 200
    assert client.delete("/workspace/state/vulnerabilities/V1").status_code == 409  # M1 fixes it
    assert client.delete("/workspace/state/mitigations/M1").status_code == 204
    assert client.delete("/workspace/state/vulnerabilities/V1").status_code == 204
    assert add(client, "risks", RISK).json()["id"] == "R2"


def test_every_change_is_logged_for_the_backend_console(client, team, caplog):
    caplog.set_level(logging.INFO, logger="security_state")
    add(client, "vulnerabilities", VULNERABILITY)
    client.patch("/workspace/state/vulnerabilities/V1", json={"status": "rejected"})
    client.patch("/workspace/state/vulnerabilities/V1", json={"status": "rejected"})  # no change, nothing logged
    client.delete("/workspace/state/vulnerabilities/V1")

    added, edited, deleted = [record.getMessage() for record in caplog.records]
    assert added.startswith("Security state of P01 (task A) changed:\n  + V1 added to vulnerabilities (by human)\n{")
    assert '  ~ V1 status: "accepted" -> "rejected"' in edited
    assert "  - V1 deleted from vulnerabilities" in deleted
    assert '"vulnerabilities": []' in deleted  # each change is followed by the whole state


def test_read_one_category_or_item(client, team):
    add(client, "risks", RISK)
    assert [r["id"] for r in client.get("/workspace/state/risks").json()] == ["R1"]
    assert client.get("/workspace/state/risks/R1").json()["cwe"] == "CWE-89"
    assert client.get("/workspace/state/risks/R7").status_code == 404


def test_state_is_team_mode_only(client, single):
    assert client.get("/workspace/state").status_code == 409
    assert add(client, "risks", RISK).status_code == 409


def test_finished_part_cannot_be_edited(client, team):
    client.post("/study/done")
    assert add(client, "risks", RISK).status_code == 409
    assert client.get("/workspace/state").status_code == 409
