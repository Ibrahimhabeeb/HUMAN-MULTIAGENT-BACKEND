from models import Event

RISK = {"description": "SQL injection in login", "severity": "High", "cwe": "CWE-89"}


def add(client, category, body):
    return client.post(f"/workspace/state/{category}", json=body)


def test_human_adds_items_directly_without_approval(client, db, team):
    risk = add(client, "risks", RISK).json()
    assert (risk["id"], risk["source"], risk["status"], risk["approval_id"]) == ("R1", "human", "open", None)
    assert client.get("/workspace/state").json()["risks"][0]["id"] == "R1"
    added = db.query(Event).filter(Event.type == "state_item_added").one()
    assert added.detail == {"category": "risks", "id": "R1"}


def test_all_four_human_categories(client, team):
    add(client, "risks", RISK)
    assert add(client, "assumptions", {"text": "Users table is in SQLite"}).json()["id"] == "A1"
    assert add(client, "mitigations", {"risk_id": "R1", "description": "Parameterised queries"}).json()["id"] == "M1"
    finding = {"description": "f-string SQL", "severity": "High", "file": "app/auth.py", "line": 5, "risk_id": "R1"}
    assert add(client, "findings", finding).json()["id"] == "F1"


def test_links_must_point_at_existing_risks(client, team):
    assert add(client, "mitigations", {"risk_id": "R9", "description": "Parameterised queries"}).status_code == 404
    assert add(client, "findings", {"description": "x injection", "severity": "Low", "risk_id": "R9"}).status_code == 404


def test_evidence_and_tests_are_not_added_by_hand(client, team):
    assert add(client, "evidence", {"text": "it works", "passed": True}).status_code == 422
    assert add(client, "tests", {"path": "tests/test_x.py"}).status_code == 422


def test_invalid_items_are_rejected(client, team):
    assert add(client, "risks", {"description": "x", "severity": "High"}).status_code == 422
    assert add(client, "risks", {**RISK, "cwe": "89"}).status_code == 422


def test_human_edits_status_and_fields_but_not_identity(client, team):
    add(client, "risks", RISK)
    edited = client.patch(
        "/workspace/state/risks/R1",
        json={"status": "accepted", "rationale": "Out of scope for the prototype", "id": "R99", "source": "verifier"},
    ).json()
    assert (edited["id"], edited["source"], edited["status"]) == ("R1", "human", "accepted")
    assert edited["rationale"] == "Out of scope for the prototype"
    assert client.patch("/workspace/state/risks/R1", json={"status": "done"}).status_code == 422


def test_delete_keeps_links_consistent_and_ids_are_never_reused(client, team):
    add(client, "risks", RISK)
    add(client, "mitigations", {"risk_id": "R1", "description": "Parameterised queries"})
    assert client.delete("/workspace/state/risks/R1").status_code == 409
    assert client.delete("/workspace/state/mitigations/M1").status_code == 204
    assert client.delete("/workspace/state/risks/R1").status_code == 204
    assert add(client, "risks", RISK).json()["id"] == "R2"


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
    assert client.get("/workspace/state").status_code == 200
