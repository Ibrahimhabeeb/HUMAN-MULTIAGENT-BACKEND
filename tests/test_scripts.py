import csv

import pytest

import export
import withdraw
from db import Base
from models import Participant


@pytest.fixture
def take_part(client, enrol, finish_parts):
    # One whole session: consent, both parts, the questionnaire, Finish.
    def _take_part(mode="team", pilot=False, given=()):
        enrol(pilot=pilot, mode=mode)
        finish_parts()
        body = {"answers": [{"condition": c, "item": item, "value": value} for c, item, value in given]}
        client.post("/study/questionnaire", json=body)
        client.post("/study/finish")

    return _take_part


def test_export_writes_a_row_per_participant_without_pilots_or_withdrawn(db, take_part, sample_questionnaire, tmp_path):
    take_part(mode="team", given=[("team", "confidence", 6)])  # P01
    take_part(mode="single", given=[("none", "preferred", "Agent team")])  # P02
    take_part(pilot=True)  # X01
    take_part()  # P03
    withdraw.withdraw(db, "P03")

    out = tmp_path / "survey.csv"
    assert export.export(db, out) == 2
    with out.open(encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    assert list(rows[0]) == [
        "participant",
        "first_mode",
        "confidence_team",
        "confidence_single",
        "effort_team",
        "effort_single",
        "roles_clear_team",
        "preferred",
        "difference",
    ]
    assert [(r["participant"], r["first_mode"]) for r in rows] == [("P01", "team"), ("P02", "single")]
    assert (rows[0]["confidence_team"], rows[0]["preferred"]) == ("6", "")
    assert rows[1]["preferred"] == "Agent team"


def test_withdraw_deletes_their_data_and_never_reuses_the_id(client, db, team, enrol, study_dirs):
    client.put("/workspace/files/app/auth.py", json={"content": "# my code"})
    client.post("/workspace/state/vulnerabilities", json={"description": "f-string SQL", "severity": "High"})
    client.post("/workspace/state/mitigations", json={"vulnerability_id": "V1", "description": "Placeholders"})
    client.post("/study/done")  # takes a snapshot, and records the unit tests' final results
    client.post("/study/restart")

    folders = withdraw.withdraw(db, "P01")
    assert sorted(f.parent.name for f in folders) == ["snapshots", "workspaces"]
    assert not (study_dirs / "workspaces" / "P01_A_team").exists()
    assert not (study_dirs / "snapshots" / "P01_A_team").exists()
    for table in Base.metadata.sorted_tables:
        if "participant_code" in table.c:
            assert db.execute(table.select().where(table.c.participant_code == "P01")).all() == [], table.name
        elif "workspace_id" in table.c:  # the security state and unit tests of their parts
            assert db.execute(table.select()).all() == [], table.name
    assert db.query(Participant).filter_by(code="P01").one().status == "withdrawn"
    assert enrol()["participant"] == "P02"


def test_withdraw_refuses_the_current_session_and_unknown_ids(db, team):
    with pytest.raises(withdraw.WithdrawError, match="current session"):
        withdraw.withdraw(db, "P01")
    with pytest.raises(withdraw.WithdrawError, match="no participant"):
        withdraw.withdraw(db, "P99")
