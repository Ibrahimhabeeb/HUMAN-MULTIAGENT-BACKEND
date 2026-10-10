from pathlib import Path

from config import get_settings
from models import ConsentRecord, Event, Participant, Workspace
from services import content


def consent_version():
    return content.load("consent")[0]


def event_types(db):
    return [e.type for e in db.query(Event).order_by(Event.id)]


# ---- before and at consent ------------------------------------------------------------------


def test_starts_on_the_start_screen(client):
    state = client.get("/study/state").json()
    assert (state["screen"], state["mode"], state["participant"]) == ("start", "team", None)


def test_information_then_consent_store_nothing(client, db, study_dirs):
    assert client.post("/study/start", json={"pilot": False}).json()["screen"] == "information"
    assert client.post("/study/continue").json()["screen"] == "consent"
    assert db.query(Participant).count() == 0
    assert db.query(Event).count() == 0
    assert not (study_dirs / "workspaces").exists()


def test_declining_returns_to_start_and_stores_nothing(client, db):
    client.post("/study/start", json={"pilot": False})
    client.post("/study/continue")
    assert client.post("/study/decline").json()["screen"] == "start"
    assert db.query(Participant).count() == 0
    assert db.query(ConsentRecord).count() == 0


def test_consent_creates_participant_and_opens_part_1(team, db):
    assert team["participant"] == "P01"
    assert (team["screen"], team["part"], team["task"]["id"]) == ("ide", 1, "A")
    assert db.get(ConsentRecord, "P01").consent_version == consent_version()
    assert event_types(db) == ["participant_created", "part_started"]


def test_consent_copies_the_starter_task_into_a_workspace(team):
    folder = Path(get_settings().workspaces_dir) / "P01_A"
    assert (folder / "app" / "auth.py").is_file()
    assert (folder / "README.md").read_text(encoding="utf-8").startswith("# Task: User login")


def test_consent_requires_the_current_form_version(client, db):
    client.post("/study/start", json={"pilot": False})
    client.post("/study/continue")
    assert client.post("/study/consent", json={"consent_version": "v0-old"}).status_code == 409
    assert db.query(Participant).count() == 0


def test_consent_must_follow_the_information_sheet(client):
    client.post("/study/start", json={"pilot": False})
    assert client.post("/study/consent", json={"consent_version": consent_version()}).status_code == 409


def test_codes_count_up_separately_for_pilots_and_are_never_reused(client, enrol):
    assert enrol()["participant"] == "P01"
    client.post("/study/restart")
    assert enrol(pilot=True)["participant"] == "X01"
    client.post("/study/restart")
    assert enrol()["participant"] == "P02"


def test_only_one_session_at_a_time(client, team):
    assert client.post("/study/start", json={"pilot": False}).status_code == 409


def test_restart_keeps_data_and_marks_incomplete(client, db, team):
    assert client.post("/study/restart").json()["screen"] == "start"
    assert db.query(Participant).one().status == "incomplete"
    assert db.get(ConsentRecord, "P01") is not None


def test_restart_before_consent_clears_without_storing(client, db):
    client.post("/study/start", json={"pilot": True})
    assert client.post("/study/restart").json()["screen"] == "start"
    assert db.query(Participant).count() == 0


# ---- the two parts ------------------------------------------------------------------------------


def test_researcher_sets_starting_mode_before_consent(single):
    assert (single["mode"], single["task"]["id"]) == ("single", "A")


def test_cannot_start_the_other_mode_before_done(client, team, db):
    assert client.post("/study/mode", json={"mode": "single"}).status_code == 409
    assert client.get("/study/state").json()["mode"] == "team"
    assert db.query(Workspace).count() == 1


def test_done_then_switch_runs_part_2_with_task_b(client, db, team):
    after_done = client.post("/study/done").json()
    assert after_done["screen"] == "part_complete"

    part_2 = client.post("/study/mode", json={"mode": "single"}).json()
    assert (part_2["screen"], part_2["part"], part_2["task"]["id"]) == ("ide", 2, "B")
    assert (Path(get_settings().workspaces_dir) / "P01_B" / "app" / "storage.py").is_file()

    switched = db.query(Event).filter(Event.type == "mode_switched").one()
    assert switched.detail == {"from": "team", "to": "single"}


def test_switching_back_to_a_finished_part_shows_part_complete(client, team):
    client.post("/study/done")
    client.post("/study/mode", json={"mode": "single"})
    assert client.post("/study/mode", json={"mode": "team"}).json()["screen"] == "part_complete"


def test_questionnaire_opens_when_both_parts_are_done(client, team):
    client.post("/study/done")
    client.post("/study/mode", json={"mode": "single"})
    state = client.post("/study/done").json()
    assert state["screen"] == "questionnaire"
    assert [(p["part"], p["mode"], p["task_id"], p["done"]) for p in state["parts"]] == [
        (1, "team", "A", True),
        (2, "single", "B", True),
    ]


def test_done_saves_a_snapshot(client, team):
    client.post("/study/done")
    assert (Path(get_settings().snapshots_dir) / "P01_A" / "01_done" / "app" / "auth.py").is_file()


def test_done_twice_is_refused(client, team):
    client.post("/study/done")
    assert client.post("/study/done").status_code == 409


def test_next_participant_starts_in_the_mode_the_last_one_ended_in(client, team):
    client.post("/study/done")
    client.post("/study/mode", json={"mode": "single"})
    client.post("/study/restart")
    assert client.get("/study/state").json()["mode"] == "single"


def test_finish_requires_the_end_of_the_study(client, team):
    assert client.post("/study/finish").status_code == 409


def test_content_endpoints(client):
    info = client.get("/study/content/information").json()
    consent = client.get("/study/content/consent").json()
    assert info["version"] == consent["version"] == consent_version()
    assert len(consent["statements"]) == 6
    assert consent["statements"][-1] == "I agree to take part in this study."
