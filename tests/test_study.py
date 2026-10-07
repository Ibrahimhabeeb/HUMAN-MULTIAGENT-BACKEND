from models import ConsentRecord, Event, Participant
from services import content


def consent_version():
    return content.load("consent")[0]


def enrol(client, pilot=False):
    client.post("/study/start", json={"pilot": pilot})
    client.post("/study/continue")
    return client.post("/study/consent", json={"consent_version": consent_version()}).json()


def test_starts_on_the_start_screen(client):
    assert client.get("/study/state").json() == {"screen": "start", "mode": "team", "participant": None, "pilot": None}


def test_information_then_consent_store_nothing(client, db):
    assert client.post("/study/start", json={"pilot": False}).json()["screen"] == "information"
    assert client.post("/study/continue").json()["screen"] == "consent"
    assert db.query(Participant).count() == 0
    assert db.query(Event).count() == 0


def test_declining_returns_to_start_and_stores_nothing(client, db):
    client.post("/study/start", json={"pilot": False})
    client.post("/study/continue")
    assert client.post("/study/decline").json()["screen"] == "start"
    assert db.query(Participant).count() == 0
    assert db.query(ConsentRecord).count() == 0


def test_consent_creates_participant_record_and_log(client, db):
    state = enrol(client)
    assert state["participant"] == "P01"
    assert state["screen"] == "ide"
    assert db.get(ConsentRecord, "P01").consent_version == consent_version()
    assert [e.type for e in db.query(Event).all()] == ["participant_created"]


def test_consent_requires_the_current_form_version(client, db):
    client.post("/study/start", json={"pilot": False})
    client.post("/study/continue")
    assert client.post("/study/consent", json={"consent_version": "v0-old"}).status_code == 409
    assert db.query(Participant).count() == 0


def test_consent_must_follow_the_information_sheet(client):
    client.post("/study/start", json={"pilot": False})
    assert client.post("/study/consent", json={"consent_version": consent_version()}).status_code == 409


def test_codes_count_up_separately_for_pilots_and_are_never_reused(client):
    assert enrol(client)["participant"] == "P01"
    client.post("/study/restart")
    assert enrol(client, pilot=True)["participant"] == "X01"
    client.post("/study/restart")
    assert enrol(client)["participant"] == "P02"


def test_only_one_session_at_a_time(client):
    enrol(client)
    assert client.post("/study/start", json={"pilot": False}).status_code == 409


def test_restart_keeps_data_and_marks_incomplete(client, db):
    enrol(client)
    assert client.post("/study/restart").json()["screen"] == "start"
    participant = db.query(Participant).one()
    assert participant.status == "incomplete"
    assert db.get(ConsentRecord, "P01") is not None


def test_restart_before_consent_clears_without_storing(client, db):
    client.post("/study/start", json={"pilot": True})
    assert client.post("/study/restart").json()["screen"] == "start"
    assert db.query(Participant).count() == 0


def test_researcher_sets_starting_mode_before_consent(client):
    assert client.post("/study/mode", json={"mode": "single"}).json()["mode"] == "single"
    assert enrol(client)["mode"] == "single"


def test_mode_switch_is_logged_for_a_participant(client, db):
    enrol(client)
    client.post("/study/mode", json={"mode": "single"})
    switch = db.query(Event).filter(Event.type == "mode_switched").one()
    assert switch.detail == {"from": "team", "to": "single"}


def test_next_participant_starts_in_the_mode_the_last_one_ended_in(client):
    enrol(client)
    client.post("/study/mode", json={"mode": "single"})
    client.post("/study/restart")
    assert client.get("/study/state").json()["mode"] == "single"


def test_finish_requires_the_end_of_the_study(client):
    enrol(client)
    assert client.post("/study/finish").status_code == 409


def test_content_endpoints(client):
    info = client.get("/study/content/information").json()
    consent = client.get("/study/content/consent").json()
    assert info["version"] == consent["version"] == consent_version()
    assert len(consent["statements"]) == 7
    assert consent["statements"][-1] == "I agree to take part in this study."
