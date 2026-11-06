from models import ConsentRecord, Event, Participant


def test_information_sheet_has_researcher_details_and_no_placeholders(client):
    response = client.get("/study/content/information")
    assert response.status_code == 200
    data = response.json()
    assert data["version"] == "v1.1"
    text = data["markdown"]
    assert "Ibrahim Habeeb-lahi Abiola" in text
    assert "[hi261@exeter.ac.uk](mailto:hi261@exeter.ac.uk)" in text
    assert "Prof. Solomon Oyelere" in text
    assert "Department of Computer Science, University of Exeter" in text
    assert "two different short programming tasks" in text
    assert "choose a different task for the other mode" in text
    assert all(marker not in text for marker in ("DRAFT", "CONFIRM", "[DATE", "[NAME"))


def test_information_and_consent_agree_on_the_withdrawal_cutoff(client):
    information = client.get("/study/content/information").json()
    consent = client.get("/study/content/consent").json()
    assert consent["version"] == information["version"]
    assert len(consent["statements"]) == 7
    withdrawal = next(text for text in consent["statements"] if "withdraw" in text)
    assert "at any time before I submit the final questionnaire" in withdrawal
    assert "After submission, I can no longer withdraw my study data" in withdrawal
    assert "After you submit the final questionnaire, you can no longer withdraw your study data" in information["markdown"]
    assert all(marker not in consent["markdown"] for marker in ("DRAFT", "CONFIRM", "[DATE"))


def test_reading_participant_documents_stores_nothing_before_consent(client, db, study_dirs):
    assert client.get("/study/content/information").status_code == 200
    assert client.get("/study/content/consent").status_code == 200
    assert db.query(Participant).count() == db.query(ConsentRecord).count() == db.query(Event).count() == 0
    assert not (study_dirs / "workspaces").exists()
