from models import SurveyResponse
from services import questionnaire


def answers(*given):
    return {"answers": [{"condition": c, "item": item, "value": value} for c, item, value in given]}


def test_opens_only_once_both_parts_are_done(client, team, finish_parts, sample_questionnaire):
    assert client.get("/study/questionnaire").status_code == 409
    assert client.post("/study/questionnaire", json=answers()).status_code == 409
    finish_parts()
    assert client.get("/study/state").json()["screen"] == "questionnaire"
    assert client.get("/study/questionnaire").status_code == 200


def test_says_so_when_the_questions_are_not_added_yet(client, team, finish_parts, content_dir):
    finish_parts()
    response = client.get("/study/questionnaire")
    assert response.status_code == 404 and "questionnaire.json" in response.json()["detail"]


def test_each_mode_is_labelled_with_its_task_in_the_order_used(client, team, finish_parts, sample_questionnaire):
    finish_parts()
    form = client.get("/study/questionnaire").json()
    assert form["modes"] == [
        {"mode": "team", "label": "Agent team (authentication task)"},
        {"mode": "single", "label": "Single assistant (authentication task)"},
    ]
    confidence = form["sections"][0]["questions"][0]
    effort = form["sections"][0]["questions"][1]
    assert confidence["scale"] == {"min": 1, "max": 7, "min_label": "Strongly disagree", "max_label": "Strongly agree"}
    assert effort["type"] == "number" and effort["scale"]["min"] == 0 and effort["scale"]["max"] == 100
    assert form["text_hint"] == "Please don't include names or other personal details."


def test_only_the_participant_id_is_stored_and_skipped_answers_are_null(client, db, team, finish_parts, sample_questionnaire):
    finish_parts()
    given = answers(("team", "confidence", 6), ("none", "preferred", "Agent team"), ("none", "difference", "  Structure "))
    assert client.post("/study/questionnaire", json=given).json()["screen"] == "thank_you"

    rows = db.query(SurveyResponse).all()
    assert {(r.condition, r.item): r.value for r in rows} == {
        ("team", "confidence"): "6",
        ("single", "confidence"): None,
        ("team", "effort"): None,
        ("single", "effort"): None,
        ("team", "roles_clear"): None,
        ("none", "preferred"): "Agent team",
        ("none", "difference"): "Structure",
    }
    assert {r.participant_code for r in rows} == {"P01"}
    assert set(SurveyResponse.__table__.columns.keys()) == {"id", "participant_code", "condition", "item", "value"}


def test_the_form_locks_after_submission(client, team, finish_parts, sample_questionnaire):
    finish_parts()
    client.post("/study/questionnaire", json=answers())  # everything skipped still counts as submitted
    assert client.post("/study/questionnaire", json=answers(("team", "confidence", 3))).status_code == 409
    assert client.get("/study/questionnaire").status_code == 409
    assert client.post("/study/finish").json()["screen"] == "start"


def test_invalid_answers_are_refused_and_nothing_is_stored(client, db, team, finish_parts, sample_questionnaire):
    finish_parts()
    invalid = [
        ("team", "confidence", 8),
        ("team", "confidence", "6"),
        ("none", "preferred", "Both"),
        ("single", "roles_clear", 4),  # a team-only question
        ("team", "effort", 101),
        ("team", "confidence", "Not applicable"),
        ("none", "age", "30"),
    ]
    for answer in invalid:
        assert client.post("/study/questionnaire", json=answers(answer)).status_code == 422
    twice = answers(("team", "confidence", 6), ("team", "confidence", 5))
    assert client.post("/study/questionnaire", json=twice).status_code == 422
    assert db.query(SurveyResponse).count() == 0


def test_numeric_answers_and_an_explicit_not_applicable_answer_are_saved(client, db, team, finish_parts, sample_questionnaire):
    finish_parts()
    given = answers(("team", "effort", 0), ("single", "effort", 100), ("team", "roles_clear", "Not applicable"))
    assert client.post("/study/questionnaire", json=given).status_code == 200
    saved = {(row.condition, row.item): row.value for row in db.query(SurveyResponse).all()}
    assert saved[("team", "effort")] == "0"
    assert saved[("single", "effort")] == "100"
    assert saved[("team", "roles_clear")] == "Not applicable"


def test_v11_questionnaire_has_the_approved_16_question_structure():
    form = questionnaire.load()
    questions = [question for section in form.sections for question in section.questions]
    assert form.version == "v1.1"
    assert [question.number for question in questions] == list(range(1, 17))
    assert questions[7].type == "number" and questions[7].scale.min == 0 and questions[7].scale.max == 100
    assert all(question.allow_not_applicable for question in questions[9:12])
    assert not any(question.allow_not_applicable for question in questions[:9])
