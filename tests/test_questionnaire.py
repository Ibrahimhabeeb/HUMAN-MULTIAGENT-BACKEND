from models import QuestionnaireItem, SurveyResponse
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
    # value_num is the same answer as a number, for the analysis; still nothing about the person or the time.
    assert set(SurveyResponse.__table__.columns.keys()) == {"id", "participant_code", "condition", "item", "value", "value_num"}
    assert {(r.condition, r.item): r.value_num for r in rows if r.value is not None} == {
        ("team", "confidence"): 6, ("none", "preferred"): 1, ("none", "difference"): None,
    }


def test_questions_are_stored_for_the_analysis_and_not_applicable_has_no_number(client, db, team, finish_parts, sample_questionnaire):
    finish_parts()
    client.post("/study/questionnaire", json=answers(("team", "roles_clear", "Not applicable"), ("team", "effort", 40)))
    items = {item.key: (item.type, item.scale_min, item.scale_max) for item in db.query(QuestionnaireItem)}
    assert items == {
        "confidence": ("scale", 1, 7), "effort": ("number", 0, 100), "roles_clear": ("scale", 1, 5),
        "preferred": ("choice", 1, 3), "difference": ("text", None, None),
    }
    rows = {(r.condition, r.item): (r.value, r.value_num) for r in db.query(SurveyResponse)}
    assert rows[("team", "roles_clear")] == ("Not applicable", None)
    assert rows[("team", "effort")] == ("40", 40)


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


def test_v13_questionnaire_uses_text_scales_and_has_the_shared_state_and_open_feedback_questions():
    form = questionnaire.load()
    questions = [question for section in form.sections for question in section.questions]
    assert form.version == "v1.3"
    assert [question.number for question in questions] == list(range(1, 22))
    assert questions[0].text == "How confident are you that the code you completed with the {mode} meets the task's functional requirements?"
    assert questions[1].text == "How confident are you that the code you completed with the {mode} meets the task's security requirements?"
    assert questions[0].options == questions[1].options == [
        "Not at all confident", "Slightly confident", "Moderately confident", "Very confident", "Extremely confident",
    ]
    assert questions[2].key == "vulnerability_risk_trust"
    assert questions[3].key == "mitigation_trust"
    assert questions[7].options == ["None", "A little", "A moderate amount", "A great deal"]
    assert questions[8].key == "security_advice_effort"
    assert [question.key for question in questions[10:16]] == [
        "specialist_role_clarity", "state_unresolved_visibility", "state_evidence_traceability",
        "state_status_tracking", "state_mitigation_linkage", "state_test_visibility",
    ]
    assert all("Not applicable" in question.options for question in questions[10:16])
    assert not any(question.type == "number" for question in questions)
    assert questions[-1].key == "open_feedback" and questions[-1].type == "text"
