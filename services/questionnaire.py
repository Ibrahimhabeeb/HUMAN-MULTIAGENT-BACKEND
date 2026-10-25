import logging
from pathlib import Path

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from config import get_settings
from models import SurveyResponse
from schemas.questionnaire import (
    MAX_ANSWER_CHARS,
    Answer,
    Question,
    Questionnaire,
)
from services import study
from services.errors import ConflictError, InvalidInputError, NotFoundError

MODE_NAMES = {"team": "Agent team", "single": "Single assistant"}
CONDITIONS = {"each_mode": ("team", "single"), "team": ("team",), "once": ("none",)}


def _path() -> Path:
    return Path(get_settings().content_dir) / "questionnaire.json"


def load() -> Questionnaire:
    if not _path().is_file():
        raise NotFoundError("The questionnaire isn't ready: content/questionnaire.json is missing")
    return Questionnaire.model_validate_json(_path().read_text(encoding="utf-8"))


def check() -> None:
    # Run at startup, so a mistake in the file shows up before a participant reaches the questionnaire.
    if _path().is_file():
        load()
    else:
        logging.getLogger(__name__).warning("content/questionnaire.json is missing; add it before the study")


def asked(questionnaire: Questionnaire) -> dict[tuple[str, str], Question]:
    # Every (condition, question key) the form asks, in the form's order.
    return {
        (condition, question.key): question
        for section in questionnaire.sections
        for question in section.questions
        for condition in CONDITIONS[section.asked_for]
    }


def _open(db: Session) -> dict:
    state = study.get_state(db)
    if state["screen"] == "thank_you":
        raise ConflictError("The questionnaire has already been submitted")
    if state["screen"] != "questionnaire":
        raise ConflictError("The questionnaire opens once both parts are done")
    return state


def get(db: Session) -> dict:
    state = _open(db)
    modes = [{"mode": p["mode"], "label": f"{MODE_NAMES[p['mode']]} ({p['task_label']})"} for p in state["parts"]]
    return {**load().model_dump(), "modes": modes}


def _value(question: Question, value: int | str | None) -> str | None:
    if value is None or value == "":
        return None
    if question.type in {"scale", "number"}:
        if value == "Not applicable" and question.allow_not_applicable:
            return value
        if type(value) is not int or question.scale is None or not question.scale.min <= value <= question.scale.max:
            scale = question.scale
            bounds = f"{scale.min} to {scale.max}" if scale else "the permitted range"
            raise InvalidInputError(f"{question.key}: choose a number from {bounds}")
        return str(value)
    if not isinstance(value, str):
        raise InvalidInputError(f"{question.key}: the answer must be text")
    if question.type == "choice" and value not in question.options:
        raise InvalidInputError(f"{question.key}: {value!r} is not one of the options")
    if len(value) > MAX_ANSWER_CHARS:
        raise InvalidInputError(f"{question.key}: answers can be at most {MAX_ANSWER_CHARS} characters")
    return value.strip() or None


def submit(db: Session, answers: list[Answer]) -> None:
    code = _open(db)["participant"]
    questionnaire = load()
    questions = asked(questionnaire)
    given: dict[tuple[str, str], str | None] = {}
    for answer in answers:
        key = (answer.condition, answer.item)
        if key not in questions:
            raise InvalidInputError(f"There is no question {answer.item} for {answer.condition}")
        if key in given:
            raise InvalidInputError(f"{answer.item} ({answer.condition}) is answered twice")
        given[key] = _value(questions[key], answer.value)

    # A row for every question, so a skipped one is stored as NULL. No event is logged, so no time goes with it.
    for condition, item in questions:
        db.add(SurveyResponse(participant_code=code, condition=condition, item=item, value=given.get((condition, item))))
    try:
        db.commit()
    except IntegrityError as e:  # a second submission at the same moment
        db.rollback()
        raise ConflictError("The questionnaire has already been submitted") from e
