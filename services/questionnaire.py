import logging
from pathlib import Path

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from config import get_settings
from models import QuestionnaireItem, SurveyResponse
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
NOT_APPLICABLE = "Not applicable"


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


def _ordered(question: Question) -> list[str]:
    return [option for option in question.options if option != NOT_APPLICABLE]


def sync_items(db: Session, *, commit: bool = True) -> None:
    # Keeps the questionnaire_items table in step with content/questionnaire.json, so answers can be analysed in SQL.
    if not _path().is_file():
        return
    questionnaire = load()
    for section in questionnaire.sections:
        for question in section.questions:
            if question.type == "choice":
                low, high = 1, len(_ordered(question))
            elif question.scale is not None:
                low, high = question.scale.min, question.scale.max
            else:
                low = high = None
            item = db.get(QuestionnaireItem, question.key) or QuestionnaireItem(key=question.key)
            item.number, item.section, item.asked_for = question.number, section.title, section.asked_for
            item.type, item.text, item.options = question.type, question.text, list(question.options)
            item.scale_min, item.scale_max, item.reverse_scored = low, high, question.reverse_scored
            item.version = questionnaire.version
            db.add(item)
    db.flush()
    if commit:
        db.commit()


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
        if value == NOT_APPLICABLE and question.allow_not_applicable:
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


def _number(question: Question, value: str | None) -> int | None:
    # The answer as a number for the analysis: a choice's position among the ordered options (1 = first), or the
    # number itself. None if skipped, "Not applicable" or text.
    if value is None or value == NOT_APPLICABLE:
        return None
    if question.type == "choice":
        options = _ordered(question)
        return options.index(value) + 1 if value in options else None
    return int(value) if question.type in {"scale", "number"} else None


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
    sync_items(db, commit=False)  # each answer points at its question
    for (condition, item), question in questions.items():
        value = given.get((condition, item))
        db.add(SurveyResponse(
            participant_code=code, condition=condition, item=item, value=value, value_num=_number(question, value),
        ))
    try:
        db.commit()
    except IntegrityError as e:  # a second submission at the same moment
        db.rollback()
        raise ConflictError("The questionnaire has already been submitted") from e
