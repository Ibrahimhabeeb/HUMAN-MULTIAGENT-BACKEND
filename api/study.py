from typing import get_args

from fastapi import APIRouter, Response
from sqlalchemy.orm import Session

from api.dependencies import Db
from api.errors import run
from schemas.questionnaire import QuestionnaireAnswers, QuestionnaireOut
from schemas.study import (
    ConsentContent,
    ConsentRequest,
    InformationContent,
    Mode,
    ModeRequest,
    NextTaskRequest,
    SessionToken,
    StartRequest,
    StudyState,
    TaskId,
)
from services import content, questionnaire, sessions, study, workspace

router = APIRouter(prefix="/study", tags=["study"])

# Every action returns the new study state, so the frontend always knows which screen to show.


def _state(db: Session) -> StudyState:
    state = study.get_state(db)
    if state["screen"] == "start":
        task_ids = get_args(TaskId)
    elif state.get("needs_next_task"):
        used_tasks = study.next_task_choices(db) or set()
        task_ids = [task_id for task_id in get_args(TaskId) if task_id not in used_tasks]
    else:
        task_ids = []
    return StudyState(
        **state,
        available_tasks=[workspace.task_info(task_id) for task_id in task_ids],
    )


@router.post("/session")
def create_session(body: ModeRequest, response: Response) -> SessionToken:
    response.headers["Cache-Control"] = "no-store"
    return SessionToken(token=sessions.create(body.mode))


def _new_session(db: Session, response: Response, mode: Mode) -> StudyState:
    token = sessions.create(mode)
    sessions.bind(db, token)
    response.headers[sessions.HEADER] = token
    return _state(db)


@router.get("/state")
def get_state(db: Db) -> StudyState:
    return _state(db)


@router.post("/start")
def start(db: Db, body: StartRequest) -> StudyState:
    run(lambda: study.start(db, body.pilot, body.task_id))
    return _state(db)


@router.post("/continue")
def continue_to_consent(db: Db) -> StudyState:
    run(lambda: study.continue_to_consent(db))
    return _state(db)


@router.post("/decline")
def decline(db: Db) -> StudyState:
    run(lambda: study.decline(db))
    return _state(db)


@router.post("/consent")
def consent(db: Db, body: ConsentRequest) -> StudyState:
    run(lambda: study.give_consent(db, body.consent_version))
    return _state(db)


@router.post("/mode")
def switch_mode(db: Db, body: ModeRequest) -> StudyState:
    run(lambda: study.switch_mode(db, body.mode))
    return _state(db)


@router.post("/part-two")
def start_part_two(db: Db, body: NextTaskRequest) -> StudyState:
    run(lambda: study.start_part_two(db, body.task_id))
    return _state(db)


@router.post("/done")
def done(db: Db) -> StudyState:
    run(lambda: study.done(db))
    return _state(db)


@router.post("/finish")
def finish(db: Db, response: Response) -> StudyState:
    mode = run(lambda: study.finish(db))
    return _new_session(db, response, mode)


@router.post("/restart")
def restart(db: Db, response: Response) -> StudyState:
    mode = run(lambda: study.restart(db))
    return _new_session(db, response, mode)


@router.get("/questionnaire")
def questionnaire_form(db: Db) -> QuestionnaireOut:
    return QuestionnaireOut.model_validate(run(lambda: questionnaire.get(db)))


@router.post("/questionnaire")
def submit_questionnaire(db: Db, body: QuestionnaireAnswers) -> StudyState:
    run(lambda: questionnaire.submit(db, body.answers))
    return _state(db)


@router.get("/content/information")
def information_sheet() -> InformationContent:
    version, markdown = run(lambda: content.load("information_sheet"))
    return InformationContent(version=version, markdown=markdown)


@router.get("/content/consent")
def consent_form() -> ConsentContent:
    version, markdown = run(lambda: content.load("consent"))
    return ConsentContent(version=version, markdown=markdown, statements=content.consent_statements(markdown))
