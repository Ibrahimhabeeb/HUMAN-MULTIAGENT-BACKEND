from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.errors import run
from db import get_db
from schemas.study import (
    ConsentContent,
    ConsentRequest,
    InformationContent,
    ModeRequest,
    StartRequest,
    StudyState,
)
from services import content, study

router = APIRouter(prefix="/study", tags=["study"])

Db = Annotated[Session, Depends(get_db)]

# Every action returns the new study state, so the frontend always knows which screen to show.


def _state(db: Session) -> StudyState:
    return StudyState(**study.get_state(db))


@router.get("/state")
def get_state(db: Db) -> StudyState:
    return _state(db)


@router.post("/start")
def start(db: Db, body: StartRequest) -> StudyState:
    run(lambda: study.start(db, body.pilot))
    return _state(db)


@router.post("/continue")
def continue_to_consent(db: Db) -> StudyState:
    run(study.continue_to_consent)
    return _state(db)


@router.post("/decline")
def decline(db: Db) -> StudyState:
    run(study.decline)
    return _state(db)


@router.post("/consent")
def consent(db: Db, body: ConsentRequest) -> StudyState:
    run(lambda: study.give_consent(db, body.consent_version))
    return _state(db)


@router.post("/mode")
def switch_mode(db: Db, body: ModeRequest) -> StudyState:
    run(lambda: study.switch_mode(db, body.mode))
    return _state(db)


@router.post("/finish")
def finish(db: Db) -> StudyState:
    run(lambda: study.finish(db))
    return _state(db)


@router.post("/restart")
def restart(db: Db) -> StudyState:
    study.restart(db)
    return _state(db)


@router.get("/content/information")
def information_sheet() -> InformationContent:
    version, markdown = run(lambda: content.load("information_sheet"))
    return InformationContent(version=version, markdown=markdown)


@router.get("/content/consent")
def consent_form() -> ConsentContent:
    version, markdown = run(lambda: content.load("consent"))
    return ConsentContent(version=version, markdown=markdown, statements=content.consent_statements(markdown))
