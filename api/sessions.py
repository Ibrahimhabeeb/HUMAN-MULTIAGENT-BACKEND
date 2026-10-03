from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.errors import run
from db import get_db
from schemas.session import SessionInfo
from services import projects

router = APIRouter(prefix="/sessions", tags=["sessions"])

Db = Annotated[Session, Depends(get_db)]


@router.get("/{session_id}")
def get_session(db: Db, session_id: str) -> SessionInfo:
    return SessionInfo.model_validate(run(lambda: projects.get_session(db, session_id)))


@router.post("/{session_id}/end")
def end_session(db: Db, session_id: str) -> SessionInfo:
    return SessionInfo.model_validate(run(lambda: projects.end_session(db, session_id)))
