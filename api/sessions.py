from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from agents import team
from api.errors import run
from db import get_db
from llm import ModelNotConfiguredError
from schemas.chat import ChatMessage, MessageCreate
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


@router.post("/{session_id}/messages")
def send_message(db: Db, session_id: str, body: MessageCreate) -> list[ChatMessage]:
    session = run(lambda: projects.get_session(db, session_id))
    run(lambda: projects.open_session(db, session.project_id, session_id))
    try:
        replies = team.run_turn(
            db, session.project_id, session_id, body.content, body.agents
        )
    except ModelNotConfiguredError as e:
        raise HTTPException(status_code=503, detail=str(e)) from e
    except Exception as e:
        # Provider problems (bad key, rate limit, network). Only the error type is returned, never details
        # that could contain request data or credentials.
        raise HTTPException(
            status_code=502, detail=f"The AI provider call failed ({type(e).__name__})"
        ) from e
    return [ChatMessage(**r) for r in replies]


@router.get("/{session_id}/messages")
def list_messages(db: Db, session_id: str) -> list[ChatMessage]:
    run(lambda: projects.get_session(db, session_id))
    return [ChatMessage(**m) for m in team.history(session_id)]
