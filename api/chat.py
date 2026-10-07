from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from agents import single, team
from agents.roles import Specialist
from api.errors import run
from db import get_db
from schemas.chat import MessageCreate, MessageOut, TurnResult
from services import chat, study

# The chat of the current part: one thread per agent in team mode, one assistant thread in single mode.
# Agents only talk and propose; what they propose comes back as pending approvals.
router = APIRouter(prefix="/chat", tags=["chat"])

Db = Annotated[Session, Depends(get_db)]
MODES = {"team": team, "single": single}


def _turn(result: dict) -> TurnResult:
    return TurnResult.model_validate(result, from_attributes=True)


@router.get("")
def all_threads(db: Db) -> dict[str, list[MessageOut]]:
    threads = run(lambda: chat.all_threads(db, study.current_workspace(db)))
    return {thread: [MessageOut.model_validate(m) for m in messages] for thread, messages in threads.items()}


@router.post("/review")
def ready_for_review(db: Db) -> TurnResult:
    def review():
        ws = study.editable_workspace(db)
        return MODES[ws.mode].review(db, ws)

    return _turn(run(review))


@router.post("/consult/{agent}")
def consult(db: Db, agent: Specialist) -> TurnResult:
    return _turn(run(lambda: team.consult(db, study.editable_workspace(db), agent)))


@router.get("/{thread}")
def thread_messages(db: Db, thread: str) -> list[MessageOut]:
    def read():
        ws = study.current_workspace(db)
        chat.require_thread(ws, thread)
        return chat.thread_messages(db, ws, thread)

    return [MessageOut.model_validate(m) for m in run(read)]


@router.post("/{thread}")
def send(db: Db, thread: str, body: MessageCreate) -> TurnResult:
    def send_message():
        ws = study.editable_workspace(db)
        return MODES[ws.mode].send(db, ws, thread, body.content)

    return _turn(run(send_message))
