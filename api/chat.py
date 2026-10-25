from fastapi import APIRouter

from agents import followups, single, team
from api.dependencies import Db
from api.errors import run
from schemas.chat import MessageCreate, MessageOut, TurnResult
from services import chat, study
from services.followups import queue_missing

# The chat of the current part: the team's conversation, or the single assistant's.
# Agents only talk and propose; what they propose comes back as pending approvals.
router = APIRouter(prefix="/chat", tags=["chat"])

MODES = {"team": team, "single": single}


def _turn(result: dict) -> TurnResult:
    return TurnResult.model_validate(result, from_attributes=True)


@router.get("")
def all_threads(db: Db) -> dict[str, list[MessageOut]]:
    def read():
        ws = study.current_workspace(db)
        queue_missing(db, ws)
        db.commit()
        return chat.all_threads(db, ws)

    threads = run(read)
    return {thread: [MessageOut.model_validate(m) for m in messages] for thread, messages in threads.items()}


@router.post("/review")
def ready_for_review(db: Db) -> TurnResult:
    def review():
        ws = study.editable_workspace(db)
        return MODES[ws.mode].review(db, ws)

    return _turn(run(review))


@router.post("/next")
def next_reply(db: Db) -> TurnResult:
    # Team mode: the next agent on the latest message's route answers.
    return _turn(run(lambda: team.next_reply(db, study.editable_workspace(db))))


@router.post("/follow-ups/{message_id}")
def follow_up(db: Db, message_id: int) -> TurnResult:
    return _turn(run(lambda: followups.run(db, study.editable_workspace(db), message_id)))


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
