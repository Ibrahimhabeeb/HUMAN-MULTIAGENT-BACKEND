import json
from collections.abc import Iterator

from fastapi import APIRouter
from fastapi.encoders import jsonable_encoder
from fastapi.responses import StreamingResponse

from agents import followups, single, team
from api.dependencies import Db
from api.errors import run
from llm import ModelCallError, ModelNotConfiguredError
from schemas.approval import ApprovalOut
from schemas.chat import MessageCreate, MessageOut, TurnResult
from services import chat, study
from services.errors import ConflictError, InvalidInputError, NotFoundError
from services.followups import queue_missing

# The chat of the current part: the team's conversation, or the single assistant's.
# Agents only talk and propose; what they propose comes back as pending approvals.
router = APIRouter(prefix="/chat", tags=["chat"])

MODES = {"team": team, "single": single}


def _turn(result: dict) -> TurnResult:
    return TurnResult.model_validate(result, from_attributes=True)


def _line(event: dict) -> str:
    """Convert durable ORM values in an internal event into one NDJSON record."""
    payload = dict(event)
    if "message" in payload:
        payload["message"] = MessageOut.model_validate(payload["message"], from_attributes=True).model_dump(mode="json")
    if "approvals" in payload:
        payload["approvals"] = [
            ApprovalOut.model_validate(approval, from_attributes=True).model_dump(mode="json")
            for approval in payload["approvals"]
        ]
    return json.dumps(jsonable_encoder(payload), separators=(",", ":")) + "\n"


def _stream_error(error: Exception) -> dict:
    if isinstance(error, NotFoundError):
        return {"type": "error", "status": 404, "detail": str(error)}
    if isinstance(error, ConflictError):
        return {"type": "error", "status": 409, "detail": str(error)}
    if isinstance(error, InvalidInputError):
        return {"type": "error", "status": 422, "detail": str(error)}
    if isinstance(error, ModelNotConfiguredError):
        return {"type": "error", "status": 503, "detail": str(error)}
    if isinstance(error, ModelCallError):
        return {"type": "error", "status": 502, "detail": str(error)}
    return {"type": "error", "status": 502, "detail": "The AI model could not answer. Please try again."}


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


@router.post("/{thread}/stream")
def send_stream(db: Db, thread: str, body: MessageCreate) -> StreamingResponse:
    # Validate before response headers are sent, so invalid threads and finished parts still return normal HTTP errors.
    ws = run(lambda: study.editable_workspace(db))
    run(lambda: chat.require_thread(ws, thread))

    def events() -> Iterator[str]:
        try:
            for event in MODES[ws.mode].send_stream(db, ws, thread, body.content):
                yield _line(event)
        except Exception as error:  # noqa: BLE001 - the response has started, so every late failure is an event.
            # A streamed response has already started, so report late failures as a final typed event for the UI.
            yield _line(_stream_error(error))

    return StreamingResponse(events(), media_type="application/x-ndjson", headers={"Cache-Control": "no-store"})


@router.post("/{thread}")
def send(db: Db, thread: str, body: MessageCreate) -> TurnResult:
    def send_message():
        ws = study.editable_workspace(db)
        return MODES[ws.mode].send(db, ws, thread, body.content)

    return _turn(run(send_message))
