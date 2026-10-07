from sqlalchemy.orm import Session

from agents.context import build_context, code_listing
from agents.roles import ASSISTANT_PROMPT, REVIEW_MESSAGE
from agents.turns import agent_turn, log_message_sent
from models import Workspace
from services import chat, workspace
from services.events import log_event


def send(db: Session, ws: Workspace, thread: str, content: str) -> dict:
    chat.require_thread(ws, thread)
    log_message_sent(db, ws, thread, content)
    return agent_turn(db, ws, "assistant", ASSISTANT_PROMPT, build_context(ws), content)


def review(db: Session, ws: Workspace) -> dict:
    # The same neutral message and code listing the team's Reviewer gets.
    ctx = build_context(ws)
    snapshot = workspace.snapshot(ws, "review")
    data = {"snapshot": snapshot.name}
    log_event(db, ws.participant_code, "ready_for_review", mode=ws.mode, detail={**data, "agents": ["assistant"]})
    text = f"{REVIEW_MESSAGE}\n\n{code_listing(ctx.files)}"
    return agent_turn(db, ws, "assistant", ASSISTANT_PROMPT, ctx, text, shown=REVIEW_MESSAGE, data=data)
