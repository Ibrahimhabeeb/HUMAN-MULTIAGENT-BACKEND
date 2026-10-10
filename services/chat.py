import re

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from sqlalchemy import select
from sqlalchemy.orm import Session

from agents.context import Proposal
from agents.roles import NAMES, THREADS
from models import Approval, Message, Workspace
from services import approvals
from services.errors import NotFoundError

MAX_HISTORY = 40  # messages of a thread sent back to the model
_LOCAL_REF = re.compile(r"^#(\d+)$")


def require_thread(ws: Workspace, thread: str) -> None:
    if thread not in THREADS[ws.mode]:
        raise NotFoundError(f"There is no {thread} chat in {ws.mode} mode")


def add_message(db: Session, ws: Workspace, thread: str, role: str, content: str, data: dict | None = None) -> Message:
    message = Message(
        participant_code=ws.participant_code,
        workspace_id=ws.id,
        mode=ws.mode,
        thread=thread,
        role=role,
        content=content,
        data=data or {},
    )
    db.add(message)
    db.flush()
    return message


def thread_messages(db: Session, ws: Workspace, thread: str) -> list[Message]:
    query = select(Message).where(Message.workspace_id == ws.id, Message.thread == thread).order_by(Message.id)
    return list(db.scalars(query))


def all_threads(db: Session, ws: Workspace) -> dict[str, list[Message]]:
    return {thread: thread_messages(db, ws, thread) for thread in THREADS[ws.mode]}


def as_langchain(messages: list[Message], me: str | None = None) -> list[BaseMessage]:
    # "system" messages are notices for the human and never go to the model. In the team conversation,
    # another agent's message starts with its name, so each agent can tell who said what.
    result: list[BaseMessage] = []
    for m in [m for m in messages if m.role != "system"][-MAX_HISTORY:]:
        agent = m.data.get("agent")
        if m.role == "human":
            result.append(HumanMessage(m.content))
        elif agent and agent != me:
            result.append(AIMessage(f"[{NAMES[agent]}] {m.content}"))
        else:
            result.append(AIMessage(m.content))
    return result


def save_proposals(db: Session, ws: Workspace, proposals: list[Proposal]) -> list[Approval]:
    # Turns an agent's collected proposals into approval requests. A "#n" reference to another proposal
    # from the same run becomes "approval:<id>", resolved to a real item id once that one is approved.
    saved: list[Approval] = []
    for proposal in proposals:
        data = dict(proposal.proposal)
        for field in ("risk_id", "finding"):
            match = _LOCAL_REF.match(str(data.get(field) or "").strip())
            if match and 0 < int(match.group(1)) <= len(saved):
                data[field] = f"approval:{saved[int(match.group(1)) - 1].id}"
        saved.append(approvals.request_approval(db, ws, proposal.actor, proposal.action_type, data))  # type: ignore[arg-type]
    return saved
