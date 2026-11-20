import time
from collections.abc import Generator
from contextlib import contextmanager

from langchain_core.messages import HumanMessage
from sqlalchemy.orm import Session

from agents import runtime
from agents.context import AgentContext
from agents.tools import make_tools
from llm import ModelCallError, ModelNotConfiguredError
from models import Workspace
from services import chat
from services.events import log_event


@contextmanager
def model_call(db: Session, ws: Workspace, *agents: str) -> Generator[None]:
    # Commits first, so SQLite isn't kept locked while the model thinks and other requests can carry on.
    db.commit()
    try:
        yield
    except ModelNotConfiguredError:
        raise
    except Exception as e:
        log_event(
            db,
            ws.participant_code,
            "agent_failed",
            actor="system",
            mode=ws.mode,
            detail={"agents": list(agents), "error": type(e).__name__},
        )
        db.commit()
        raise ModelCallError(f"The AI model could not answer ({type(e).__name__}). Please try again.") from e


def save_turn(
    db: Session,
    ws: Workspace,
    thread: str,
    human_text: str,
    reply: str,
    ctx: AgentContext,
    seconds: float,
    human_data: dict | None = None,
) -> dict:
    # Saved only once the model has answered, so a failed call leaves no half-finished turn.
    human = chat.add_message(db, ws, thread, "human", human_text, human_data)
    saved = chat.save_proposals(db, ws, ctx.proposals)
    agent = chat.add_message(db, ws, thread, "agent", reply, {"approval_ids": [a.id for a in saved]})
    log_event(
        db,
        ws.participant_code,
        "agent_replied",
        actor=thread,
        mode=ws.mode,
        detail={"seconds": round(seconds, 1), "proposals": len(saved)},
    )
    db.commit()
    return {"messages": [human, agent], "approvals": saved}


def agent_turn(
    db: Session,
    ws: Workspace,
    thread: str,
    system_prompt: str,
    ctx: AgentContext,
    text: str,
    *,
    shown: str | None = None,
    data: dict | None = None,
) -> dict:
    # `text` goes to the model; the chat keeps `shown` instead when given (e.g. without the code listing).
    messages = [*chat.as_langchain(chat.thread_messages(db, ws, thread)), HumanMessage(text)]
    tools = make_tools(ctx, thread)
    started = time.monotonic()
    with model_call(db, ws, thread):
        reply = runtime.run_agent(system_prompt, tools, messages)
    return save_turn(db, ws, thread, shown or text, reply, ctx, time.monotonic() - started, data)


def agent_turn_stream(
    db: Session,
    ws: Workspace,
    thread: str,
    system_prompt: str,
    ctx: AgentContext,
    text: str,
    *,
    shown: str | None = None,
    data: dict | None = None,
) -> Generator[dict]:
    """Stream an assistant reply and persist it only after the model finishes."""
    messages = [*chat.as_langchain(chat.thread_messages(db, ws, thread)), HumanMessage(text)]
    tools = make_tools(ctx, thread)
    human = chat.add_message(db, ws, thread, "human", shown or text, data)
    db.commit()
    yield {"type": "message", "message": human}

    started = time.monotonic()
    chunks: list[str] = []
    yield {"type": "agent_start", "agent": "assistant"}
    with model_call(db, ws, thread):
        for delta in runtime.run_agent_stream(system_prompt, tools, messages):
            chunks.append(delta)
            yield {"type": "delta", "agent": "assistant", "content": delta}

    saved = chat.save_proposals(db, ws, ctx.proposals)
    agent = chat.add_message(db, ws, thread, "agent", "".join(chunks), {"approval_ids": [a.id for a in saved]})
    log_event(
        db,
        ws.participant_code,
        "agent_replied",
        actor=thread,
        mode=ws.mode,
        detail={"seconds": round(time.monotonic() - started, 1), "proposals": len(saved)},
    )
    db.commit()
    yield {"type": "agent_complete", "agent": "assistant", "message": agent, "approvals": saved}


def log_message_sent(db: Session, ws: Workspace, thread: str, content: str) -> None:
    log_event(db, ws.participant_code, "message_sent", mode=ws.mode, detail={"thread": thread, "chars": len(content)})

