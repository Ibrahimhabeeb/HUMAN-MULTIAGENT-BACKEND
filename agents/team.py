import time

from langchain_core.messages import HumanMessage
from sqlalchemy.orm import Session

from agents import runtime
from agents.context import AgentContext, build_context, code_listing
from agents.roles import (
    FACILITATOR_PROMPT,
    FIRST_ROUTE,
    NAMES,
    REVIEW_MESSAGE,
    REVIEW_ROUTE,
    Specialist,
    team_prompt,
)
from agents.runtime import RouteDecision
from agents.tools import make_tools
from agents.turns import log_message_sent, model_call
from models import Message, Workspace
from schemas.security_state import SecurityState
from services import chat, workspace
from services.errors import ConflictError
from services.events import log_event

# Team mode is one conversation. Each developer message carries a route: the agents that answer it, in order.
# Every call answers with one agent; when more are on the route, the frontend asks for the next one (next_reply),
# so the chat shows each answer as soon as it is ready.
THREAD = "team"
NO_RISKS_NOTICE = "The Test/Verifier writes security tests from approved risks. There are none yet, so it had nothing to test."


def _risk_list(state: SecurityState) -> str:
    tested = {risk_id: test.path for test in state.tests for risk_id in test.risk_ids}
    lines = []
    for risk in state.risks:
        line = f"- {risk.id} ({risk.severity}{', ' + risk.cwe if risk.cwe else ''}): {risk.description}"
        lines.append(line + (f" [already tested in {tested[risk.id]}]" if risk.id in tested else ""))
    return "\n".join(lines)


def _waiting(messages: list[Message]) -> tuple[Message, Specialist] | None:
    # The latest developer message, and the first agent on its route that hasn't answered it yet.
    asked = next((m for m in reversed(messages) if m.role == "human"), None)
    if asked is None:
        return None
    answered = {m.data.get("agent") for m in messages if m.data.get("reply_to") == asked.id}
    agent = next((a for a in asked.data.get("route", []) if a not in answered), None)
    return (asked, agent) if agent else None


def _input(agent: Specialist, asked: Message, replies: list[Message], ctx: AgentContext) -> str:
    # What the agent is given: the developer's message and what the others already answered; the Code Reviewer
    # always gets the current code, the Test/Verifier the approved risks.
    review = "snapshot" in asked.data
    if agent == "verifier":
        risks = _risk_list(ctx.state or SecurityState()) or "(none yet)"
        if review:
            return f"The developer asked for a review. Write security tests for the approved risks:\n{risks}"
        return f"{asked.content}\n\nThe approved risks:\n{risks}"
    if agent == "reviewer" and review:
        return f"{REVIEW_MESSAGE}\n\n{code_listing(ctx.files)}"

    text = asked.content
    for reply in replies:
        text += f"\n\n[{NAMES[reply.data['agent']]} already answered this]\n{reply.content}"
    if agent == "reviewer":
        text += f"\n\nThe developer's current code:\n{code_listing(ctx.files)}"
    return text


def _answer(db: Session, ws: Workspace, asked: Message, agent: Specialist) -> dict:
    messages = chat.thread_messages(db, ws, THREAD)
    replies = [m for m in messages if m.data.get("reply_to") == asked.id and m.role == "agent"]
    reply_data = {"agent": agent, "reply_to": asked.id}
    ctx = build_context(ws)

    if agent == "verifier" and not (ctx.state and ctx.state.risks):
        notice = chat.add_message(db, ws, THREAD, "system", NO_RISKS_NOTICE, reply_data)
        db.commit()
        return {"messages": [notice], "approvals": [], "next": next_agent(db, ws)}

    history = chat.as_langchain([m for m in messages if m.id < asked.id], me=agent)
    prompt = [*history, HumanMessage(_input(agent, asked, replies, ctx))]
    tools = make_tools(ctx, agent)
    started = time.monotonic()
    with model_call(db, ws, agent):
        reply = runtime.run_agent(team_prompt(agent), tools, prompt)

    saved = chat.save_proposals(db, ws, ctx.proposals)
    message = chat.add_message(db, ws, THREAD, "agent", reply, {**reply_data, "approval_ids": [a.id for a in saved]})
    log_event(
        db,
        ws.participant_code,
        "agent_replied",
        actor=agent,
        mode=ws.mode,
        detail={"seconds": round(time.monotonic() - started, 1), "proposals": len(saved)},
    )
    db.commit()
    return {"messages": [message], "approvals": saved, "next": next_agent(db, ws)}


def _route(db: Session, ws: Workspace, messages: list[Message], content: str) -> RouteDecision:
    reviewed = any("snapshot" in m.data for m in messages)
    stage = "The code has been reviewed at least once." if reviewed else "The code has not been reviewed yet."
    with model_call(db, ws, "facilitator"):
        decision = runtime.route(
            FACILITATOR_PROMPT.format(stage=stage), [*chat.as_langchain(messages), HumanMessage(content)]
        )
    log_event(
        db,
        ws.participant_code,
        "message_routed",
        actor="facilitator",
        mode=ws.mode,
        detail={"agent": decision.agent, "reason": decision.reason},
    )
    return decision


def next_agent(db: Session, ws: Workspace) -> Specialist | None:
    waiting = _waiting(chat.thread_messages(db, ws, THREAD))
    return waiting[1] if waiting else None


def send(db: Session, ws: Workspace, thread: str, content: str) -> dict:
    chat.require_thread(ws, thread)
    log_message_sent(db, ws, thread, content)
    messages = chat.thread_messages(db, ws, THREAD)
    if any(m.role == "human" for m in messages):
        decision = _route(db, ws, messages, content)
        data = {"route": [decision.agent], "reason": decision.reason}
    else:
        data = {"route": list(FIRST_ROUTE)}  # telling the team what you want to build: steps, then threats

    # Saved before any agent answers, so if one fails the developer can retry with next_reply.
    asked = chat.add_message(db, ws, THREAD, "human", content, data)
    db.commit()
    result = _answer(db, ws, asked, data["route"][0])
    return {**result, "messages": [asked, *result["messages"]]}


def review(db: Session, ws: Workspace) -> dict:
    snapshot = workspace.snapshot(ws, "review")
    log_event(db, ws.participant_code, "ready_for_review", mode=ws.mode, detail={"snapshot": snapshot.name})
    data = {"snapshot": snapshot.name, "route": list(REVIEW_ROUTE)}
    # The code listing isn't kept in the chat; the snapshot holds exactly what was reviewed.
    asked = chat.add_message(db, ws, THREAD, "human", REVIEW_MESSAGE, data)
    db.commit()
    result = _answer(db, ws, asked, "reviewer")
    return {**result, "messages": [asked, *result["messages"]]}


def next_reply(db: Session, ws: Workspace) -> dict:
    if ws.mode != "team":
        raise ConflictError("Only the agent team has more than one agent to answer")
    waiting = _waiting(chat.thread_messages(db, ws, THREAD))
    if waiting is None:
        raise ConflictError("No agent is waiting to answer")
    return _answer(db, ws, *waiting)
