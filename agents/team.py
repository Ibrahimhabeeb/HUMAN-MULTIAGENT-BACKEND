import time
from collections.abc import Iterator

from langchain_core.messages import HumanMessage
from sqlalchemy.orm import Session

from agents import runtime
from agents.context import (
    AgentContext,
    Earlier,
    build_context,
    code_listing,
    earlier_proposals,
)
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
from agents.threat_examples import extract as extract_threat_example
from agents.tools import make_tools
from agents.turns import log_message_sent, model_call
from models import Message, Workspace
from schemas.security_state import SecurityState
from services import chat, workspace
from services.errors import ConflictError
from services.events import log_event

# Team mode is one conversation. Each developer message carries a route: the agents that answer it, in order.
# The initial plan and threat analysis run sequentially in one request, with no human handoff.
# Each reply is saved separately, so next_reply can recover an interrupted route without repeating saved work.
THREAD = "team"
NO_VULNERABILITIES_NOTICE = (
    "The Test/Verifier writes tests against approved vulnerabilities. There are none yet, so it had nothing to test."
)


def _risk_list(state: SecurityState) -> str:
    lines = []
    for risk in state.risks:
        details = ", ".join(part for part in (risk.severity, risk.cwe, risk.status) if part)
        lines.append(f"- {risk.id} ({details}): {risk.description}")
    return "\n".join(lines)


def _vulnerability_list(state: SecurityState) -> str:
    tested = {found: test.path for test in state.tests for found in test.vulnerability_ids}
    mitigations: dict[str, list[str]] = {}
    for m in state.mitigations:
        if m.vulnerability_id:
            mitigations.setdefault(m.vulnerability_id, []).append(m.id)
    lines = []
    for v in state.vulnerabilities:
        where = f"{v.file}:{v.line}" if v.file and v.line else v.file
        details = ", ".join(part for part in (v.severity, v.cwe, where, v.status) if part)
        notes = []
        if v.id in mitigations:
            notes.append(f"mitigation {', '.join(mitigations[v.id])}")
        elif v.status == "open":
            notes.append("no mitigation yet")
        if v.id in tested:
            notes.append(f"tested in {tested[v.id]}")
        lines.append(f"- {v.id} ({details}){''.join(f' [{note}]' for note in notes)}: {v.description}")
    return "\n".join(lines)


def _in_the_state(state: SecurityState | None) -> str:
    # Approved findings and their fixes/tests, so the Code Reviewer can avoid duplicates and re-check them.
    state = state or SecurityState()
    return f"The approved vulnerabilities:\n{_vulnerability_list(state) or '(none yet)'}"


def _describe(earlier: Earlier) -> str | None:
    p = earlier.proposal
    match earlier.action_type:
        case "propose_assumption":
            return f"assumption: {p['text']}"
        case "propose_risk":
            return f"risk ({', '.join(filter(None, (p['severity'], p.get('cwe'))))}): {p['description']}"
        case "propose_vulnerability":
            where = f"{p.get('file')}:{p.get('line')}" if p.get("file") and p.get("line") else p.get("file")
            details = ", ".join(filter(None, (p["severity"], p.get("cwe"), where)))
            return f"vulnerability ({details}): {p['description']}"
        case "suggest_fix":
            return f"fix for {p['vulnerability']}: {p['why']}"
        case "mark_resolved":
            return f"mark {p['item_id']} as resolved: {p['reason']}"
        case "propose_test":
            return f"test file {p['path']} for {', '.join(p.get('vulnerability_ids') or []) or 'no vulnerability'}"
    return None  # an action type that no longer exists


def _not_approved(ctx: AgentContext, agent: Specialist) -> str:
    # The agent's own proposals that the developer hasn't approved, with the ids the developer sees, so it never
    # proposes them again.
    lines: dict[str, list[str]] = {"pending": [], "rejected": []}
    for earlier in ctx.earlier:
        described = _describe(earlier)
        if earlier.actor == agent and described:
            lines[earlier.status].append(f"- #{earlier.id} {described[:200]}")
    parts = []
    if lines["pending"]:
        parts.append("Your proposals still waiting for the developer's decision:\n" + "\n".join(lines["pending"]))
    if lines["rejected"]:
        parts.append("Your proposals the developer rejected:\n" + "\n".join(lines["rejected"]))
    return "\n\n".join(parts)


def _waiting(messages: list[Message]) -> tuple[Message, Specialist] | None:
    # The latest developer message, and the first agent on its route that hasn't answered it yet.
    asked = next((m for m in reversed(messages) if m.role == "human"), None)
    if asked is None:
        return None
    answered = {m.data.get("agent") for m in messages if m.data.get("reply_to") == asked.id}
    agent = next((
        a for a in asked.data.get("route", [])
        if a not in answered and not ("snapshot" in asked.data and a == "verifier")
    ), None)
    return (asked, agent) if agent else None


def _input(agent: Specialist, asked: Message, replies: list[Message], ctx: AgentContext) -> str:
    # What the agent is given: the developer's message and what the others already answered; the Code Reviewer
    # always gets the current code and what is in the state, the Test/Verifier the approved vulnerabilities.
    # Every agent also sees its own proposals that are still waiting or were rejected.
    review = "snapshot" in asked.data
    if agent == "verifier":
        vulnerabilities = _vulnerability_list(ctx.state or SecurityState()) or "(none yet)"
        if review:
            text = "The developer asked for a review. Write security tests against the approved vulnerabilities:\n"
            text += vulnerabilities
        else:
            text = f"{asked.content}\n\nThe approved vulnerabilities:\n{vulnerabilities}"
    elif agent == "reviewer" and review:
        text = f"{REVIEW_MESSAGE}\n\n{code_listing(ctx.files)}\n\n{_in_the_state(ctx.state)}"
    else:
        text = asked.content
        for reply in replies:
            text += f"\n\n[{NAMES[reply.data['agent']]} already answered this]\n{reply.content}"
        if agent in ("planner", "threat_modeller"):
            text += f"\n\nTask description (README.md):\n{ctx.task_description}"
            text += "\n\nProject files:\n" + "\n".join(sorted(ctx.files))
            if asked.data.get("route") == FIRST_ROUTE:
                instruction = (
                    "Give the implementation steps now. The Threat Modeller will analyse the threats after your plan."
                    if agent == "planner" else
                    "Analyse potential threats in this task now, building on the plan above. Do not repeat the plan."
                )
                text += f"\n\n{instruction} The handoff is automatic; no developer confirmation is needed."
        if agent == "reviewer":
            text += f"\n\nThe developer's current code:\n{code_listing(ctx.files)}\n\n{_in_the_state(ctx.state)}"
        if agent == "threat_modeller":
            risks = _risk_list(ctx.state or SecurityState()) or "(none yet)"
            text += f"\n\nThe risks already in the security state (don't suggest these again):\n{risks}"
    not_approved = _not_approved(ctx, agent)
    return f"{text}\n\n{not_approved}" if not_approved else text


def _answer(db: Session, ws: Workspace, asked: Message, agent: Specialist) -> dict:
    messages = chat.thread_messages(db, ws, THREAD)
    replies = [m for m in messages if m.data.get("reply_to") == asked.id and m.role == "agent"]
    reply_data = {"agent": agent, "reply_to": asked.id}
    ctx = build_context(ws)
    ctx.earlier = earlier_proposals(db, ws)

    if agent == "verifier" and not (ctx.state and ctx.state.vulnerabilities):
        notice = chat.add_message(db, ws, THREAD, "system", NO_VULNERABILITIES_NOTICE, reply_data)
        db.commit()
        return {"messages": [notice], "approvals": [], "next": next_agent(db, ws)}

    history = chat.as_langchain([m for m in messages if m.id < asked.id], me=agent)
    prompt = [*history, HumanMessage(_input(agent, asked, replies, ctx))]
    tools = make_tools(ctx, agent)
    started = time.monotonic()
    with model_call(db, ws, agent):
        reply = runtime.run_agent(team_prompt(agent), tools, prompt)
    if agent == "threat_modeller":
        reply, example = extract_threat_example(reply, set(ctx.files))
        if example:
            reply_data["threat_example"] = example

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


def _answer_stream(db: Session, ws: Workspace, asked: Message, agent: Specialist) -> Iterator[dict]:
    """Run one team member, yielding deltas before its durable completed reply."""
    messages = chat.thread_messages(db, ws, THREAD)
    replies = [m for m in messages if m.data.get("reply_to") == asked.id and m.role == "agent"]
    reply_data = {"agent": agent, "reply_to": asked.id}
    ctx = build_context(ws)
    ctx.earlier = earlier_proposals(db, ws)

    if agent == "verifier" and not (ctx.state and ctx.state.vulnerabilities):
        notice = chat.add_message(db, ws, THREAD, "system", NO_VULNERABILITIES_NOTICE, reply_data)
        db.commit()
        yield {"type": "message", "message": notice}
        return

    history = chat.as_langchain([m for m in messages if m.id < asked.id], me=agent)
    prompt = [*history, HumanMessage(_input(agent, asked, replies, ctx))]
    tools = make_tools(ctx, agent)
    started = time.monotonic()
    chunks: list[str] = []
    yield {"type": "agent_start", "agent": agent}
    with model_call(db, ws, agent):
        for delta in runtime.run_agent_stream(team_prompt(agent), tools, prompt):
            chunks.append(delta)
            yield {"type": "delta", "agent": agent, "content": delta}
    reply = "".join(chunks)
    if agent == "threat_modeller":
        reply, example = extract_threat_example(reply, set(ctx.files))
        if example:
            reply_data["threat_example"] = example

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
    yield {"type": "agent_complete", "agent": agent, "message": message, "approvals": saved}


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
    replies = [asked]
    proposals = []
    for agent in data["route"]:
        result = _answer(db, ws, asked, agent)
        replies.extend(result["messages"])
        proposals.extend(result["approvals"])
    return {"messages": replies, "approvals": proposals, "next": next_agent(db, ws)}


def send_stream(db: Session, ws: Workspace, thread: str, content: str) -> Iterator[dict]:
    """Save the developer message, then stream each automatically routed team reply."""
    chat.require_thread(ws, thread)
    log_message_sent(db, ws, thread, content)
    messages = chat.thread_messages(db, ws, THREAD)
    if any(m.role == "human" for m in messages):
        decision = _route(db, ws, messages, content)
        data = {"route": [decision.agent], "reason": decision.reason}
    else:
        data = {"route": list(FIRST_ROUTE)}

    asked = chat.add_message(db, ws, THREAD, "human", content, data)
    db.commit()
    yield {"type": "message", "message": asked}
    for agent in data["route"]:
        yield from _answer_stream(db, ws, asked, agent)
    yield {"type": "done", "next": next_agent(db, ws)}


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
