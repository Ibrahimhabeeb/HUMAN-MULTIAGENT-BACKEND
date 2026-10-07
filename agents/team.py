import json
import time

from langchain_core.messages import HumanMessage
from sqlalchemy.orm import Session

from agents import runtime
from agents.context import AgentContext, build_context, code_listing
from agents.roles import (
    FACILITATOR_PROMPT,
    REVIEW_MESSAGE,
    ROLE_PROMPTS,
    SHARED_RULES,
    SPECIALISTS,
    Specialist,
)
from agents.tools import make_tools
from agents.turns import agent_turn, log_message_sent, merge, model_call, save_turn
from models import Message, Workspace
from schemas.security_state import SecurityState
from services import approvals, chat, state_service, workspace
from services.events import log_event

NO_RISKS_NOTICE = (
    "The Verifier writes security tests from approved risks. There are none yet, so it had nothing to test."
)


def _prompt(role: Specialist) -> str:
    return ROLE_PROMPTS[role] + SHARED_RULES


def _state_summary(db: Session, ws: Workspace) -> str:
    state = state_service.load(ws)
    return json.dumps(
        {
            "risks": [{"id": r.id, "status": r.status} for r in state.risks],
            "open_findings": [f.id for f in state.findings if f.status == "open"],
            "mitigations": len(state.mitigations),
            "tests": len(state.tests),
            "proposals_waiting_for_approval": len(approvals.list_approvals(db, ws, "pending")),
        }
    )


# ---- the Facilitator suggests; the human decides whom to consult -----------------------------


def _ask_facilitator(db: Session, ws: Workspace, content: str) -> dict:
    consulted = [role for role in SPECIALISTS if chat.thread_messages(db, ws, role)]
    prompt = FACILITATOR_PROMPT.format(consulted=", ".join(consulted) or "none", state_summary=_state_summary(db, ws))
    messages = [*chat.as_langchain(chat.thread_messages(db, ws, "facilitator")), HumanMessage(content)]
    started = time.monotonic()
    with model_call(db, ws, "facilitator"):
        reply = runtime.facilitate(prompt, messages)
    seconds = round(time.monotonic() - started, 1)

    suggestions: dict[str, dict] = {}
    for suggestion in reply.suggestions:
        suggestions.setdefault(suggestion.agent, suggestion.model_dump())  # one button per agent
    human = chat.add_message(db, ws, "facilitator", "human", content)
    agent = chat.add_message(db, ws, "facilitator", "agent", reply.message, {"suggestions": list(suggestions.values())})
    log_event(
        db,
        ws.participant_code,
        "facilitator_suggested",
        actor="facilitator",
        mode=ws.mode,
        detail={"agents": list(suggestions), "seconds": seconds},
    )
    db.commit()
    return {"messages": [human, agent], "approvals": []}


def send(db: Session, ws: Workspace, thread: str, content: str) -> dict:
    chat.require_thread(ws, thread)
    log_message_sent(db, ws, thread, content)
    if thread == "facilitator":
        return _ask_facilitator(db, ws, content)
    return agent_turn(db, ws, thread, _prompt(thread), build_context(ws), content)  # type: ignore[arg-type]


def _suggested_reason(facilitator: list[Message], agent: Specialist) -> str | None:
    # Why the Facilitator's latest reply suggested this agent, if it did.
    replies = [m for m in facilitator if m.role == "agent"]
    suggestions = replies[-1].data.get("suggestions", []) if replies else []
    return next((s["reason"] for s in suggestions if s["agent"] == agent), None)


def consult(db: Session, ws: Workspace, agent: Specialist) -> dict:
    # The human clicked to consult an agent: one the Facilitator suggested, or their own choice.
    state_service.require_team(ws)
    facilitator = chat.thread_messages(db, ws, "facilitator")
    told = "\n\n".join(m.content for m in facilitator if m.role == "human")
    reason = _suggested_reason(facilitator, agent)
    text = "The developer is consulting you."
    if told:
        text += f"\n\nWhat they told the Facilitator:\n{told[-4000:]}"
    if reason:
        text += f"\n\nThe Facilitator suggested you because: {reason}"
    log_event(
        db, ws.participant_code, "agent_consulted", mode=ws.mode, detail={"agent": agent, "suggested": reason is not None}
    )
    return agent_turn(db, ws, agent, _prompt(agent), build_context(ws), text, data={"consult": True})


# ---- Ready for review: the Reviewer and the Verifier in parallel -------------------------------


def _risk_list(state: SecurityState) -> str:
    tested = {risk_id: test.path for test in state.tests for risk_id in test.risk_ids}
    lines = []
    for risk in state.risks:
        line = f"- {risk.id} ({risk.severity}{', ' + risk.cwe if risk.cwe else ''}): {risk.description}"
        lines.append(line + (f" [already tested in {tested[risk.id]}]" if risk.id in tested else ""))
    return "\n".join(lines)


def review(db: Session, ws: Workspace) -> dict:
    # Each agent gets its own context, so their proposals stay apart while they run side by side.
    reviewer_ctx, verifier_ctx = build_context(ws), build_context(ws)
    state = verifier_ctx.state or SecurityState()
    review_text = f"{REVIEW_MESSAGE}\n\n{code_listing(reviewer_ctx.files)}"
    verifier_text = "The developer clicked Ready for review. Write security tests for the approved risks:\n"
    verifier_text += _risk_list(state)
    seconds: dict[str, float] = {}

    def job(role: Specialist, ctx: AgentContext, text: str):
        tools = make_tools(ctx, role)
        messages = [*chat.as_langchain(chat.thread_messages(db, ws, role)), HumanMessage(text)]

        def call() -> str:
            started = time.monotonic()
            reply = runtime.run_agent(_prompt(role), tools, messages)
            seconds[role] = time.monotonic() - started
            return reply

        return call

    jobs = {"reviewer": job("reviewer", reviewer_ctx, review_text)}
    if state.risks:  # tests are written from approved risks; with none, the Verifier has nothing to work from
        jobs["verifier"] = job("verifier", verifier_ctx, verifier_text)

    snapshot = workspace.snapshot(ws, "review")
    data = {"snapshot": snapshot.name}
    log_event(db, ws.participant_code, "ready_for_review", mode=ws.mode, detail={**data, "agents": list(jobs)})
    with model_call(db, ws, *jobs):
        replies = runtime.run_parallel(jobs)

    # The code listing isn't kept in the chat; the snapshot holds exactly what was reviewed.
    reviewed = save_turn(
        db, ws, "reviewer", REVIEW_MESSAGE, replies["reviewer"], reviewer_ctx, seconds["reviewer"], data
    )
    if "verifier" in replies:
        verified = save_turn(
            db, ws, "verifier", verifier_text, replies["verifier"], verifier_ctx, seconds["verifier"], data
        )
    else:
        notice = chat.add_message(db, ws, "verifier", "system", NO_RISKS_NOTICE, data)
        db.commit()
        verified = {"messages": [notice], "approvals": []}
    return merge(reviewed, verified)
