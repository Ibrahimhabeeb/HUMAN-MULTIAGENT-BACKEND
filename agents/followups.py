import time
from uuid import uuid4

from langchain_core.messages import HumanMessage
from sqlalchemy import exists, select, update
from sqlalchemy.orm import Session, aliased

from agents import runtime
from agents.context import AgentContext, build_context, code_listing, earlier_proposals
from agents.roles import team_prompt
from agents.team import _not_approved, _vulnerability_list
from agents.tools import make_tools
from agents.turns import model_call
from models import Approval, Message, Workspace
from schemas.security_state import Mitigation
from services import chat
from services.errors import NotFoundError
from services.events import log_event
from services.followups import KIND

LEASE_SECONDS = 600
FIX_TOOLS = {"list_files", "read_file", "read_task_description", "get_security_state", "suggest_fix"}


def _test_request(ctx: AgentContext, target: str, fixes: list[Mitigation]) -> str:
    # The Test/Verifier first decides whether a new test adds anything; it still never reads application source.
    tests = {p: c for p, c in ctx.files.items() if p.startswith("tests/") and p.endswith(".py")}
    waiting = {
        e.proposal["path"]: e.proposal["content"]
        for e in ctx.earlier
        if (e.actor, e.status, e.action_type) == ("verifier", "pending", "propose_test")
    }
    fixed_by = "\n".join(f"- {m.id}: {m.description}" for m in fixes) or "(the fix is no longer in the security state)"
    text = (
        f"The developer approved a fix for {target}:\n{fixed_by}\n\n{_vulnerability_list(ctx.state)}\n\n"
        f"Decide whether {target} needs a new security test, then do one of these:\n"
        "- Already covered: an existing test, or a test still waiting for the developer's decision, already checks "
        'this attack. Don\'t duplicate it: call no_test_needed with reason "already_covered" and name that test.\n'
        "- Not testable: the weakness can't be shown by using the task's interface in a pytest test (for example a "
        'hardcoded secret or a missing log line). Call no_test_needed with reason "not_testable" and say what the '
        "developer should check instead. Never propose a test that passes whether or not the fix is in place.\n"
        f"- Otherwise propose a regression test for {target} that fails while the vulnerability is present and passes "
        "once the fix is in place. If an existing test file already tests the same kind of attack, extend that file, "
        "preserving all its tests, imports and fixtures; otherwise use a new tests/test_security_<topic>.py. Submit "
        "the complete file contents for approval; never write files directly.\n\n"
        f"Task interface:\n{ctx.task_description}\n\n"
        f"Existing Python test files:\n{code_listing(tests) or '(none yet)'}"
    )
    if waiting:
        text += f"\n\nTests still waiting for the developer's decision:\n{code_listing(waiting)}"
    return text


def _result(db: Session, message: Message) -> dict:
    ids = message.data.get("approval_ids", [])
    approvals = list(db.scalars(select(Approval).where(Approval.id.in_(ids)))) if ids else []
    return {"messages": [message], "approvals": approvals, "next": None}


def run(db: Session, ws: Workspace, message_id: int) -> dict:
    """One durable follow-up per request: Reviewer and Verifier can run in separate sessions concurrently."""
    job = db.get(Message, message_id)
    if ws.mode != "team" or job is None or job.workspace_id != ws.id or job.data.get("kind") != KIND:
        raise NotFoundError("Follow-up not found")
    if job.data["status"] == "complete":
        return _result(db, job)

    now = time.time()
    token = uuid4().hex
    actor = job.data["agent"]
    other = aliased(Message)
    busy = exists(select(other.id).where(
        other.workspace_id == ws.id,
        other.id != job.id,
        other.data["kind"].as_string() == KIND,
        other.data["agent"].as_string() == actor,
        other.data["status"].as_string() == "running",
        other.data["started_at"].as_float() > now - LEASE_SECONDS,
    ))
    # Atomic claim prevents duplicate model calls and serializes the same specialist's queued findings.
    claimed = db.execute(update(Message).where(
        Message.id == job.id,
        (Message.data["status"].as_string().in_(["queued", "failed"]))
        | ((Message.data["status"].as_string() == "running")
           & (Message.data["started_at"].as_float() <= now - LEASE_SECONDS)),
        ~busy,
    ).values(data={**job.data, "status": "running", "started_at": now, "run_token": token}))
    db.commit()
    db.refresh(job)
    if claimed.rowcount != 1:
        return _result(db, job)

    started = time.monotonic()
    try:
        ctx = build_context(ws)
        ctx.earlier = earlier_proposals(db, ws)
        target = job.data["vulnerability_id"]
        ctx.target_vulnerability = target
        vulnerability = next((v for v in ctx.state.vulnerabilities if v.id == target), None)
        if vulnerability is None or vulnerability.status != "open":
            reply = f"{target} is no longer an open vulnerability; no new proposals are needed."
        elif actor == "verifier" and vulnerability.severity == "Low":
            # A fixed rule, so no model call: Low-severity findings get no automatic test.
            reply = f"No new security test for {target}: it is Low severity. Ask me in the chat if you want one anyway."
            ctx.no_test = ("low_severity", reply)
        else:
            if actor == "reviewer":
                text = (
                    f"The developer approved vulnerability {target}.\n\n{_vulnerability_list(ctx.state)}\n\n"
                    f"Suggest the fix for {target} now: code, file, location and why. The human writes it; "
                    "do not edit any files or propose new vulnerabilities. The Test/Verifier considers a test once "
                    "the developer approves your fix.\n\n"
                    f"Current project files:\n{code_listing(ctx.files)}"
                )
            else:
                fixes = [m for m in ctx.state.mitigations if m.vulnerability_id == target]
                text = _test_request(ctx, target, fixes)
            text += f"\n\n{_not_approved(ctx, actor)}"
            with model_call(db, ws, actor):
                reply = runtime.run_agent(
                    team_prompt(actor),
                    make_tools(ctx, actor, only=FIX_TOOLS if actor == "reviewer" else None),
                    [HumanMessage(text)],
                )

        # Reclaiming an expired run invalidates its token. Save proposals and reply in one transaction.
        owned = db.execute(update(Message).where(
            Message.id == job.id, Message.data["run_token"].as_string() == token,
        ).values(content=reply)).rowcount
        if owned != 1:
            db.rollback()
            db.refresh(job)
            return _result(db, job)
        db.refresh(ws)
        if ws.done_at is not None:
            job.content = "This part finished before the follow-up completed; no new proposals were saved."
            ctx.proposals.clear()
            ctx.no_test = None
        saved = chat.save_proposals(db, ws, ctx.proposals, commit=False)
        job.role = "agent"
        job.data = {**job.data, "status": "complete", "approval_ids": [a.id for a in saved]}
        log_event(db, ws.participant_code, "agent_replied", actor=actor, mode=ws.mode, detail={
            "seconds": round(time.monotonic() - started, 1), "proposals": len(saved), "vulnerability_id": target,
        })
        if ctx.no_test:
            reason, why = ctx.no_test
            log_event(db, ws.participant_code, "test_skipped", actor=actor, mode=ws.mode, detail={
                "vulnerability_id": target, "reason": reason, "why": why,
            })
        db.commit()
    except Exception:
        db.rollback()
        db.refresh(job)
        db.execute(update(Message).where(
            Message.id == job.id, Message.data["run_token"].as_string() == token,
        ).values(data={**job.data, "status": "failed"}))
        db.commit()
        raise
    db.refresh(job)
    return _result(db, job)
