import time
from uuid import uuid4

from langchain_core.messages import HumanMessage
from sqlalchemy import exists, select, update
from sqlalchemy.orm import Session, aliased

from agents import runtime
from agents.context import build_context, code_listing, earlier_proposals
from agents.roles import team_prompt
from agents.team import _not_approved, _vulnerability_list
from agents.tools import make_tools
from agents.turns import model_call
from models import Approval, Message, Workspace
from services import chat
from services.errors import NotFoundError
from services.events import log_event
from services.followups import KIND

LEASE_SECONDS = 600
FIX_TOOLS = {"list_files", "read_file", "read_task_description", "get_security_state", "suggest_fix"}


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
        else:
            text = f"The developer approved vulnerability {target}.\n\n{_vulnerability_list(ctx.state)}\n\n"
            if actor == "reviewer":
                text += (
                    f"Suggest the fix for {target} now: code, file, location and why. The human writes it; "
                    "do not edit any files or propose new vulnerabilities. The Verifier is preparing tests separately.\n\n"
                    f"Current project files:\n{code_listing(ctx.files)}"
                )
            else:
                tests = {p: c for p, c in ctx.files.items() if p.startswith("tests/") and p.endswith(".py")}
                text += (
                    f"Propose security regression tests for {target} now. Inspect and extend a suitable existing "
                    "test file, preserving all existing tests, imports and fixtures. Submit the complete file "
                    "contents for approval; never write files directly. If no file is suitable, use a new "
                    "tests/test_security_<topic>.py. The Reviewer is preparing the fix separately.\n\n"
                    f"Task interface:\n{ctx.task_description}\n\n"
                    f"Existing Python test files:\n{code_listing(tests) or '(none yet)'}"
                )
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
        saved = chat.save_proposals(db, ws, ctx.proposals, commit=False)
        job.role = "agent"
        job.data = {**job.data, "status": "complete", "approval_ids": [a.id for a in saved]}
        log_event(db, ws.participant_code, "agent_replied", actor=actor, mode=ws.mode, detail={
            "seconds": round(time.monotonic() - started, 1), "proposals": len(saved), "vulnerability_id": target,
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
