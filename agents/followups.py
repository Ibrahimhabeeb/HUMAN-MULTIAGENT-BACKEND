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
from services.errors import ConflictError, NotFoundError
from services.events import log_event
from services.followups import KIND

LEASE_SECONDS = 600
# Only a reviewer-owned fix can change the code. The frontend locks the editor while it runs.
FIX_TOOLS = ["list_files", "read_file", "read_task_description", "get_security_state", "write_fix"]
GUIDANCE_TOOLS = ["list_files", "read_file", "read_task_description", "get_security_state"]


def _result(db: Session, message: Message) -> dict:
    ids = message.data.get("approval_ids", [])
    approvals = list(db.scalars(select(Approval).where(Approval.id.in_(ids)))) if ids else []
    return {"messages": [message], "approvals": approvals, "next": None}


def run(db: Session, ws: Workspace, message_id: int) -> dict:
    """One durable follow-up: write the fix or explain it, as the developer chose."""
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
    ).values(data={**job.data, "status": "running", "started_at": now, "run_token": token, "error": None}))
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
        hidden = actor != "reviewer"
        if hidden:
            # Older sessions also queued the Test/Verifier here. It no longer writes tests, so the job just ends.
            reply = "The Test/Verifier no longer writes tests."
        elif vulnerability is None or vulnerability.status != "accepted":
            reply = f"{target} is no longer an accepted vulnerability; no fix is needed."
        elif any(m.vulnerability_id == target for m in ctx.state.mitigations):
            reply = f"{target} already has a mitigation; no fix is needed."
        elif job.data.get("fix_choice") not in {"reviewer", "developer"}:
            reply = f"Choose who should write the fix for {target} before the Code Reviewer continues."
        elif job.data.get("fix_choice") == "developer":
            text = (
                f"The developer accepted vulnerability {target} and chose to write the fix themselves.\n\n"
                f"{_vulnerability_list(ctx.state)}\n\n"
                "Explain a concrete fix for this vulnerability in chat. Give the exact file path and location, "
                "a short Python code block they can copy or adapt, and why it addresses the weakness. "
                "Do not edit files, call write_fix, claim the fix is implemented, or propose another finding.\n\n"
                f"Current project files:\n{code_listing(ctx.files)}"
            )
            with model_call(db, ws, actor):
                reply = runtime.run_agent(team_prompt(actor), make_tools(ctx, actor, names=GUIDANCE_TOOLS), [HumanMessage(text)])
        else:
            text = (
                f"The developer accepted vulnerability {target}.\n\n{_vulnerability_list(ctx.state)}\n\n"
                f"Write the fix for {target} now with write_fix. It goes straight into the developer's code, so change "
                "only what the fix needs. Preserve existing imports, classes and function interfaces; the tool rejects "
                "new undefined names or syntax errors. Then say in one or two sentences what you changed "
                "and why, without repeating "
                "the code. Do not propose new vulnerabilities.\n\n"
                f"Current project files:\n{code_listing(ctx.files)}"
                f"\n\n{_not_approved(ctx, actor)}"
            )
            with model_call(db, ws, actor):
                reply = runtime.run_agent(team_prompt(actor), make_tools(ctx, actor, names=FIX_TOOLS), [HumanMessage(text)])
            if not ctx.proposals:
                detail = f" Last tool rejection: {ctx.rejected_fixes[-1]}" if ctx.rejected_fixes else ""
                raise ConflictError(f"The Code Reviewer didn't write a fix for {target}.{detail} Retry it, or fix it yourself.")

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
            job.content = "This part finished before the fix was ready, so it wasn't written into the code."
            ctx.proposals.clear()
        saved = chat.save_proposals(db, ws, ctx.proposals, commit=False)
        job.role = "agent"
        job.data = {**job.data, "status": "complete", "approval_ids": [a.id for a in saved]}
        if hidden:
            job.data = {**job.data, "hidden": True}
        else:
            log_event(db, ws.participant_code, "agent_replied", actor=actor, mode=ws.mode, detail={
                "seconds": round(time.monotonic() - started, 1), "proposals": len(saved), "vulnerability_id": target,
            })
        db.commit()
    except Exception as error:
        db.rollback()
        db.refresh(job)
        db.execute(update(Message).where(
            Message.id == job.id, Message.data["run_token"].as_string() == token,
        ).values(data={**job.data, "status": "failed",
                       "error": str(error) if isinstance(error, ConflictError) else None}))
        db.commit()
        raise
    db.refresh(job)
    return _result(db, job)
