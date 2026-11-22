import time
from uuid import uuid4

from langchain_core.messages import AIMessage, HumanMessage
from sqlalchemy import exists, select, update
from sqlalchemy.orm import Session, aliased

from agents import runtime
from agents.context import build_context, code_listing, earlier_proposals
from agents.review_contracts import expected_duplicate_error
from agents.roles import team_prompt
from agents.team import _not_approved, _vulnerability_list
from agents.tools import make_tools
from agents.turns import model_call
from llm import ModelCallError, ModelNotConfiguredError
from models import Approval, Message, Workspace
from services import chat
from services.errors import ConflictError, NotFoundError
from services.events import log_event
from services.followups import KIND

LEASE_SECONDS = 600
# Only a reviewer-owned fix can change the code. The frontend locks the editor while it runs.
FIX_TOOLS = ["list_files", "read_file", "read_task_description", "get_security_state", "write_fix_lines", "write_fix", "explain_no_fix"]
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
    ).values(data={**job.data, "status": "running", "started_at": now, "run_token": token, "error": None,
                   "reviewer_reply": None, "fix_outcome": None}))
    db.commit()
    db.refresh(job)
    if claimed.rowcount != 1:
        return _result(db, job)

    started = time.monotonic()
    reply = ""
    fix_outcome = None
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
        elif problem := expected_duplicate_error(ctx.files, vulnerability.model_dump()):
            reply = (f"No code change was made for {target}.\n\n{problem}\n\n"
                     "Please reconsider this finding in the shared security state. Its status has not been changed automatically.")
            fix_outcome = "no_change"
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
                f"The developer accepted vulnerability {target} and explicitly chose the Code Reviewer to implement "
                "the fix. That separate authorisation is already recorded. Do not ask for confirmation again or "
                "ask the developer to call tools for you.\n\n"
                f"{_vulnerability_list(ctx.state)}\n\n"
                f"Write the fix for {target} now, preferably with write_fix_lines using the numbered current file. "
                "The server will copy the original lines; do not reconstruct a find string from memory. "
                "It goes straight into the developer's code, so change "
                "only what the fix needs. Preserve existing imports, classes and function interfaces; the tool rejects "
                "new undefined names or syntax errors. Then say in one or two sentences what you changed "
                "and why, without repeating "
                "the code. If the finding is unsupported or already prevented by existing controls, use "
                "explain_no_fix with the file and concrete evidence instead. An accepted finding may still be "
                "mistaken; an expected exception is not by itself a security vulnerability. Do not change code "
                "just to produce an edit. Do not propose new vulnerabilities.\n\n"
                f"Current project files:\n{code_listing(ctx.files)}"
                f"\n\n{_not_approved(ctx, actor)}"
            )
            messages = [HumanMessage(text)]
            tools = make_tools(ctx, actor, names=FIX_TOOLS)
            for attempt in range(2):
                with model_call(db, ws, actor):
                    response = runtime.run_agent(team_prompt(actor), tools, messages)
                if response.strip():
                    reply = response
                if ctx.proposals or ctx.fix_no_change:
                    break
                if attempt == 0:
                    if response.strip():
                        messages.append(AIMessage(response))
                    rejection = f" Last tool rejection: {ctx.rejected_fixes[-1]}" if ctx.rejected_fixes else ""
                    messages.append(HumanMessage(
                        "No valid edit or no-change explanation was recorded. Implementation is already authorised; "
                        "do not ask for confirmation. Use write_fix_lines with current file line numbers to submit the "
                        "required edit, or explain_no_fix if no security fix is justified, citing existing code "
                        f"and task requirements. Do not claim an edit was applied without using the tool.{rejection}"
                    ))
            if ctx.fix_no_change and not ctx.proposals:
                reply = ctx.fix_no_change
                fix_outcome = "no_change"
            elif ctx.proposals:
                fix_outcome = "written"
            else:
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
        job.data = {**job.data, "status": "complete", "approval_ids": [a.id for a in saved],
                    "fix_outcome": fix_outcome if saved or fix_outcome == "no_change" else None}
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
                       "reviewer_reply": reply or None,
                       "error": str(error) if isinstance(error, (ConflictError, ModelCallError, ModelNotConfiguredError)) else None}))
        db.commit()
        raise
    db.refresh(job)
    return _result(db, job)
