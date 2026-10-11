from sqlalchemy import select, update
from sqlalchemy.orm import Session

from models import Approval, Message, Workspace
from services import state_service

KIND = "vulnerability_follow_up"


def queue_missing(db: Session, ws: Workspace) -> None:
    """Persist one fix/test follow-up per approved finding, including older sessions."""
    if ws.mode != "team" or ws.done_at is not None:
        return
    # Serialize reconciliation with approvals and other tabs, so refresh never queues duplicate work.
    db.execute(update(Workspace).where(Workspace.id == ws.id).values(id=ws.id))
    db.refresh(ws)
    if ws.done_at is not None:
        return
    state = state_service.load(ws)
    existing = {
        (m.data.get("vulnerability_id"), m.data.get("agent"))
        for m in db.scalars(select(Message).where(Message.workspace_id == ws.id))
        if m.data.get("kind") == KIND
    }
    pending = list(db.scalars(select(Approval).where(Approval.workspace_id == ws.id, Approval.status == "pending")))
    for vulnerability in state.vulnerabilities:
        if vulnerability.status != "open":
            continue
        fixed = any(m.vulnerability_id == vulnerability.id for m in state.mitigations)
        tested = any(vulnerability.id in t.vulnerability_ids for t in state.tests)
        for agent, covered, action, key in (
            ("reviewer", fixed, "suggest_fix", "vulnerability"),
            ("verifier", tested, "propose_test", "vulnerability_ids"),
        ):
            if covered or (vulnerability.id, agent) in existing:
                continue
            if any(
                a.action_type == action
                and (
                    a.proposal.get(key) == vulnerability.id if key == "vulnerability"
                    else vulnerability.id in (a.proposal.get(key) or [])
                )
                for a in pending
            ):
                continue
            db.add(
                Message(
                    participant_code=ws.participant_code,
                    workspace_id=ws.id,
                    mode=ws.mode,
                    thread="team",
                    role="system",
                    content=f"Preparing {'fix suggestions' if agent == 'reviewer' else 'security tests'} for {vulnerability.id}.",
                    data={
                        "kind": KIND,
                        "agent": agent,
                        "vulnerability_id": vulnerability.id,
                        "approval_id": vulnerability.approval_id,
                        "status": "queued",
                    },
                )
            )
    db.flush()
