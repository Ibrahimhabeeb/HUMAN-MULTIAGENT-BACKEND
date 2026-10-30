from sqlalchemy import select, update
from sqlalchemy.orm import Session

from models import Message, Workspace
from services import state_service

KIND = "vulnerability_follow_up"


def queue_missing(db: Session, ws: Workspace) -> None:
    """Persist one Code Reviewer fix follow-up per accepted finding without a mitigation, including older sessions."""
    if ws.mode != "team" or ws.done_at is not None:
        return
    # Serialize reconciliation with approvals and other tabs, so refresh never queues duplicate work.
    db.execute(update(Workspace).where(Workspace.id == ws.id).values(id=ws.id))
    db.refresh(ws)
    if ws.done_at is not None:
        return
    state = state_service.load(ws)
    queued = {
        m.data.get("vulnerability_id")
        for m in db.scalars(select(Message).where(Message.workspace_id == ws.id))
        if m.data.get("kind") == KIND and m.data.get("agent") == "reviewer"
    }
    fixed = {m.vulnerability_id for m in state.mitigations}
    for vulnerability in state.vulnerabilities:
        if vulnerability.status != "accepted" or vulnerability.id in fixed | queued:
            continue
        db.add(
            Message(
                participant_code=ws.participant_code,
                workspace_id=ws.id,
                mode=ws.mode,
                thread="team",
                role="system",
                content=f"Writing the fix for {vulnerability.id}.",
                data={
                    "kind": KIND,
                    "agent": "reviewer",
                    "vulnerability_id": vulnerability.id,
                    "approval_id": vulnerability.approval_id,
                    "status": "queued",
                },
            )
        )
    db.flush()
