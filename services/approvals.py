from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from models import Approval, Workspace
from models.common import as_utc, utc_now
from schemas.approval import (
    PROPOSAL_SCHEMAS,
    SINGLE_MODE_ACTIONS,
    ActionType,
    Decision,
    ProposedTest,
)
from schemas.security_state import MitigationCreate
from services import state_service, workspace
from services.errors import ConflictError, NotFoundError
from services.events import log_event

# Which state category each "propose_*" action adds to.
_ADDS_TO = {
    "propose_assumption": "assumptions",
    "propose_risk": "risks",
    "propose_vulnerability": "vulnerabilities",
}
_STATUS_FOR = {"approve": "approved", "reject": "rejected"}


def request_approval(db: Session, ws: Workspace, actor: str, action_type: ActionType, proposal: dict) -> Approval:
    """Every agent tool call that would change something ends up here instead of changing it."""
    if ws.mode == "single" and action_type not in SINGLE_MODE_ACTIONS:
        raise ConflictError(f"{action_type} is not available in single mode")
    data = PROPOSAL_SCHEMAS[action_type].model_validate(proposal)
    approval = Approval(
        participant_code=ws.participant_code,
        workspace_id=ws.id,
        mode=ws.mode,
        actor=actor,
        action_type=action_type,
        proposal=data.model_dump(mode="json"),
    )
    db.add(approval)
    db.flush()
    log_event(
        db,
        ws.participant_code,
        "approval_requested",
        actor=actor,
        mode=ws.mode,
        detail={"approval_id": approval.id, "proposer": actor, "action_type": action_type},
    )
    db.commit()
    return approval


def list_approvals(db: Session, ws: Workspace, status: str | None = None) -> list[Approval]:
    query = select(Approval).where(Approval.workspace_id == ws.id).order_by(Approval.id)
    if status is not None:
        query = query.where(Approval.status == status)
    return list(db.scalars(query))


def get_approval(db: Session, ws: Workspace, approval_id: int) -> Approval:
    approval = db.get(Approval, approval_id)
    if approval is None or approval.workspace_id != ws.id:
        raise NotFoundError(f"Approval {approval_id} not found")
    return approval


def _add_mitigation(ws: Workspace, approval: Approval, fix: dict[str, Any]) -> dict:
    # In team mode an approved fix becomes a mitigation, linked to the vulnerability it fixes if that is in the state.
    state = state_service.load(ws)
    fixes = fix["vulnerability"]
    mitigation = MitigationCreate(
        vulnerability_id=fixes if state_service.has(state, "vulnerabilities", fixes) else None,
        description=fix["why"],
        file=fix["file"],
        location=fix["location"],
        code=fix["code"],
    )
    item = state_service.add_item(state, "mitigations", mitigation, approval.actor, approval.id)
    state_service.save(ws, state)
    return {"item_id": item.id}


def _apply(db: Session, ws: Workspace, approval: Approval, final: dict[str, Any]) -> dict | None:
    # Makes the approved change. Nothing here commits; decide() commits once at the end.
    action = approval.action_type
    if action == "suggest_fix":
        # The human types the fix themselves; nothing is written into the code.
        return _add_mitigation(ws, approval, final) if ws.mode == "team" else None

    if action == "propose_test":
        test = ProposedTest.model_validate(final)
        if ws.mode == "team":
            state = state_service.load(ws)
            state_service.link_test(state, test.path, test.vulnerability_ids, approval.id)
            state_service.save(ws, state)
        workspace.write_text(ws, test.path, test.content)
        log_event(
            db,
            ws.participant_code,
            "file_created",
            actor="system",
            mode=ws.mode,
            detail={"path": test.path, "chars": len(test.content), "approval_id": approval.id},
        )
        return {"path": test.path}

    state = state_service.load(ws)
    if action == "mark_resolved":
        item = state_service.resolve(state, final["item_id"])
    else:
        category = _ADDS_TO[action]
        data = state_service.CREATE_SCHEMA[category].model_validate(final)
        item = state_service.add_item(state, category, data, approval.actor, approval.id)
    state_service.save(ws, state)
    return {"item_id": item.id}


def decide(db: Session, ws: Workspace, approval_id: int, decision: Decision) -> Approval:
    # Approve or reject only: a proposal is never edited. The human changes approved items themselves.
    approval = get_approval(db, ws, approval_id)
    if approval.status != "pending":
        raise ConflictError(f"Approval {approval_id} has already been decided")
    final: dict[str, Any] | None = approval.proposal if decision == "approve" else None

    # Claim the approval atomically, so two clicks (or two requests) can never both apply it.
    claimed = db.execute(
        update(Approval).where(Approval.id == approval_id, Approval.status == "pending").values(status="deciding")
    ).rowcount
    if claimed != 1:
        db.rollback()
        raise ConflictError(f"Approval {approval_id} has already been decided")

    try:
        approval.result = _apply(db, ws, approval, final) if final is not None else None
        approval.status = _STATUS_FOR[decision]
        approval.final_proposal = final
        approval.decided_at = utc_now()
        log_event(
            db,
            ws.participant_code,
            f"action_{approval.status}",
            mode=ws.mode,
            detail={
                "approval_id": approval.id,
                "proposer": approval.actor,
                "action_type": approval.action_type,
                "decision_seconds": round((approval.decided_at - as_utc(approval.requested_at)).total_seconds(), 1),
            },
        )
        db.commit()
    except Exception:
        db.rollback()  # nothing applied, and the approval goes back to pending
        raise
    return approval
