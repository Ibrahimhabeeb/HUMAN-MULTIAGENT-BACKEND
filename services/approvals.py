from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from models import Approval, Workspace
from models.common import as_utc, utc_now
from schemas.approval import (
    PROPOSAL_SCHEMAS,
    SINGLE_MODE_ACTIONS,
    SUGGESTIONS,
    ActionType,
    Decision,
    ProposedTest,
)
from schemas.security_state import MitigationCreate
from services import followups, state_service, workspace
from services.errors import ConflictError, NotFoundError
from services.events import log_event

# Which state category each "propose_*" action adds to.
_ADDS_TO = {
    "propose_assumption": "assumptions",
    "propose_risk": "risks",
    "propose_vulnerability": "vulnerabilities",
}
_STATUS_FOR = {"approve": "approved", "reject": "rejected"}


def request_approval(
    db: Session, ws: Workspace, actor: str, action_type: ActionType, proposal: dict, *, commit: bool = True
) -> Approval:
    """Every agent tool call that would change something ends up here. It waits for the human's decision,
    except a suggested risk, which goes straight into the security state."""
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
    if action_type in SUGGESTIONS:
        _suggest(db, ws, approval)
    else:
        log_event(
            db,
            ws.participant_code,
            "approval_requested",
            actor=actor,
            mode=ws.mode,
            detail={"approval_id": approval.id, "proposer": actor, "action_type": action_type},
        )
    if commit:
        db.commit()
    return approval


def _suggest(db: Session, ws: Workspace, approval: Approval) -> None:
    approval.result = _apply(db, ws, approval, approval.proposal)
    approval.final_proposal = approval.proposal
    approval.status = "suggested"
    detail = {"category": "risks", "id": approval.result["item_id"], "approval_id": approval.id}
    log_event(db, ws.participant_code, "state_item_added", actor=approval.actor, mode=ws.mode, detail=detail)


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
    # In team mode an approved fix must point at the vulnerability it fixes.
    state = state_service.load(ws)
    mitigation = MitigationCreate(
        vulnerability_id=fix["vulnerability"].strip(),
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
        if test.base_content is not None and workspace.read_file(ws, test.path)["content"] != test.base_content:
            raise ConflictError(f"{test.path} has changed since this proposal. Reject it and request updated tests.")
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
        item = state_service.mark_implemented(state, final["item_id"])
    else:
        category = _ADDS_TO[action]
        data = state_service.CREATE_SCHEMA[category].model_validate(final)
        item = state_service.add_item(state, category, data, approval.actor, approval.id)
    state_service.save(ws, state)
    return {"item_id": item.id}


def _record_rejected_vulnerability(ws: Workspace, approval: Approval) -> dict:
    # Team mode keeps a rejected finding in the state as "rejected", so everyone can see it was dismissed.
    state = state_service.load(ws)
    data = state_service.CREATE_SCHEMA["vulnerabilities"].model_validate(approval.proposal)
    item = state_service.add_item(state, "vulnerabilities", data, approval.actor, approval.id)
    item.status = "rejected"
    state_service.save(ws, state)
    return {"item_id": item.id}


def decide(db: Session, ws: Workspace, approval_id: int, decision: Decision) -> Approval:
    # Approve or reject only: a proposal is never edited. The human changes approved items themselves.
    approval = get_approval(db, ws, approval_id)
    if approval.status == "suggested":
        raise ConflictError("A suggested risk is already in the security state; there is nothing to approve")
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
        db.refresh(ws)  # another approval may have changed the shared state while this request waited for its claim
        if ws.mode == "team":
            state_service.lock(ws)
        if final is not None:
            approval.result = _apply(db, ws, approval, final)
        elif approval.action_type == "propose_vulnerability" and ws.mode == "team":
            approval.result = _record_rejected_vulnerability(ws, approval)
        approval.status = _STATUS_FOR[decision]
        approval.final_proposal = final
        approval.decided_at = utc_now()
        if decision == "approve" and approval.action_type == "propose_vulnerability":
            followups.queue_missing(db, ws)  # an accepted finding starts the Code Reviewer's fix
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
