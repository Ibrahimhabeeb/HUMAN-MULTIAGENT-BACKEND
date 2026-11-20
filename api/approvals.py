from fastapi import APIRouter

from api.dependencies import Db
from api.errors import run
from schemas.approval import (
    ApprovalOut,
    ApprovalStatus,
    DecisionRequest,
    FixChoiceRequest,
)
from services import approvals, study

# Proposals waiting for (or already given) the human's decision, for the current part.
router = APIRouter(prefix="/approvals", tags=["approvals"])



@router.get("")
def list_approvals(db: Db, status: ApprovalStatus | None = None) -> list[ApprovalOut]:
    rows = run(lambda: approvals.list_approvals(db, study.current_workspace(db), status))
    return [ApprovalOut.model_validate(a) for a in rows]


@router.get("/{approval_id}")
def get_approval(db: Db, approval_id: int) -> ApprovalOut:
    return ApprovalOut.model_validate(run(lambda: approvals.get_approval(db, study.current_workspace(db), approval_id)))


@router.post("/{approval_id}/decide")
def decide(db: Db, approval_id: int, body: DecisionRequest) -> ApprovalOut:
    decided = run(
        lambda: approvals.decide(db, study.editable_workspace(db), approval_id, body.decision)
    )
    return ApprovalOut.model_validate(decided)


@router.post("/{approval_id}/fix-choice")
def choose_fix(db: Db, approval_id: int, body: FixChoiceRequest) -> ApprovalOut:
    chosen = run(lambda: approvals.choose_fix(db, study.editable_workspace(db), approval_id, body.choice))
    return ApprovalOut.model_validate(chosen)


@router.post("/{approval_id}/undo")
def undo_fix(db: Db, approval_id: int) -> ApprovalOut:
    undone = run(lambda: approvals.undo_fix(db, study.editable_workspace(db), approval_id))
    return ApprovalOut.model_validate(undone)
