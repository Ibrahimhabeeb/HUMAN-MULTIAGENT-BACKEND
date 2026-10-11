from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from api.errors import run
from db import get_db
from schemas.approval import ApprovalOut, ApprovalStatus, DecisionRequest
from services import approvals, study

# Proposals waiting for (or already given) the human's decision, for the current part.
router = APIRouter(prefix="/approvals", tags=["approvals"])

Db = Annotated[Session, Depends(get_db)]


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
