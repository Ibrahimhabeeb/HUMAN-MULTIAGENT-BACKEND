from typing import Any

from pydantic import BaseModel
from sqlalchemy.orm import Session

from models import Workspace
from schemas.security_state import (
    Actor,
    Assumption,
    AssumptionCreate,
    Category,
    Evidence,
    Finding,
    FindingCreate,
    HumanCategory,
    LinkedTest,
    Mitigation,
    MitigationCreate,
    Risk,
    RiskCreate,
    SecurityState,
    StateItem,
)
from services.errors import ConflictError, NotFoundError
from services.events import log_event

ID_PREFIX: dict[str, str] = {
    "assumptions": "A",
    "risks": "R",
    "mitigations": "M",
    "findings": "F",
    "evidence": "E",
    "tests": "T",
}
ITEM_CLASS: dict[str, type[StateItem]] = {
    "assumptions": Assumption,
    "risks": Risk,
    "mitigations": Mitigation,
    "findings": Finding,
    "evidence": Evidence,
    "tests": LinkedTest,
}
CREATE_SCHEMA: dict[str, type[BaseModel]] = {
    "assumptions": AssumptionCreate,
    "risks": RiskCreate,
    "mitigations": MitigationCreate,
    "findings": FindingCreate,
}
PROTECTED_FIELDS = {"id", "source", "approval_id", "timestamp"}


def require_team(ws: Workspace) -> None:
    if ws.mode != "team":
        raise ConflictError("The shared security state is only used in team mode")


def load(ws: Workspace) -> SecurityState:
    require_team(ws)
    return SecurityState.model_validate(ws.security_state)


def save(ws: Workspace, state: SecurityState) -> None:
    # Assigning a new value is what tells SQLAlchemy the JSON changed. The caller commits.
    ws.security_state = state.model_dump(mode="json")


# ---- working on a state object (no database) -------------------------------------------------


def find(state: SecurityState, category: Category, item_id: str) -> StateItem:
    for item in getattr(state, category):
        if item.id == item_id:
            return item
    raise NotFoundError(f"{item_id} not found in {category}")


def _check_links(state: SecurityState, category: str, item: BaseModel) -> None:
    risk_id = getattr(item, "risk_id", None)
    if category in ("mitigations", "findings") and risk_id is not None:
        find(state, "risks", risk_id)


def _new_id(state: SecurityState, category: str) -> str:
    state.counters[category] = state.counters.get(category, 0) + 1
    return f"{ID_PREFIX[category]}{state.counters[category]}"


def add_item(
    state: SecurityState, category: Category, data: BaseModel, source: Actor, approval_id: int | None = None
) -> StateItem:
    _check_links(state, category, data)
    item = ITEM_CLASS[category](id=_new_id(state, category), source=source, approval_id=approval_id, **data.model_dump())
    getattr(state, category).append(item)
    return item


def edit_item(state: SecurityState, category: Category, item_id: str, changes: dict[str, Any]) -> StateItem:
    item = find(state, category, item_id)
    allowed = {k: v for k, v in changes.items() if k not in PROTECTED_FIELDS}
    updated = ITEM_CLASS[category].model_validate({**item.model_dump(), **allowed})
    _check_links(state, category, updated)
    items = getattr(state, category)
    items[items.index(item)] = updated
    return updated


def delete_item(state: SecurityState, category: Category, item_id: str) -> None:
    item = find(state, category, item_id)
    if category == "risks":
        linked = [m.id for m in state.mitigations if m.risk_id == item_id]
        linked += [f.id for f in state.findings if f.risk_id == item_id]
        if linked:
            raise ConflictError(f"{item_id} is linked to {', '.join(linked)}; delete or change those first")
    getattr(state, category).remove(item)


def resolve(state: SecurityState, item_id: str) -> StateItem:
    if item_id.startswith("F"):
        return edit_item(state, "findings", item_id, {"status": "fixed"})
    return edit_item(state, "risks", item_id, {"status": "mitigated"})


def link_test(state: SecurityState, path: str, risk_ids: list[str], approval_id: int | None) -> LinkedTest:
    for risk_id in risk_ids:
        find(state, "risks", risk_id)
    for existing in state.tests:
        if existing.path == path:  # a re-proposed test file replaces the earlier link
            existing.risk_ids = risk_ids
            existing.approval_id = approval_id
            return existing
    link = LinkedTest(id=_new_id(state, "tests"), source="verifier", approval_id=approval_id, path=path, risk_ids=risk_ids)
    state.tests.append(link)
    return link


def add_evidence(state: SecurityState, text: str, passed: bool, risk_ids: list[str]) -> Evidence:
    evidence = Evidence(id=_new_id(state, "evidence"), source="system", text=text, passed=passed, risk_ids=risk_ids)
    state.evidence.append(evidence)
    return evidence


# ---- the human edits the state directly (no approval: the human is the authority) -------------


def _commit_human_change(db: Session, ws: Workspace, state: SecurityState, type: str, detail: dict) -> None:
    save(ws, state)
    log_event(db, ws.participant_code, type, mode=ws.mode, detail=detail)
    db.commit()


def human_add(db: Session, ws: Workspace, category: HumanCategory, body: dict[str, Any]) -> StateItem:
    state = load(ws)
    item = add_item(state, category, CREATE_SCHEMA[category].model_validate(body), "human")
    _commit_human_change(db, ws, state, "state_item_added", {"category": category, "id": item.id})
    return item


def human_edit(db: Session, ws: Workspace, category: HumanCategory, item_id: str, changes: dict[str, Any]) -> StateItem:
    state = load(ws)
    item = edit_item(state, category, item_id, changes)
    detail = {"category": category, "id": item_id, "fields": sorted(set(changes) - PROTECTED_FIELDS)}
    _commit_human_change(db, ws, state, "state_item_edited", detail)
    return item


def human_delete(db: Session, ws: Workspace, category: HumanCategory, item_id: str) -> None:
    state = load(ws)
    delete_item(state, category, item_id)
    _commit_human_change(db, ws, state, "state_item_deleted", {"category": category, "id": item_id})
