import json
import logging
from typing import Any

from pydantic import BaseModel
from sqlalchemy.orm import Session

from models import Workspace
from schemas.security_state import (
    Actor,
    Assumption,
    AssumptionCreate,
    Category,
    HumanCategory,
    Mitigation,
    MitigationCreate,
    Risk,
    RiskCreate,
    SecurityState,
    SecurityTest,
    StateItem,
    Vulnerability,
    VulnerabilityCreate,
)
from services.errors import ConflictError, NotFoundError
from services.events import log_event

ID_PREFIX: dict[str, str] = {
    "assumptions": "A",
    "risks": "R",
    "vulnerabilities": "V",
    "mitigations": "M",
    "tests": "T",
}
ITEM_CLASS: dict[str, type[StateItem]] = {
    "assumptions": Assumption,
    "risks": Risk,
    "vulnerabilities": Vulnerability,
    "mitigations": Mitigation,
    "tests": SecurityTest,
}
CREATE_SCHEMA: dict[str, type[BaseModel]] = {
    "assumptions": AssumptionCreate,
    "risks": RiskCreate,
    "vulnerabilities": VulnerabilityCreate,
    "mitigations": MitigationCreate,
}
# The fields that link one item to another: (category, field) -> the category of the item it points at.
LINKS: dict[tuple[str, str], Category] = {
    ("mitigations", "vulnerability_id"): "vulnerabilities",
}
PROTECTED_FIELDS = {"id", "source", "approval_id", "timestamp"}

# Every change is printed in the backend console (main.py sets up the output); the app doesn't show it.
log = logging.getLogger("security_state")


def require_team(ws: Workspace) -> None:
    if ws.mode != "team":
        raise ConflictError("The shared security state is only used in team mode")


def load(ws: Workspace) -> SecurityState:
    require_team(ws)
    return SecurityState.model_validate(ws.security_state)


def _short(value: Any) -> str:
    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= 80 else text[:77] + "..."


def _changes(old: dict, new: dict) -> list[str]:
    # One line per item added (+), changed (~) or deleted (-).
    lines = []
    for category in ITEM_CLASS:
        before = {item["id"]: item for item in old.get(category, [])}
        after = {item["id"]: item for item in new.get(category, [])}
        for item_id, item in after.items():
            if item_id not in before:
                proposal = f", proposal #{item['approval_id']}" if item.get("approval_id") else ""
                lines.append(f"  + {item_id} added to {category} (by {item['source']}{proposal})")
                continue
            changed = [
                f"{key}: {_short(before[item_id].get(key))} -> {_short(value)}"
                for key, value in item.items()
                if before[item_id].get(key) != value
            ]
            if changed:
                lines.append(f"  ~ {item_id} " + ", ".join(changed))
        lines += [f"  - {item_id} deleted from {category}" for item_id in before if item_id not in after]
    return lines


def save(ws: Workspace, state: SecurityState) -> None:
    # Assigning a new value is what tells SQLAlchemy the JSON changed. The caller commits.
    new = state.model_dump(mode="json")
    changes = _changes(ws.security_state or {}, new)
    ws.security_state = new
    if changes:
        log.info(
            "Security state of %s (task %s) changed:\n%s\n%s",
            ws.participant_code,
            ws.task_id,
            "\n".join(changes),
            json.dumps(new, indent=2, ensure_ascii=False),
        )


# ---- working on a state object (no database) -------------------------------------------------


def find(state: SecurityState, category: Category, item_id: str) -> StateItem:
    for item in getattr(state, category):
        if item.id == item_id:
            return item
    raise NotFoundError(f"{item_id} not found in {category}")


def has(state: SecurityState, category: Category, item_id: str | None) -> bool:
    return any(item.id == item_id for item in getattr(state, category))


def _require(state: SecurityState, category: Category, item_id: str) -> None:
    if not has(state, category, item_id):
        raise NotFoundError(f"{item_id} is not in {category}; change or remove the link")


def _check_links(state: SecurityState, category: str, item: BaseModel) -> None:
    if category == "mitigations" and not getattr(item, "vulnerability_id", None):
        raise ConflictError("A mitigation must be linked to an existing vulnerability")
    for (linking, field), target in LINKS.items():
        target_id = getattr(item, field, None)
        if linking == category and target_id is not None:
            _require(state, target, target_id)


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
    linked = []
    for (linking, field), target in LINKS.items():
        if target == category:
            linked += [other.id for other in getattr(state, linking) if getattr(other, field) == item_id]
    if linked:
        raise ConflictError(f"{item_id} is linked to {', '.join(linked)}; delete or change those first")
    if category == "vulnerabilities":
        for test in state.tests:  # tests can't be edited by hand, so they just stop listing it
            if item_id in test.vulnerability_ids:
                test.vulnerability_ids.remove(item_id)
    getattr(state, category).remove(item)


def resolve(state: SecurityState, item_id: str) -> StateItem:
    if item_id.startswith("V"):
        return edit_item(state, "vulnerabilities", item_id, {"status": "fixed"})
    return edit_item(state, "risks", item_id, {"status": "mitigated"})


def link_test(state: SecurityState, path: str, vulnerability_ids: list[str], approval_id: int | None) -> SecurityTest:
    for vulnerability_id in vulnerability_ids:
        _require(state, "vulnerabilities", vulnerability_id)
    for existing in state.tests:
        if existing.path == path:  # a re-proposed test file replaces the earlier one, and its old result
            existing.vulnerability_ids = vulnerability_ids
            existing.approval_id = approval_id
            existing.passed = existing.result = None
            return existing
    test = SecurityTest(
        id=_new_id(state, "tests"),
        source="verifier",
        approval_id=approval_id,
        path=path,
        vulnerability_ids=vulnerability_ids,
    )
    state.tests.append(test)
    return test


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
