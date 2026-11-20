import json
import logging
from typing import Any

from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.orm import Session, object_session

from models import (
    AssumptionRecord,
    MitigationRecord,
    RiskRecord,
    UnitTestRecord,
    VulnerabilityRecord,
    Workspace,
)
from models.common import as_utc
from schemas.runner import CaseResult
from schemas.security_state import (
    Actor,
    Assumption,
    AssumptionCreate,
    Category,
    HumanAddCategory,
    HumanCategory,
    Mitigation,
    MitigationCreate,
    Risk,
    RiskCreate,
    SecurityState,
    StateItem,
    UnitTest,
    UnitTestStatus,
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
    "tests": UnitTest,
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

# Each category's table, and the columns that hold an item's own fields (besides its id, source, approval and time).
# Vulnerabilities come before mitigations, which point at them.
RECORD: dict[str, type] = {
    "assumptions": AssumptionRecord,
    "risks": RiskRecord,
    "vulnerabilities": VulnerabilityRecord,
    "mitigations": MitigationRecord,
    "tests": UnitTestRecord,
}
FIELDS: dict[str, tuple[str, ...]] = {
    "assumptions": ("text",),
    "risks": ("description", "severity", "cwe", "owasp", "stride"),
    "vulnerabilities": ("description", "severity", "file", "line", "cwe", "status"),
    "mitigations": ("description", "file", "location", "code", "status"),
    "tests": ("file", "name", "status", "message"),
}

# Every change is printed in the backend console (main.py sets up the output); the app doesn't show it.
log = logging.getLogger("security_state")


def require_team(ws: Workspace) -> None:
    if ws.mode != "team":
        raise ConflictError("The shared security state is only used in team mode")


# ---- the state in the database: one row per item ---------------------------------------------


def lock(ws: Workspace) -> None:
    # Taken before changing the state, so two requests can't both read it and then both add, say, V3.
    object_session(ws).execute(update(Workspace).where(Workspace.id == ws.id).values(id=ws.id))


def _rows(db: Session, ws: Workspace, category: str) -> list:
    record = RECORD[category]
    return list(db.scalars(select(record).where(record.workspace_id == ws.id).order_by(record.id)))


def _read(ws: Workspace) -> SecurityState:
    db = object_session(ws)
    data: dict[str, Any] = {"counters": dict(ws.state_counters or {})}
    refs: dict[int, str] = {}  # vulnerability row id -> its ref, for the mitigations that point at them
    for category in RECORD:
        items = []
        for row in _rows(db, ws, category):
            item = {"id": row.ref, "source": row.source, "approval_id": row.approval_id, "timestamp": as_utc(row.created_at)}
            item |= {field: getattr(row, field) for field in FIELDS[category]}
            if category == "vulnerabilities":
                refs[row.id] = row.ref
            if category == "mitigations":
                item["vulnerability_id"] = refs.get(row.vulnerability_id)
            items.append(item)
        data[category] = items
    return SecurityState.model_validate(data)


def _write(ws: Workspace, state: SecurityState) -> None:
    # Adds, updates and deletes rows so the tables match the state. The caller commits.
    db = object_session(ws)
    ws.state_counters = dict(state.counters)
    stale = []
    vulnerability_ids: dict[str, int] = {}
    for category, record in RECORD.items():
        rows = {row.ref: row for row in _rows(db, ws, category)}
        kept = []
        for item in getattr(state, category):
            row = rows.pop(item.id, None)
            if row is None:
                row = record(
                    workspace_id=ws.id, ref=item.id, source=item.source, approval_id=item.approval_id, created_at=item.timestamp
                )
                db.add(row)
            for field in FIELDS[category]:
                setattr(row, field, getattr(item, field))
            if category == "mitigations":
                row.vulnerability_id = vulnerability_ids[item.vulnerability_id]
            kept.append(row)
        stale.extend(rows.values())
        if category == "vulnerabilities":
            db.flush()  # new vulnerabilities get their row ids before mitigations point at them
            vulnerability_ids = {row.ref: row.id for row in kept}
    for row in reversed(stale):  # mitigations go before the vulnerabilities they point at
        db.delete(row)
    db.flush()


def load(ws: Workspace) -> SecurityState:
    require_team(ws)
    return _read(ws)


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
    # The caller commits.
    require_team(ws)
    new = state.model_dump(mode="json")
    changes = _changes(_read(ws).model_dump(mode="json"), new)
    _write(ws, state)
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
    getattr(state, category).remove(item)


def mark_implemented(state: SecurityState, mitigation_id: str) -> StateItem:
    return edit_item(state, "mitigations", mitigation_id, {"status": "implemented"})


_STATUS_OF: dict[str, UnitTestStatus] = {"passed": "passed", "skipped": "open"}  # a run's outcome; others fail
_RANK: dict[UnitTestStatus, int] = {"open": 0, "passed": 1, "failed": 2}


def _outcomes(
    cases: list[CaseResult], functions: set[tuple[str, str]]
) -> tuple[dict[tuple[str, str], tuple[UnitTestStatus, str | None]], dict[str, str]]:
    # Each test function's outcome (any failing case fails it, e.g. one parametrized case), and the files whose
    # tests couldn't run at all, with why (e.g. an import error in the code they test).
    outcomes: dict[tuple[str, str], tuple[UnitTestStatus, str | None]] = {}
    broken: dict[str, str] = {}
    for case in cases:
        key = (case.file, case.name.split("[", 1)[0])
        if key not in functions:
            if case.outcome == "error":
                broken.setdefault(case.file, case.message or "The tests could not be collected")
            continue
        status = _STATUS_OF.get(case.outcome, "failed")
        if key not in outcomes or _RANK[status] > _RANK[outcomes[key][0]]:
            outcomes[key] = (status, case.message if status == "failed" else None)
    return outcomes, broken


def update_tests(
    state: SecurityState,
    functions: list[tuple[str, str]],
    unreadable: dict[str, str],
    cases: list[CaseResult] | None = None,
    failure: str | None = None,
    source: Actor = "human",
) -> None:
    """List every test function in tests/ as (file, name), with the outcome of the latest run replacing the one
    before. Without a run (cases is None) outcomes stay as they were: open for a new test. A test the run couldn't
    reach fails with the reason; a test file that can't be read keeps its tests from before. A new test gets
    `source`: "system" for the task's own tests when the part starts, "human" for ones the developer adds later."""
    existing = {(test.file, test.name): test for test in state.tests}
    outcomes, broken = _outcomes(cases or [], set(functions))
    tests = []
    for file, name in functions:
        test = existing.get((file, name)) or UnitTest(id=_new_id(state, "tests"), source=source, file=file, name=name)
        if cases is not None:
            reason = broken.get(file) or failure
            test.status, test.message = outcomes.get((file, name)) or (("failed", reason) if reason else ("open", None))
        tests.append(test)
    for (file, _), test in existing.items():
        if file in unreadable:
            if cases is not None:
                test.status, test.message = "failed", unreadable[file]
            tests.append(test)
    state.tests = tests


def record_tests(
    ws: Workspace,
    functions: list[tuple[str, str]],
    unreadable: dict[str, str],
    cases: list[CaseResult] | None = None,
    failure: str | None = None,
    source: Actor = "human",
) -> None:
    # Unit tests are kept in both modes: single mode stores them for the analysis without showing them.
    state = _read(ws)
    update_tests(state, functions, unreadable, cases=cases, failure=failure, source=source)
    if ws.mode == "team":
        save(ws, state)
    else:
        _write(ws, state)


# ---- the human edits the state directly (no approval: the human is the authority) -------------


def _commit_human_change(db: Session, ws: Workspace, state: SecurityState, type: str, detail: dict) -> None:
    save(ws, state)
    log_event(db, ws.participant_code, type, mode=ws.mode, detail=detail)
    db.commit()


def human_add(db: Session, ws: Workspace, category: HumanAddCategory, body: dict[str, Any]) -> StateItem:
    lock(ws)
    state = load(ws)
    item = add_item(state, category, CREATE_SCHEMA[category].model_validate(body), "human")
    _commit_human_change(db, ws, state, "state_item_added", {"category": category, "id": item.id})
    return item


def human_edit(db: Session, ws: Workspace, category: HumanCategory, item_id: str, changes: dict[str, Any]) -> StateItem:
    lock(ws)
    state = load(ws)
    item = edit_item(state, category, item_id, changes)
    detail = {"category": category, "id": item_id, "fields": sorted(set(changes) - PROTECTED_FIELDS)}
    _commit_human_change(db, ws, state, "state_item_edited", detail)
    return item


def human_delete(db: Session, ws: Workspace, category: HumanCategory, item_id: str) -> None:
    lock(ws)
    state = load(ws)
    delete_item(state, category, item_id)
    _commit_human_change(db, ws, state, "state_item_deleted", {"category": category, "id": item_id})
