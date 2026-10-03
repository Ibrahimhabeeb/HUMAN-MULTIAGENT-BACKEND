from collections.abc import Generator
from contextlib import contextmanager
from typing import Literal

from sqlalchemy.orm import Session

from schemas.security_state import (
    Actor,
    Evidence,
    EvidenceCreate,
    Mitigation,
    MitigationCreate,
    MitigationStatus,
    Risk,
    RiskCreate,
    RiskStatus,
    SecurityState,
    Severity,
    StateItem,
)
from services.errors import NotFoundError, StateRuleError
from services.projects import get_project, open_session

Category = Literal["requirements", "assumptions", "risks", "mitigations", "evidence", "questions"]

ID_PREFIX: dict[Category, str] = {
    "requirements": "REQ",
    "assumptions": "A",
    "risks": "R",
    "mitigations": "M",
    "evidence": "E",
    "questions": "Q",
}


def get_state(db: Session, project_id: str) -> SecurityState:
    return SecurityState.model_validate(get_project(db, project_id).security_state)


@contextmanager
def _edit(db: Session, project_id: str, session_id: str) -> Generator[SecurityState]:
    # Load the project's state, let the caller change it, then save it.
    # If the caller raises (e.g. a broken rule), nothing is saved.
    project = get_project(db, project_id)
    open_session(db, project_id, session_id)
    state = SecurityState.model_validate(project.security_state)
    yield state
    project.security_state = state.model_dump(mode="json")
    db.commit()


# ---- reading --------------------------------------------------------------------------


def _find(state: SecurityState, category: Category, item_id: str) -> StateItem:
    for item in getattr(state, category):
        if item.id == item_id:
            return item
    raise NotFoundError(f"{item_id} not found in {category}")


def _find_risk(state: SecurityState, risk_id: str) -> Risk:
    return _find(state, "risks", risk_id)  # type: ignore[return-value]


def _find_mitigation(state: SecurityState, mitigation_id: str) -> Mitigation:
    return _find(state, "mitigations", mitigation_id)  # type: ignore[return-value]


def get_risk(db: Session, project_id: str, risk_id: str) -> Risk:
    return _find_risk(get_state(db, project_id), risk_id)


def get_mitigation(db: Session, project_id: str, mitigation_id: str) -> Mitigation:
    return _find_mitigation(get_state(db, project_id), mitigation_id)


def list_risks(
    db: Session, project_id: str, status: RiskStatus | None = None, severity: Severity | None = None
) -> list[Risk]:
    return [
        r
        for r in get_state(db, project_id).risks
        if (status is None or r.status == status) and (severity is None or r.severity == severity)
    ]


def list_mitigations(
    db: Session, project_id: str, risk_id: str | None = None, status: MitigationStatus | None = None
) -> list[Mitigation]:
    state = get_state(db, project_id)
    if risk_id is not None:
        _find_risk(state, risk_id)
    return [
        m
        for m in state.mitigations
        if (risk_id is None or m.risk_id == risk_id) and (status is None or m.status == status)
    ]


# ---- adding items (called by agents with their own name as the source) ----------------


def _next_id(state: SecurityState, category: Category) -> str:
    return f"{ID_PREFIX[category]}{len(getattr(state, category)) + 1}"


def _initial_approval(source: Actor) -> bool | None:
    # Items from the human count as approved; items from agents wait for the human.
    return True if source == "human" else None


def add_risk(db: Session, project_id: str, session_id: str, data: RiskCreate, source: Actor) -> Risk:
    with _edit(db, project_id, session_id) as state:
        risk = Risk(
            id=_next_id(state, "risks"), source=source, human_approved=_initial_approval(source), **data.model_dump()
        )
        state.risks.append(risk)
    return risk


def add_mitigation(db: Session, project_id: str, session_id: str, data: MitigationCreate, source: Actor) -> Mitigation:
    with _edit(db, project_id, session_id) as state:
        risk = _find_risk(state, data.risk_id)
        if risk.human_approved is False:
            raise StateRuleError(f"{risk.id} was rejected, so it cannot have mitigations")
        mitigation = Mitigation(
            id=_next_id(state, "mitigations"),
            source=source,
            human_approved=_initial_approval(source),
            **data.model_dump(),
        )
        state.mitigations.append(mitigation)
    return mitigation


def add_evidence(db: Session, project_id: str, session_id: str, data: EvidenceCreate, source: Actor) -> Evidence:
    with _edit(db, project_id, session_id) as state:
        for risk_id in data.risk_ids:
            _find_risk(state, risk_id)
        evidence = Evidence(
            id=_next_id(state, "evidence"), source=source, human_approved=_initial_approval(source), **data.model_dump()
        )
        state.evidence.append(evidence)
    return evidence


# ---- the human's decisions -------------------------------------------------------------


def set_approval(
    db: Session, project_id: str, session_id: str, category: Category, item_id: str, approved: bool
) -> StateItem:
    with _edit(db, project_id, session_id) as state:
        item = _find(state, category, item_id)
        item.human_approved = approved
        if isinstance(item, Mitigation) and not approved:
            item.status = "rejected"
    return item


def _mitigations_for(state: SecurityState, risk_id: str) -> list[Mitigation]:
    return [m for m in state.mitigations if m.risk_id == risk_id and m.status != "rejected"]


def _has_passing_evidence(state: SecurityState, risk_id: str) -> bool:
    return any(e.passed and e.human_approved is not False and risk_id in e.risk_ids for e in state.evidence)


def set_risk_status(
    db: Session, project_id: str, session_id: str, risk_id: str, status: RiskStatus, rationale: str | None = None
) -> Risk:
    with _edit(db, project_id, session_id) as state:
        risk = _find_risk(state, risk_id)
        if risk.human_approved is False:
            raise StateRuleError(f"{risk_id} was rejected, so its status cannot change")

        if status == "mitigated":
            approved = [m for m in _mitigations_for(state, risk_id) if m.human_approved]
            if not approved:
                raise StateRuleError(f"{risk_id} needs an approved mitigation before it can be mitigated")
            for m in approved:
                if m.status == "proposed":
                    m.status = "implemented"

        elif status == "verified":
            if risk.status != "mitigated":
                raise StateRuleError(f"{risk_id} must be mitigated before it can be verified")
            if not _has_passing_evidence(state, risk_id):
                raise StateRuleError(f"{risk_id} needs passing evidence before it can be verified")
            for m in _mitigations_for(state, risk_id):
                if m.status == "implemented":
                    m.status = "verified"

        elif status == "accepted":
            if not rationale:
                raise StateRuleError("Accepting a risk without fixing it needs a rationale")
            risk.rationale = rationale

        risk.status = status
    return risk
