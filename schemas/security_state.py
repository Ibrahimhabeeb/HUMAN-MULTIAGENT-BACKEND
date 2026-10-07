from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

Actor = Literal["human", "system", "assistant", "facilitator", "planner", "threat_modeller", "reviewer", "verifier"]
Severity = Literal["Low", "Medium", "High", "Critical"]
RiskStatus = Literal["open", "mitigated", "verified", "accepted"]
MitigationStatus = Literal["planned", "implemented"]
FindingStatus = Literal["open", "fixed"]

Category = Literal["assumptions", "risks", "mitigations", "findings", "evidence", "tests"]
HumanCategory = Literal["assumptions", "risks", "mitigations", "findings"]  # the ones the human edits directly


def utc_now() -> datetime:
    return datetime.now(UTC)


# ---- what can be created (by the human directly, or by an approved agent proposal) -----------


class AssumptionCreate(BaseModel):
    text: str = Field(min_length=3, max_length=1000)


class RiskCreate(BaseModel):
    description: str = Field(min_length=3, max_length=1000)
    severity: Severity
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d+$")
    owasp: str | None = Field(default=None, max_length=100)
    stride: str | None = Field(default=None, max_length=50)


class MitigationCreate(BaseModel):
    risk_id: str
    description: str = Field(min_length=3, max_length=1000)


class FindingCreate(BaseModel):
    description: str = Field(min_length=3, max_length=1000)
    severity: Severity
    file: str | None = Field(default=None, max_length=300)
    line: int | None = Field(default=None, ge=1)
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d+$")
    risk_id: str | None = None  # the risk this finding is an instance of, if any


# ---- the items stored in the state ------------------------------------------------------------


class StateItem(BaseModel):
    id: str
    source: Actor  # who proposed it ("human" if added directly)
    approval_id: int | None = None  # the approval that put it here, if it came from an agent
    timestamp: datetime = Field(default_factory=utc_now)


class Assumption(StateItem, AssumptionCreate):
    pass


class Risk(StateItem, RiskCreate):
    status: RiskStatus = "open"
    rationale: str | None = Field(default=None, max_length=1000)  # why the human accepted the risk instead of fixing it


class Mitigation(StateItem, MitigationCreate):
    status: MitigationStatus = "planned"


class Finding(StateItem, FindingCreate):
    status: FindingStatus = "open"


class Evidence(StateItem):
    text: str
    passed: bool
    risk_ids: list[str] = []


class LinkedTest(StateItem):
    # An approved test file and the risks it was written for, so test results can become evidence.
    path: str
    risk_ids: list[str] = []


class SecurityState(BaseModel):
    counters: dict[str, int] = {}  # last id number used per category, so ids are never reused after a delete
    assumptions: list[Assumption] = []
    risks: list[Risk] = []
    mitigations: list[Mitigation] = []
    findings: list[Finding] = []
    evidence: list[Evidence] = []
    tests: list[LinkedTest] = []
