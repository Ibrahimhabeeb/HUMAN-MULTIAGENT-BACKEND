from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

Actor = Literal["facilitator", "planner", "threat_modeller", "reviewer", "verifier", "human"]
Severity = Literal["Low", "Medium", "High", "Critical"]
RiskStatus = Literal["identified", "accepted", "mitigated", "verified", "unresolved"]
MitigationStatus = Literal["proposed", "implemented", "verified", "rejected"]
EvidenceKind = Literal["test", "static_analysis", "review", "manual"]


def utc_now() -> datetime:
    return datetime.now(UTC)


class StateItem(BaseModel):
    id: str
    source: Actor
    timestamp: datetime = Field(default_factory=utc_now)
    human_approved: bool | None = None  # None = awaiting the human's decision


class Requirement(StateItem):
    text: str


class Assumption(StateItem):
    text: str


class Question(StateItem):
    text: str
    answer: str | None = None


class Risk(StateItem):
    description: str
    severity: Severity
    status: RiskStatus = "identified"
    cwe: str | None = None
    owasp: str | None = None
    stride: str | None = None
    file: str | None = None
    line: int | None = None


class Mitigation(StateItem):
    risk_id: str
    description: str
    status: MitigationStatus = "proposed"


class Evidence(StateItem):
    text: str
    kind: EvidenceKind
    passed: bool
    risk_ids: list[str] = []


class SecurityState(BaseModel):
    feature: str = "User Login"
    requirements: list[Requirement] = []
    assumptions: list[Assumption] = []
    risks: list[Risk] = []
    mitigations: list[Mitigation] = []
    evidence: list[Evidence] = []
    questions: list[Question] = []


# Request body for adding a risk. id, timestamp and approval are set by the server.
class RiskCreate(BaseModel):
    description: str = Field(min_length=3, max_length=500)
    severity: Severity
    source: Actor = "human"
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d+$")
    owasp: str | None = None
    stride: str | None = None
    file: str | None = None
    line: int | None = Field(default=None, ge=1)
