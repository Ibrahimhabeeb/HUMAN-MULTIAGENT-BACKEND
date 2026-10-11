from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

Actor = Literal["human", "system", "assistant", "facilitator", "planner", "threat_modeller", "reviewer", "verifier"]
Severity = Literal["Low", "Medium", "High", "Critical"]
RiskStatus = Literal["open", "mitigated", "verified", "accepted"]
VulnerabilityStatus = Literal["open", "fixed"]
MitigationStatus = Literal["planned", "implemented"]

Category = Literal["assumptions", "risks", "vulnerabilities", "mitigations", "tests"]
HumanCategory = Literal["assumptions", "risks", "vulnerabilities", "mitigations"]  # the ones the human edits directly


def utc_now() -> datetime:
    return datetime.now(UTC)


# ---- what can be created (by the human directly, or by an approved agent proposal) -----------


class AssumptionCreate(BaseModel):
    text: str = Field(min_length=3, max_length=1000)


class RiskCreate(BaseModel):
    # What could go wrong, from the Threat Modeller.
    description: str = Field(min_length=3, max_length=1000)
    severity: Severity
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d+$")
    owasp: str | None = Field(default=None, max_length=100)
    stride: str | None = Field(default=None, max_length=50)


class VulnerabilityCreate(BaseModel):
    # A weakness the Code Reviewer found in the developer's code.
    description: str = Field(min_length=3, max_length=1000)
    severity: Severity
    file: str | None = Field(default=None, max_length=300)
    line: int | None = Field(default=None, ge=1)
    cwe: str | None = Field(default=None, pattern=r"^CWE-\d+$")


class MitigationCreate(BaseModel):
    # A fix the Code Reviewer suggested and the human approved: the code to write, where it goes, and why.
    vulnerability_id: str | None = None  # nullable for legacy data; new/edited items must link to a vulnerability
    description: str = Field(min_length=3, max_length=2000)
    file: str | None = Field(default=None, max_length=300)
    location: str | None = Field(default=None, max_length=300)
    code: str | None = Field(default=None, max_length=20_000)


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


class Vulnerability(StateItem, VulnerabilityCreate):
    status: VulnerabilityStatus = "open"


class Mitigation(StateItem, MitigationCreate):
    status: MitigationStatus = "planned"


class SecurityTest(StateItem):
    # An approved test file from the Test/Verifier, the vulnerabilities it tests, and its result in the latest
    # Run tests. Every run's results are also in the event log.
    path: str
    vulnerability_ids: list[str] = []
    passed: bool | None = None  # None until it has been run
    result: str | None = None  # e.g. "2 of 3 tests passed"


class SecurityState(BaseModel):
    counters: dict[str, int] = {}  # last id number used per category, so ids are never reused after a delete
    assumptions: list[Assumption] = []
    risks: list[Risk] = []
    vulnerabilities: list[Vulnerability] = []
    mitigations: list[Mitigation] = []
    tests: list[SecurityTest] = []
