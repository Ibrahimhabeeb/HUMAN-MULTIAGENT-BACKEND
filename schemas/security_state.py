from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator

Actor = Literal["human", "system", "assistant", "facilitator", "planner", "threat_modeller", "reviewer", "verifier"]
Severity = Literal["Low", "Medium", "High", "Critical"]
VulnerabilityStatus = Literal["accepted", "rejected"]  # the developer's decision on the finding
MitigationStatus = Literal["planned", "implemented"]
UnitTestStatus = Literal["open", "passed", "failed"]  # open: not run yet

Category = Literal["assumptions", "risks", "vulnerabilities", "mitigations", "tests"]
HumanCategory = Literal["assumptions", "risks", "vulnerabilities", "mitigations"]  # the ones the human edits directly
HumanAddCategory = Literal["vulnerabilities", "mitigations"]


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
    # A fix for a vulnerability: the Code Reviewer's, written into the code, or one the human adds: the code, where
    # it is, and why.
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
    # A concern to keep in view, so it has no status. (Older states stored one; it is ignored.)
    pass


class Vulnerability(StateItem, VulnerabilityCreate):
    status: VulnerabilityStatus = "accepted"  # a rejected finding stays listed, so it isn't raised again

    @field_validator("status", mode="before")
    @classmethod
    def _older_statuses(cls, value: str) -> str:
        return "accepted" if value in ("open", "fixed") else value  # saved before accepted/rejected


class Mitigation(StateItem, MitigationCreate):
    status: MitigationStatus = "planned"  # implemented once the code contains the fix


class UnitTest(StateItem):
    # One test function in the task's tests/ folder, with the outcome of the most recent run, which replaces the
    # one before. Every run's results are also in the event log.
    file: str  # e.g. "tests/test_functional.py"
    name: str  # e.g. "test_wrong_password_is_refused"
    status: UnitTestStatus = "open"
    message: str | None = None  # why it failed in the most recent run


class SecurityState(BaseModel):
    counters: dict[str, int] = {}  # last id number used per category, so ids are never reused after a delete
    assumptions: list[Assumption] = []
    risks: list[Risk] = []
    vulnerabilities: list[Vulnerability] = []
    mitigations: list[Mitigation] = []
    tests: list[UnitTest] = []

    @field_validator("tests", mode="before")
    @classmethod
    def _drop_older_tests(cls, value: list) -> list:
        # Older states listed test files the Test/Verifier wrote, not test functions; those aren't tracked any more.
        return [test for test in value or [] if not isinstance(test, dict) or "name" in test]
