from typing import Literal

from pydantic import BaseModel

from schemas.security_state import Evidence

Outcome = Literal["passed", "failed", "error", "skipped"]
RunStatus = Literal["passed", "failed", "no_tests", "timed_out", "error"]


class CaseResult(BaseModel):
    file: str  # e.g. "tests/test_security_login.py"
    name: str
    outcome: Outcome
    message: str | None = None
    details: str | None = None  # the end of the traceback, for failures and errors


class RunResult(BaseModel):
    status: RunStatus
    message: str  # one line for the human, e.g. "2 passed, 1 failed"
    counts: dict[Outcome, int]
    tests: list[CaseResult]
    output: str  # the end of pytest's own output
    evidence: list[Evidence] = []  # team mode: what this run attached to risks
