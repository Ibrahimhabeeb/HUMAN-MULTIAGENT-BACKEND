from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from schemas.common import UtcDatetime
from schemas.security_state import AssumptionCreate, RiskCreate, VulnerabilityCreate
from schemas.workspace import MAX_FILE_CHARS
from services.paths import clean_path

ActionType = Literal[
    "propose_assumption",
    "propose_risk",
    "propose_vulnerability",
    "mark_resolved",
    "propose_test",
    "suggest_fix",
    "write_fix",
]
ApprovalStatus = Literal["pending", "approved", "rejected", "suggested", "written", "undone"]
Decision = Literal["approve", "reject"]  # proposals are never edited: the human changes approved items themselves
FixChoice = Literal["reviewer", "developer"]


class ResolveProposal(BaseModel):
    item_id: str = Field(pattern=r"^M\d+$")  # a mitigation the developer's code now contains, marked implemented
    reason: str = Field(min_length=3, max_length=1000)


class ProposedTest(BaseModel):
    # Single mode only: the team's Test/Verifier runs the task's tests and never writes any.
    path: str = Field(pattern=r"^tests/(?:[\w-]+/)*test_[\w-]+\.py$")
    content: str = Field(min_length=1, max_length=MAX_FILE_CHARS)
    base_content: str | None = None  # existing file when proposed; prevents overwriting later human edits


class Fix(BaseModel):
    vulnerability: str = Field(max_length=200)  # what it fixes, e.g. "V2", or a short description in single mode
    file: str = Field(min_length=1, max_length=300)
    why: str = Field(min_length=3, max_length=2000)

    @field_validator("file")
    @classmethod
    def valid_file_path(cls, value: str) -> str:
        return clean_path(value)


class FixWrite(Fix):
    # Team mode: the Code Reviewer's fix for an accepted vulnerability, written straight into the code.
    find: str = Field(min_length=1, max_length=20_000)  # the existing code to replace, exactly as it is in the file
    replace: str = Field(max_length=20_000)


class FixSuggestion(Fix):
    # Single mode: the human types an approved fix themselves.
    location: str = Field(min_length=3, max_length=300)  # where the code goes, e.g. "login(), replacing line 12"
    code: str = Field(min_length=1, max_length=20_000)

    @field_validator("location")
    @classmethod
    def precise_location(cls, value: str) -> str:
        if len(value.strip()) < 3:
            raise ValueError("Specify the function, line or nearby statement and where to put the fix")
        return value.strip()


PROPOSAL_SCHEMAS: dict[str, type[BaseModel]] = {
    "propose_assumption": AssumptionCreate,
    "propose_risk": RiskCreate,
    "propose_vulnerability": VulnerabilityCreate,
    "mark_resolved": ResolveProposal,
    "propose_test": ProposedTest,
    "suggest_fix": FixSuggestion,
    "write_fix": FixWrite,
}

# Single mode has no shared security state, so only fixes and tests can be proposed there.
SINGLE_MODE_ACTIONS = {"suggest_fix", "propose_test"}

# These need no decision, so the Approvals panel shows them without Approve or Reject: (their status, their state
# category). The Threat Modeller's risks go straight into the security state. The Code Reviewer's fix goes straight
# into the code, and into the state as a mitigation: accepting the vulnerability was the decision.
NO_DECISION: dict[str, tuple[ApprovalStatus, str]] = {
    "propose_risk": ("suggested", "risks"),
    "write_fix": ("written", "mitigations"),
}


class ApprovalOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    actor: str
    action_type: ActionType
    proposal: dict[str, Any]
    final_proposal: dict[str, Any] | None
    status: ApprovalStatus
    requested_at: UtcDatetime
    decided_at: UtcDatetime | None
    result: dict[str, Any] | None


class DecisionRequest(BaseModel):
    decision: Decision


class FixChoiceRequest(BaseModel):
    choice: FixChoice
