from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from schemas.common import UtcDatetime
from schemas.security_state import AssumptionCreate, RiskCreate, VulnerabilityCreate
from schemas.workspace import MAX_FILE_CHARS

ActionType = Literal[
    "propose_assumption",
    "propose_risk",
    "propose_vulnerability",
    "mark_resolved",
    "propose_test",
    "suggest_fix",
]
ApprovalStatus = Literal["pending", "approved", "rejected"]
Decision = Literal["approve", "reject"]  # proposals are never edited: the human changes approved items themselves


class ResolveProposal(BaseModel):
    item_id: str = Field(pattern=r"^[RV]\d+$")  # a risk (R2) or a vulnerability (V1)
    reason: str = Field(min_length=3, max_length=1000)


class ProposedTest(BaseModel):
    path: str = Field(pattern=r"^tests/(?:[\w-]+/)*test_[\w-]+\.py$")
    content: str = Field(min_length=1, max_length=MAX_FILE_CHARS)
    vulnerability_ids: list[str] = []  # the approved vulnerabilities it tests (team mode)


class FixSuggestion(BaseModel):
    # In team mode an approved fix becomes a mitigation for the vulnerability it fixes.
    vulnerability: str = Field(max_length=200)  # what it fixes, e.g. "V2", or a short description in single mode
    file: str = Field(max_length=300)
    location: str = Field(max_length=300)  # where the code goes, e.g. "login(), replacing line 12"
    code: str = Field(min_length=1, max_length=20_000)
    why: str = Field(min_length=3, max_length=2000)


PROPOSAL_SCHEMAS: dict[str, type[BaseModel]] = {
    "propose_assumption": AssumptionCreate,
    "propose_risk": RiskCreate,
    "propose_vulnerability": VulnerabilityCreate,
    "mark_resolved": ResolveProposal,
    "propose_test": ProposedTest,
    "suggest_fix": FixSuggestion,
}

# Single mode has no shared security state, so only fixes and tests can be proposed there.
SINGLE_MODE_ACTIONS = {"suggest_fix", "propose_test"}


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
