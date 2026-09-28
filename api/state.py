from fastapi import APIRouter

from models.security_state import Risk, RiskCreate, SecurityState

router = APIRouter(prefix="/state", tags=["security state"])

# In memory for now; resets when the server restarts.
_state = SecurityState()


def reset_state() -> None:
    global _state
    _state = SecurityState()


@router.get("")
def get_state() -> SecurityState:
    return _state


@router.post("/risks", status_code=201)
def add_risk(body: RiskCreate) -> Risk:
    # Risks from the human are approved immediately; risks from agents wait for approval.
    risk = Risk(
        id=f"R{len(_state.risks) + 1}",
        human_approved=True if body.source == "human" else None,
        **body.model_dump(),
    )
    _state.risks.append(risk)
    return risk
