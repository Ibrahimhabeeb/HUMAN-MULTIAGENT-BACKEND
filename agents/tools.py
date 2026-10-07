import json

from langchain_core.tools import BaseTool, tool
from pydantic import ValidationError
from sqlalchemy.orm import Session

from agents.roles import Specialist
from schemas.security_state import MitigationCreate, RiskCreate, Severity
from services import state_service, workspace
from services.errors import ConflictError, InvalidPathError, NotFoundError

MAX_FILE_CHARS_FOR_AGENT = 20_000


def make_tools(
    db: Session, project_id: str, session_id: str, role: Specialist
) -> list[BaseTool]:
    # Tools are built per request so they always act on this project, in this session,
    # under this agent's own name. Errors are returned as text so the model can correct itself.

    def safely(action) -> str:
        try:
            return action()
        except (NotFoundError, ConflictError, InvalidPathError, ValidationError) as e:
            return f"Error: {e}"

    @tool
    def list_files() -> str:
        """List the paths of every file in the project."""
        return "\n".join(
            p
            for p, node in workspace.list_files(db, project_id).items()
            if node["type"] == "file"
        )

    @tool
    def read_file(path: str) -> str:
        """Read one project file, e.g. "app/auth.py"."""
        return safely(
            lambda: workspace.read_file(db, project_id, path)["content"][
                :MAX_FILE_CHARS_FOR_AGENT
            ]
        )

    @tool
    def get_security_state() -> str:
        """Get the shared security state: requirements, assumptions, risks, mitigations, evidence, questions."""
        return state_service.get_state(db, project_id).model_dump_json(indent=1)

    @tool
    def add_requirement(text: str) -> str:
        """Record a requirement the implementation must meet."""
        return safely(
            lambda: (
                state_service.add_requirement(db, project_id, session_id, text, role).id
            )
        )

    @tool
    def add_assumption(text: str) -> str:
        """Record an assumption the plan relies on."""
        return safely(
            lambda: (
                state_service.add_assumption(db, project_id, session_id, text, role).id
            )
        )

    @tool
    def add_question(text: str) -> str:
        """Record an open question the human needs to answer."""
        return safely(
            lambda: (
                state_service.add_question(db, project_id, session_id, text, role).id
            )
        )

    @tool
    def add_risk(
        description: str,
        severity: Severity,
        cwe: str | None = None,
        owasp: str | None = None,
        stride: str | None = None,
        file: str | None = None,
        line: int | None = None,
    ) -> str:
        """Record a security risk. cwe looks like "CWE-89"; file and line point at the code if known."""

        def record() -> str:
            data = RiskCreate(
                description=description,
                severity=severity,
                cwe=cwe,
                owasp=owasp,
                stride=stride,
                file=file,
                line=line,
            )
            return state_service.add_risk(db, project_id, session_id, data, role).id

        return safely(record)

    @tool
    def add_mitigation(risk_id: str, description: str) -> str:
        """Propose a mitigation for an existing risk, e.g. risk_id "R1"."""

        def record() -> str:
            data = MitigationCreate(risk_id=risk_id, description=description)
            return state_service.add_mitigation(
                db, project_id, session_id, data, role
            ).id

        return safely(record)

    read_tools = [list_files, read_file, get_security_state]
    role_tools: dict[str, list[BaseTool]] = {
        "planner": [add_requirement, add_assumption, add_question],
        "threat_modeller": [add_risk, add_mitigation, add_question],
        "reviewer": [add_risk, add_mitigation],
        "verifier": [add_question],
    }
    return read_tools + role_tools[role]


def summarise_state(db: Session, project_id: str) -> str:
    state = state_service.get_state(db, project_id)
    return json.dumps(
        {
            "requirements": len(state.requirements),
            "risks": [
                {"id": r.id, "status": r.status, "approved": r.human_approved}
                for r in state.risks
            ],
            "mitigations": [
                {"id": m.id, "risk": m.risk_id, "status": m.status}
                for m in state.mitigations
            ],
            "open_questions": [q.id for q in state.questions if q.answer is None],
        }
    )
