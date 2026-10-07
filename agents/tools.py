from langchain_core.tools import BaseTool, tool
from pydantic import ValidationError

from agents.context import AgentContext, Proposal, numbered
from schemas.approval import PROPOSAL_SCHEMAS
from schemas.security_state import Severity

# Which tools each agent gets. Reading tools only look at the run's snapshot;
# every other tool records a proposal that waits for the human's approval.
TOOLS_FOR: dict[str, list[str]] = {
    "planner": ["list_files", "read_file", "read_task_description"],
    "threat_modeller": [
        "list_files",
        "read_file",
        "read_task_description",
        "get_security_state",
        "propose_assumption",
        "propose_risk",
        "propose_mitigation",
    ],
    "reviewer": [
        "list_files",
        "read_file",
        "read_task_description",
        "get_security_state",
        "propose_finding",
        "suggest_fix",
        "mark_resolved",
    ],
    # Tests are written from the approved risks and the task's interface, not from the code.
    "verifier": ["read_task_description", "get_security_state", "propose_test"],
    "assistant": ["list_files", "read_file", "suggest_fix", "propose_test"],
}


def make_tools(ctx: AgentContext, actor: str) -> list[BaseTool]:
    def record(action_type: str, **fields) -> str:
        try:
            data = PROPOSAL_SCHEMAS[action_type].model_validate({k: v for k, v in fields.items() if v is not None})
        except ValidationError as e:
            return f"Not recorded, the proposal is invalid: {e.errors(include_url=False, include_context=False)}"
        ctx.proposals.append(Proposal(actor, action_type, data.model_dump(mode="json")))
        return f"Recorded as proposal #{len(ctx.proposals)}. It waits for the developer's approval."

    @tool
    def list_files() -> str:
        """List the paths of every file in the project."""
        return "\n".join(sorted(ctx.files))

    @tool
    def read_file(path: str) -> str:
        """Read one project file, with line numbers, e.g. "app/auth.py"."""
        if path not in ctx.files:
            return f"No file called {path}. Use list_files to see the files."
        return numbered(ctx.files[path])

    @tool
    def read_task_description() -> str:
        """Read the task description (README.md), including the interface to implement."""
        return ctx.task_description

    @tool
    def get_security_state() -> str:
        """Get the approved shared security state: assumptions, risks, mitigations, findings, evidence and tests."""
        return ctx.state.model_dump_json(indent=1, exclude={"counters"}) if ctx.state else "No security state."

    @tool
    def propose_assumption(text: str) -> str:
        """Propose an assumption the analysis relies on."""
        return record("propose_assumption", text=text)

    @tool
    def propose_risk(
        description: str, severity: Severity, cwe: str | None = None, owasp: str | None = None, stride: str | None = None
    ) -> str:
        """Propose a security risk. cwe looks like "CWE-89"; owasp is an OWASP Top 10 category; stride a STRIDE category."""
        return record("propose_risk", description=description, severity=severity, cwe=cwe, owasp=owasp, stride=stride)

    @tool
    def propose_mitigation(risk_id: str, description: str) -> str:
        """Propose a mitigation for a risk: an approved risk id like "R1", or "#n" for a risk you proposed this turn."""
        return record("propose_mitigation", risk_id=risk_id, description=description)

    @tool
    def propose_finding(
        description: str,
        severity: Severity,
        file: str | None = None,
        line: int | None = None,
        cwe: str | None = None,
        risk_id: str | None = None,
    ) -> str:
        """Propose a finding: a weakness in the code, with its file and line, linked to a risk id if it is one."""
        return record(
            "propose_finding", description=description, severity=severity, file=file, line=line, cwe=cwe, risk_id=risk_id
        )

    @tool
    def suggest_fix(finding: str, file: str, location: str, code: str, why: str) -> str:
        """Suggest a fix: what it fixes (e.g. "F2" or "#1"), the file, where the code goes, the code, and why."""
        return record("suggest_fix", finding=finding, file=file, location=location, code=code, why=why)

    @tool
    def mark_resolved(item_id: str, reason: str) -> str:
        """Propose marking a finding (F1) or risk (R2) as resolved, with the reason."""
        return record("mark_resolved", item_id=item_id, reason=reason)

    @tool
    def propose_test(path: str, content: str, risk_ids: list[str] | None = None) -> str:
        """Propose a pytest file, e.g. path "tests/test_security_login.py", and the risk ids it covers."""
        return record("propose_test", path=path, content=content, risk_ids=risk_ids or [])

    available = {t.name: t for t in locals().values() if isinstance(t, BaseTool)}
    return [available[name] for name in TOOLS_FOR[actor]]
