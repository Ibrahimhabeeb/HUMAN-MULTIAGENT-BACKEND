import re

from langchain_core.tools import BaseTool, tool
from pydantic import ValidationError

from agents.context import AgentContext, Proposal, numbered
from schemas.approval import PROPOSAL_SCHEMAS
from schemas.security_state import Severity, StateItem

_EARLIER_PROPOSAL = re.compile(r"#(\d+)")

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
    ],
    # An approved fix becomes a mitigation for the vulnerability it fixes.
    "reviewer": [
        "list_files",
        "read_file",
        "read_task_description",
        "get_security_state",
        "propose_vulnerability",
        "suggest_fix",
        "mark_resolved",
    ],
    # Tests are written against the approved vulnerabilities and the task's interface, not from the code.
    "verifier": ["read_task_description", "get_security_state", "propose_test"],
    "assistant": ["list_files", "read_file", "suggest_fix", "propose_test"],
}


def _ids(items: list[StateItem]) -> str:
    return ", ".join(item.id for item in items) or "none yet"


def _link_problem(ctx: AgentContext, action_type: str, proposal: dict) -> str | None:
    # Team mode: a proposal may only point at items in the approved state, or a fix at a vulnerability proposed
    # earlier in the same reply ("#n"). Saying so straight away lets the agent correct it before the developer sees it.
    state = ctx.state
    if state is None:
        return None
    risks = {risk.id for risk in state.risks}
    vulnerabilities = {v.id for v in state.vulnerabilities}
    if action_type == "propose_vulnerability":
        risk_id = proposal["risk_id"]
        if risk_id is not None and risk_id not in risks:
            return (
                f"{risk_id} is not an approved risk (approved risks: {_ids(state.risks)}). "
                "Use one of those or leave risk_id empty."
            )
    elif action_type == "suggest_fix":
        target = proposal["vulnerability"].strip()
        earlier = _EARLIER_PROPOSAL.fullmatch(target)
        if earlier:
            n = int(earlier.group(1))
            if not (0 < n <= len(ctx.proposals) and ctx.proposals[n - 1].action_type == "propose_vulnerability"):
                return f"{target} is not a vulnerability you proposed earlier in this reply."
        elif target not in vulnerabilities:
            return (
                f"{target} is not a vulnerability in the security state (vulnerabilities: {_ids(state.vulnerabilities)}). "
                "Propose the vulnerability first, then refer to it by its proposal number, e.g. #1."
            )
    elif action_type == "propose_test":
        unknown = [v for v in proposal["vulnerability_ids"] if v not in vulnerabilities]
        if unknown:
            approved = _ids(state.vulnerabilities)
            return f"these are not approved vulnerabilities: {', '.join(unknown)} (approved: {approved})."
    elif action_type == "mark_resolved" and proposal["item_id"] not in risks | vulnerabilities:
        return f"{proposal['item_id']} is not in the security state."
    return None


def make_tools(ctx: AgentContext, actor: str) -> list[BaseTool]:
    def record(action_type: str, **fields) -> str:
        try:
            data = PROPOSAL_SCHEMAS[action_type].model_validate({k: v for k, v in fields.items() if v is not None})
        except ValidationError as e:
            return f"Not recorded, the proposal is invalid: {e.errors(include_url=False, include_context=False)}"
        problem = _link_problem(ctx, action_type, data.model_dump())
        if problem:
            return f"Not recorded: {problem}"
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
        """Get the approved shared security state: assumptions, risks, vulnerabilities, mitigations and tests."""
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
    def propose_vulnerability(
        description: str,
        severity: Severity,
        file: str | None = None,
        line: int | None = None,
        cwe: str | None = None,
        risk_id: str | None = None,
    ) -> str:
        """Propose a vulnerability: a weakness in the code, with its file and line. Give risk_id only if it is an
        instance of one of the approved risks; otherwise leave it empty."""
        return record(
            "propose_vulnerability",
            description=description,
            severity=severity,
            file=file,
            line=line,
            cwe=cwe,
            risk_id=risk_id,
        )

    @tool
    def suggest_fix(vulnerability: str, file: str, location: str, code: str, why: str) -> str:
        """Suggest a fix: what it fixes (a vulnerability like "V2", "#1" for one you proposed in this reply, or a
        short description), the file, where the code goes, the code, and why."""
        return record("suggest_fix", vulnerability=vulnerability, file=file, location=location, code=code, why=why)

    @tool
    def mark_resolved(item_id: str, reason: str) -> str:
        """Propose marking a vulnerability (V1) as fixed or a risk (R2) as mitigated, with the reason."""
        return record("mark_resolved", item_id=item_id, reason=reason)

    @tool
    def propose_test(path: str, content: str, vulnerability_ids: list[str] | None = None) -> str:
        """Propose a pytest file, e.g. path "tests/test_security_login.py", and the vulnerability ids it tests."""
        return record("propose_test", path=path, content=content, vulnerability_ids=vulnerability_ids or [])

    available = {t.name: t for t in locals().values() if isinstance(t, BaseTool)}
    return [available[name] for name in TOOLS_FOR[actor]]
