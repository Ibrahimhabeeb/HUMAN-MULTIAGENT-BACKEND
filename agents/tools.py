from langchain_core.tools import BaseTool, tool
from pydantic import ValidationError

from agents.context import AgentContext, Proposal, numbered
from schemas.approval import PROPOSAL_SCHEMAS, SUGGESTIONS
from schemas.security_state import SecurityState, Severity, StateItem

# Which tools each agent gets. Reading tools only look at the run's snapshot; every other tool records a proposal
# that waits for the human's approval, except a suggested risk, which goes straight into the security state.
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


def _same_place(a: dict, b: dict) -> bool:
    # Two vulnerabilities are the same if they are in the same file, on the same line, with the same CWE.
    return a.get("file") is not None and all(a.get(key) == b.get(key) for key in ("file", "line", "cwe"))


def _same_text(a: str, b: str) -> bool:
    return " ".join(a.lower().split()) == " ".join(b.lower().split())


def _risk_problem(ctx: AgentContext, state: SecurityState, proposal: dict) -> str | None:
    for risk in state.risks:
        if _same_text(risk.description, proposal["description"]):
            return f"this risk is already in the security state as {risk.id}."
    earlier = [p.proposal["description"] for p in ctx.proposals if p.action_type == "propose_risk"]
    if any(_same_text(description, proposal["description"]) for description in earlier):
        return "you already suggested this risk in this reply."
    return None


def _vulnerability_problem(ctx: AgentContext, state: SecurityState, proposal: dict) -> str | None:
    risk_id = proposal["risk_id"]
    if risk_id is not None and not any(risk.id == risk_id for risk in state.risks):
        return (
            f"{risk_id} is not a risk in the security state (risks: {_ids(state.risks)}). "
            "Use one of those or leave risk_id empty."
        )
    for v in state.vulnerabilities:
        if _same_place(proposal, v.model_dump()):
            return f"this is the same as {v.id}, which is already in the security state."
    for earlier in ctx.earlier:
        if earlier.action_type == "propose_vulnerability" and _same_place(proposal, earlier.proposal):
            if earlier.status == "pending":
                return f"this is the same as proposal #{earlier.id}, which is waiting for the developer's decision."
            return f"the developer rejected this vulnerability (proposal #{earlier.id}). Don't propose it again."
    if any(p.action_type == "propose_vulnerability" and _same_place(proposal, p.proposal) for p in ctx.proposals):
        return "you already proposed this vulnerability in this reply."
    return None


def _fix_problem(ctx: AgentContext, state: SecurityState, proposal: dict) -> str | None:
    target = proposal["vulnerability"].strip()
    vulnerability = next((v for v in state.vulnerabilities if v.id == target), None)
    if vulnerability is None:
        return (
            f"{target} is not an approved vulnerability (approved: {_ids(state.vulnerabilities)}). "
            "Suggest fixes only for vulnerabilities the developer has approved."
        )
    if vulnerability.status == "fixed":
        return f"{target} is already fixed."
    mitigation = next((m.id for m in state.mitigations if m.vulnerability_id == target), None)
    if mitigation:
        return f"{target} already has a mitigation ({mitigation})."
    for earlier in ctx.earlier:
        if earlier.action_type == "suggest_fix" and earlier.proposal.get("vulnerability") == target:
            if earlier.status == "pending":
                return f"a fix for {target} is already waiting for the developer's decision (proposal #{earlier.id})."
            if earlier.proposal.get("code") == proposal["code"]:
                return f"the developer rejected this fix (proposal #{earlier.id}). Don't suggest it again."
    if any(p.action_type == "suggest_fix" and p.proposal.get("vulnerability") == target for p in ctx.proposals):
        return f"you already suggested a fix for {target} in this reply."
    return None


def _test_problem(ctx: AgentContext, state: SecurityState, proposal: dict) -> str | None:
    unknown = [v for v in proposal["vulnerability_ids"] if not any(x.id == v for x in state.vulnerabilities)]
    if unknown:
        approved = _ids(state.vulnerabilities)
        return f"these are not approved vulnerabilities: {', '.join(unknown)} (approved: {approved})."
    for earlier in ctx.earlier:
        if earlier.action_type == "propose_test" and earlier.proposal.get("path") == proposal["path"]:
            if earlier.status == "pending":
                return f"{proposal['path']} is already waiting for the developer's decision (proposal #{earlier.id})."
            if earlier.proposal.get("content") == proposal["content"]:
                return f"the developer rejected this test (proposal #{earlier.id}). Don't propose it again."
    if any(p.action_type == "propose_test" and p.proposal.get("path") == proposal["path"] for p in ctx.proposals):
        return f"you already proposed {proposal['path']} in this reply."
    return None


def _resolve_problem(ctx: AgentContext, state: SecurityState, proposal: dict) -> str | None:
    item_id = proposal["item_id"]
    item = next((i for i in [*state.risks, *state.vulnerabilities] if i.id == item_id), None)
    if item is None:
        return f"{item_id} is not in the security state."
    if item.status != "open":
        return f"{item_id} is already {item.status}."
    for earlier in ctx.earlier:
        if (earlier.status, earlier.action_type, earlier.proposal.get("item_id")) == ("pending", "mark_resolved", item_id):
            return f"marking {item_id} as resolved is already waiting for the developer's decision."
    if any(p.action_type == "mark_resolved" and p.proposal.get("item_id") == item_id for p in ctx.proposals):
        return f"you already proposed marking {item_id} as resolved in this reply."
    return None


_CHECKS = {
    "propose_risk": _risk_problem,
    "propose_vulnerability": _vulnerability_problem,
    "suggest_fix": _fix_problem,
    "propose_test": _test_problem,
    "mark_resolved": _resolve_problem,
}


def _problem(ctx: AgentContext, action_type: str, proposal: dict) -> str | None:
    # Team mode: a proposal may only point at items in the state, and each thing is proposed once: not again while it
    # waits for the developer's decision, after it was rejected, or once it is in the state. Saying so straight
    # away lets the agent correct it before the developer sees it.
    check = _CHECKS.get(action_type)
    return check(ctx, ctx.state, proposal) if check and ctx.state else None


def make_tools(ctx: AgentContext, actor: str) -> list[BaseTool]:
    def record(action_type: str, **fields) -> str:
        try:
            data = PROPOSAL_SCHEMAS[action_type].model_validate({k: v for k, v in fields.items() if v is not None})
        except ValidationError as e:
            return f"Not recorded, the proposal is invalid: {e.errors(include_url=False, include_context=False)}"
        problem = _problem(ctx, action_type, data.model_dump(mode="json"))
        if problem:
            return f"Not recorded: {problem}"
        ctx.proposals.append(Proposal(actor, action_type, data.model_dump(mode="json")))
        if action_type in SUGGESTIONS and ctx.state:
            return "Recorded. It goes straight into the security state as a suggested risk."
        return "Recorded. It waits for the developer's approval."

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
        """Get the shared security state: assumptions, risks, vulnerabilities, mitigations and tests."""
        return ctx.state.model_dump_json(indent=1, exclude={"counters"}) if ctx.state else "No security state."

    @tool
    def propose_assumption(text: str) -> str:
        """Propose an assumption the analysis relies on."""
        return record("propose_assumption", text=text)

    @tool
    def propose_risk(
        description: str, severity: Severity, cwe: str | None = None, owasp: str | None = None, stride: str | None = None
    ) -> str:
        """Suggest a security risk; it goes straight into the security state. cwe looks like "CWE-89"; owasp is an
        OWASP Top 10 category; stride a STRIDE category."""
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
        instance of one of the risks in the security state; otherwise leave it empty."""
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
        """Suggest a fix: what it fixes (an approved vulnerability's id such as "V2" when there is a security state,
        otherwise a short description), the full workspace-relative file path (e.g. "app/auth.py"), a precise
        location (function/class and lines or nearby statement, and whether to replace or insert), the code,
        and why. For a new file, say to create it in location. Never omit the file path or location."""
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
