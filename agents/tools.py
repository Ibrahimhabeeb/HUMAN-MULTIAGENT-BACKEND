import re

from langchain_core.tools import BaseTool, tool
from pydantic import ValidationError

from agents.context import AgentContext, Proposal, numbered
from schemas.approval import PROPOSAL_SCHEMAS
from schemas.security_state import SecurityState, Severity, StateItem
from services.fix_validation import invalid_python_edit

# Which tools each agent gets. Reading tools only look at the run's snapshot; every other tool records a proposal
# that waits for the human's approval, except a suggested risk, which goes straight into the security state.
# The Code Reviewer's write_fix isn't here: only the follow-up after an accepted vulnerability gets it.
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
    # mark_resolved marks a planned mitigation implemented.
    "reviewer": [
        "list_files",
        "read_file",
        "read_task_description",
        "get_security_state",
        "propose_vulnerability",
        "mark_resolved",
    ],
    # The Test/Verifier has no tools: it runs the task's unit tests without the model.
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
    description = proposal["description"]
    if re.search(r"\bno vulnerabilities? (?:were )?found\b", description, re.IGNORECASE) or re.search(
        r"\bno\b[^.!?]{0,100}\b(?:weakness(?:es)?|vulnerabilit(?:y|ies))\b[^.!?]{0,30}\bfound\b",
        description,
        re.IGNORECASE,
    ):
        return "the description says no security weakness was found. Report a clean review in chat, without a proposal."
    for v in state.vulnerabilities:
        if _same_place(proposal, v.model_dump()):
            if v.status == "rejected":
                return f"the developer rejected this vulnerability ({v.id}). Don't propose it again."
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
    if ctx.fix_no_change:
        return "you already recorded that no code change is justified for this finding."
    target = proposal["vulnerability"].strip()
    accepted = [v for v in state.vulnerabilities if v.status == "accepted"]
    if not any(v.id == target for v in accepted):
        return (
            f"{target} is not an accepted vulnerability (accepted: {_ids(accepted)}). "
            "Suggest fixes only for vulnerabilities the developer has accepted."
        )
    mitigation = next((m.id for m in state.mitigations if m.vulnerability_id == target), None)
    if mitigation:
        return f"{target} already has a mitigation ({mitigation})."
    if any(p.action_type == "write_fix" and p.proposal.get("vulnerability") == target for p in ctx.proposals):
        return f"you already wrote a fix for {target} in this reply."
    file = proposal["file"]
    if file not in ctx.files:
        return f"there is no file called {file}. Use list_files to see the files."
    matches = ctx.files[file].count(proposal["find"])
    if matches != 1:
        return (
            f"find must match the code in {file} exactly once, but it matched {matches} times. Copy it exactly from "
            "the file, without the line numbers, with enough of the surrounding lines to be unique."
        )
    content = ctx.files[file]
    updated = content.replace(proposal["find"], proposal["replace"], 1)
    if problem := invalid_python_edit(file, content, updated):
        return problem
    return None


def _resolve_problem(ctx: AgentContext, state: SecurityState, proposal: dict) -> str | None:
    item_id = proposal["item_id"]
    mitigation = next((m for m in state.mitigations if m.id == item_id), None)
    if mitigation is None:
        return f"{item_id} is not a mitigation in the security state (mitigations: {_ids(state.mitigations)})."
    if mitigation.status == "implemented":
        return f"{item_id} is already implemented."
    for earlier in ctx.earlier:
        if (earlier.status, earlier.action_type, earlier.proposal.get("item_id")) == ("pending", "mark_resolved", item_id):
            return f"marking {item_id} as implemented is already waiting for the developer's decision."
    if any(p.action_type == "mark_resolved" and p.proposal.get("item_id") == item_id for p in ctx.proposals):
        return f"you already proposed marking {item_id} as implemented in this reply."
    return None


_CHECKS = {
    "propose_risk": _risk_problem,
    "propose_vulnerability": _vulnerability_problem,
    "write_fix": _fix_problem,
    "mark_resolved": _resolve_problem,
}


def _problem(ctx: AgentContext, action_type: str, proposal: dict) -> str | None:
    # Team mode: a proposal may only point at items in the state, and each thing is proposed once: not again while it
    # waits for the developer's decision, after it was rejected, or once it is in the state. Saying so straight
    # away lets the agent correct it before the developer sees it.
    check = _CHECKS.get(action_type)
    return check(ctx, ctx.state, proposal) if check and ctx.state else None


def make_tools(ctx: AgentContext, actor: str, *, names: list[str] | None = None) -> list[BaseTool]:
    def record(action_type: str, **fields) -> str:
        try:
            data = PROPOSAL_SCHEMAS[action_type].model_validate({k: v for k, v in fields.items() if v is not None})
        except ValidationError as e:
            reason = f"the proposal is invalid: {e.errors(include_url=False, include_context=False, include_input=False)}"
            if action_type == "write_fix":
                ctx.rejected_fixes.append(reason)
            return f"Not recorded, {reason}"
        target = ctx.target_vulnerability
        if target and action_type == "write_fix" and data.vulnerability.strip() != target:
            reason = f"this follow-up is only for {target}."
            ctx.rejected_fixes.append(reason)
            return f"Not recorded: {reason}"
        problem = _problem(ctx, action_type, data.model_dump(mode="json"))
        if problem:
            if action_type == "write_fix":
                ctx.rejected_fixes.append(problem)
            return f"Not recorded: {problem}"
        ctx.proposals.append(Proposal(actor, action_type, data.model_dump(mode="json")))
        if action_type == "propose_risk" and ctx.state:
            return "Recorded. It goes straight into the security state as a suggested risk."
        if action_type == "write_fix":
            return "Recorded. It goes straight into the code and into the security state as a mitigation."
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
        """Get the shared security state: assumptions, risks, vulnerabilities, mitigations and unit test results."""
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
    ) -> str:
        """Propose an actual security weakness in the current code, with its file and line, how it could be exploited
        and its impact. Do not propose secure practices, hypothetical risks or optional improvements. If no
        vulnerabilities are found, say "No vulnerabilities found." in chat instead of calling this tool."""
        return record(
            "propose_vulnerability",
            description=description,
            severity=severity,
            file=file,
            line=line,
            cwe=cwe,
        )

    @tool
    def suggest_fix(vulnerability: str, file: str, location: str, code: str, why: str) -> str:
        """Suggest a fix: a short description of what it fixes, the full workspace-relative file path
        (e.g. "app/auth.py"), a precise location (function/class and lines or nearby statement, and whether to
        replace or insert), the code, and why. For a new file, say to create it in location. Never omit the file
        path or location."""
        return record("suggest_fix", vulnerability=vulnerability, file=file, location=location, code=code, why=why)

    @tool
    def write_fix(vulnerability: str, file: str, find: str, replace: str, why: str) -> str:
        """Write the fix for an accepted vulnerability straight into the developer's code: its id (e.g. "V2"), the
        full workspace-relative file path (e.g. "app/auth.py"), the existing code to replace (find), the code that
        replaces it (replace), and why. find is copied exactly from the current file, without the line numbers, and
        must match exactly once. To add code, put a nearby line in find and keep that line in replace."""
        return record("write_fix", vulnerability=vulnerability, file=file, find=find, replace=replace, why=why)

    @tool
    def explain_no_fix(vulnerability: str, file: str, reason: str) -> str:
        """Explain why no edit is justified for the current accepted finding. Give its id, an existing file path,
        and concrete evidence (existing checks, constraints or task requirements). This changes no code, finding
        status or mitigation. The developer decides whether to reconsider the finding."""
        if not ctx.target_vulnerability or vulnerability.strip() != ctx.target_vulnerability:
            problem = "explain only the vulnerability assigned to this follow-up."
        elif file not in ctx.files:
            problem = "cite an existing project file as evidence."
        elif not 20 <= len(reason.strip()) <= 2000:
            problem = "give a concrete explanation between 20 and 2000 characters."
        elif any(p.action_type == "write_fix" for p in ctx.proposals):
            problem = "a code edit has already been recorded in this follow-up."
        else:
            ctx.fix_no_change = (
                f"No code change was made for {vulnerability.strip()}.\n\n"
                f"**{file}:** {reason.strip()}\n\n"
                "The finding remains accepted. Please review this explanation and decide whether to keep or reject it."
            )
            return "Explanation recorded. No code or security-state status has been changed."
        ctx.rejected_fixes.append(problem)
        return f"Not recorded: {problem}"

    @tool
    def mark_resolved(item_id: str, reason: str) -> str:
        """Propose marking a planned mitigation (e.g. M1) as implemented, once the developer's current code contains
        that fix, with the reason."""
        return record("mark_resolved", item_id=item_id, reason=reason)

    @tool
    def propose_test(path: str, content: str) -> str:
        """Propose a pytest file, e.g. path "tests/test_login.py"."""
        return record("propose_test", path=path, content=content, base_content=ctx.files.get(path))

    def invalid_fix_arguments(error):
        reason = f"tool arguments are invalid: {error.errors(include_url=False, include_context=False, include_input=False)}"
        ctx.rejected_fixes.append(reason)
        return f"Not recorded: {reason}"

    write_fix.handle_validation_error = invalid_fix_arguments
    explain_no_fix.handle_validation_error = invalid_fix_arguments
    available = {t.name: t for t in locals().values() if isinstance(t, BaseTool)}
    return [available[name] for name in names or TOOLS_FOR[actor]]
