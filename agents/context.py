from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from models import Workspace
from schemas.security_state import SecurityState
from services import approvals, state_service, workspace

MAX_LISTING_CHARS = 60_000


@dataclass
class Proposal:
    actor: str
    action_type: str
    proposal: dict


@dataclass
class Earlier:
    # A proposal from an earlier reply that the developer hasn't approved: still waiting, or rejected.
    id: int
    actor: str
    action_type: str
    status: str  # pending | rejected
    proposal: dict


@dataclass
class AgentContext:
    # What an agent sees during one run: a snapshot of the files and of the approved security state.
    # Its proposals are collected here and only saved as approval requests after the run.
    files: dict[str, str]
    state: SecurityState | None  # team mode only
    earlier: list[Earlier] = field(default_factory=list)  # team mode only
    proposals: list[Proposal] = field(default_factory=list)
    target_vulnerability: str | None = None  # automatic follow-ups stay focused on the newly approved finding

    @property
    def task_description(self) -> str:
        return self.files.get("README.md", "(no task description)")


def build_context(ws: Workspace) -> AgentContext:
    tree = workspace.list_files(ws)
    files = {path: node["content"] for path, node in tree.items() if node["type"] == "file"}
    return AgentContext(files=files, state=state_service.load(ws) if ws.mode == "team" else None)


def earlier_proposals(db: Session, ws: Workspace) -> list[Earlier]:
    return [
        Earlier(a.id, a.actor, a.action_type, a.status, a.proposal)
        for a in approvals.list_approvals(db, ws)
        if a.status in ("pending", "rejected")
    ]


def numbered(content: str) -> str:
    return "\n".join(f"{n:>4}| {line}" for n, line in enumerate(content.splitlines(), start=1))


def code_listing(files: dict[str, str]) -> str:
    parts, size = [], 0
    for path in sorted(files):
        block = f"### {path}\n```\n{numbered(files[path])}\n```"
        if size + len(block) > MAX_LISTING_CHARS:
            parts.append(f"(listing truncated; read the remaining files with read_file, starting at {path})")
            break
        parts.append(block)
        size += len(block)
    return "\n\n".join(parts)
