from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from db import Base
from models.common import utc_now


class Approval(Base):
    # Every change an agent proposes waits here until the human decides. Decided once only.
    __tablename__ = "approvals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    participant_code: Mapped[str] = mapped_column(String(10), index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    mode: Mapped[str] = mapped_column(String(10))
    actor: Mapped[str] = mapped_column(String(30))  # the agent that proposed it
    action_type: Mapped[str] = mapped_column(String(30))
    proposal: Mapped[dict] = mapped_column(JSON)  # as proposed
    final_proposal: Mapped[dict | None] = mapped_column(JSON)  # as applied; empty if rejected
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending | approved | rejected
    requested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    result: Mapped[dict | None] = mapped_column(JSON)  # e.g. {"item_id": "R3"} or {"path": "tests/test_x.py"}
