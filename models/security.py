from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from db import Base
from models.common import utc_now

# The shared security state, one row per item, so it can be counted and compared with plain SQL (see the views in
# the migrations). Team mode only, except unit tests, which are kept for both modes. `ref` is the id participants
# and agents see (R1, V2, M1, T3); ids are never reused within a part (Workspace.state_counters).

SEVERITIES = "('Low', 'Medium', 'High', 'Critical')"


class StateRow:
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    ref: Mapped[str] = mapped_column(String(10))
    source: Mapped[str] = mapped_column(String(30))  # who proposed it: an agent, or "human" if added directly
    approval_id: Mapped[int | None] = mapped_column(ForeignKey("approvals.id"))  # the approval that put it here
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)


class AssumptionRecord(StateRow, Base):
    __tablename__ = "assumptions"
    __table_args__ = (UniqueConstraint("workspace_id", "ref"),)

    text: Mapped[str] = mapped_column(Text)


class RiskRecord(StateRow, Base):
    # A concern to keep in view, from the Threat Modeller; it has no status.
    __tablename__ = "risks"
    __table_args__ = (UniqueConstraint("workspace_id", "ref"), CheckConstraint(f"severity IN {SEVERITIES}"))

    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(10))
    cwe: Mapped[str | None] = mapped_column(String(20))
    owasp: Mapped[str | None] = mapped_column(String(100))
    stride: Mapped[str | None] = mapped_column(String(50))


class VulnerabilityRecord(StateRow, Base):
    # A weakness the Code Reviewer found (or the developer added), with the developer's decision on it.
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        UniqueConstraint("workspace_id", "ref"),
        CheckConstraint(f"severity IN {SEVERITIES}"),
        CheckConstraint("status IN ('accepted', 'rejected')"),
    )

    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(10))
    file: Mapped[str | None] = mapped_column(String(300))
    line: Mapped[int | None] = mapped_column(Integer)
    cwe: Mapped[str | None] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(10), default="accepted")


class MitigationRecord(StateRow, Base):
    # An approved fix for one vulnerability. The developer types the code; implemented once the code contains it.
    __tablename__ = "mitigations"
    __table_args__ = (UniqueConstraint("workspace_id", "ref"), CheckConstraint("status IN ('planned', 'implemented')"))

    vulnerability_id: Mapped[int] = mapped_column(ForeignKey("vulnerabilities.id"), index=True)
    description: Mapped[str] = mapped_column(Text)
    file: Mapped[str | None] = mapped_column(String(300))
    location: Mapped[str | None] = mapped_column(String(300))
    code: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(15), default="planned")


class UnitTestRecord(StateRow, Base):
    # One test function in the part's tests/ folder, with the outcome of the most recent run only. Finishing the part
    # runs the tests last, so after submission this is the final result. source: "system" for the task's own tests,
    # "human" for ones the developer wrote.
    __tablename__ = "unit_tests"
    __table_args__ = (
        UniqueConstraint("workspace_id", "ref"),
        UniqueConstraint("workspace_id", "file", "name"),
        CheckConstraint("status IN ('open', 'passed', 'failed')"),
    )

    file: Mapped[str] = mapped_column(String(300))
    name: Mapped[str] = mapped_column(String(200))
    status: Mapped[str] = mapped_column(String(10), default="open")  # open: not run in the latest run
    message: Mapped[str | None] = mapped_column(Text)  # why it failed in the most recent run
