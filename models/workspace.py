from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db import Base
from models.common import JSONData, utc_now


class Workspace(Base):
    # One independent attempt per mode, in workspaces/<code>_<task_id>_<mode>/.
    __tablename__ = "workspaces"
    __table_args__ = (UniqueConstraint("participant_code", "mode"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    participant_code: Mapped[str] = mapped_column(String(10), ForeignKey("participants.code"), index=True)
    mode: Mapped[str] = mapped_column(String(10))  # team | single
    task_id: Mapped[str] = mapped_column(String(10))  # the same chosen task (A or B) in both modes
    part: Mapped[int] = mapped_column(Integer)  # 1 or 2
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    done_reason: Mapped[str | None] = mapped_column(String(20))
    # The last id number used per security-state category, so ids are never reused; the items are in models/security.py.
    state_counters: Mapped[dict] = mapped_column(JSONData, default=dict)
    notes: Mapped[str] = mapped_column(Text, default="")  # single mode only
