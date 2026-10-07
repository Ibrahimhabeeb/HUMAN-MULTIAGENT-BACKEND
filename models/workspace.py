from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db import Base
from models.common import utc_now


class Workspace(Base):
    # One per participant per mode. The files themselves live on disk in workspaces/<code>_<task_id>/.
    __tablename__ = "workspaces"
    __table_args__ = (UniqueConstraint("participant_code", "mode"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    participant_code: Mapped[str] = mapped_column(String(10), index=True)
    mode: Mapped[str] = mapped_column(String(10))  # team | single
    task_id: Mapped[str] = mapped_column(String(10))  # A for the first mode used, B for the second
    part: Mapped[int] = mapped_column(Integer)  # 1 or 2
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    done_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    done_reason: Mapped[str | None] = mapped_column(String(20))  # done | time_limit
    security_state: Mapped[dict] = mapped_column(JSON, default=dict)  # team mode only
    notes: Mapped[str] = mapped_column(Text, default="")  # single mode only
