from datetime import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db import Base
from models.common import utc_now


class Message(Base):
    # One chat message. Team mode has a thread per agent; single mode has one "assistant" thread.
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    participant_code: Mapped[str] = mapped_column(String(10), index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    mode: Mapped[str] = mapped_column(String(10))
    thread: Mapped[str] = mapped_column(String(30))  # facilitator | planner | ... | assistant
    role: Mapped[str] = mapped_column(String(10))  # human | agent
    content: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSON, default=dict)  # e.g. Facilitator suggestions, approval ids
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
