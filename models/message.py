from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from db import Base
from models.common import JSONData, utc_now


class Message(Base):
    # One chat message. Team mode is one "team" conversation; single mode is one "assistant" conversation.
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    participant_code: Mapped[str] = mapped_column(String(10), ForeignKey("participants.code"), index=True)
    workspace_id: Mapped[int] = mapped_column(ForeignKey("workspaces.id"), index=True)
    mode: Mapped[str] = mapped_column(String(10))
    thread: Mapped[str] = mapped_column(String(30))  # team | assistant
    role: Mapped[str] = mapped_column(String(10))  # human | agent | system (a notice for the human)
    content: Mapped[str] = mapped_column(Text)
    data: Mapped[dict] = mapped_column(JSONData, default=dict)  # e.g. which agent wrote it, its route, approval ids
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
