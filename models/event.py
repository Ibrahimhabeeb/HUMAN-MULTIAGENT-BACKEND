from datetime import datetime

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from db import Base
from models.common import utc_now


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    participant_code: Mapped[str] = mapped_column(String(10), index=True)
    mode: Mapped[str | None] = mapped_column(String(10))  # team | single, when the event happened in a mode
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    type: Mapped[str] = mapped_column(String(50), index=True)
    actor: Mapped[str] = mapped_column(String(30))  # human | system | an agent's name
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
