from datetime import datetime

from sqlalchemy import JSON, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from db import Base
from models.common import new_id, utc_now


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    name: Mapped[str] = mapped_column(String(100))
    user_id: Mapped[str | None] = mapped_column(String(100), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now)
    # path -> {"type": "folder"} or {"type": "file", "content": "..."}, same shape as the frontend
    files: Mapped[dict] = mapped_column(JSON, default=dict)
    security_state: Mapped[dict] = mapped_column(JSON, default=dict)
