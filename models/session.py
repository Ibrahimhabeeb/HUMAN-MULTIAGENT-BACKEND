from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from db import Base


class StudySession(Base):
    __tablename__ = "study_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    participant_code: Mapped[str] = mapped_column(ForeignKey("participants.code"), unique=True)
