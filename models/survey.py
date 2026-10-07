from sqlalchemy import Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from db import Base


class SurveyResponse(Base):
    # One questionnaire answer. The participant code is the only thing stored with it: no timestamps or other details.
    __tablename__ = "survey_responses"
    __table_args__ = (UniqueConstraint("participant_code", "condition", "item"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    participant_code: Mapped[str] = mapped_column(String(10), index=True)
    condition: Mapped[str] = mapped_column(String(10))  # team | single (per-mode and team-only questions) | none
    item: Mapped[str] = mapped_column(String(60))  # the question's key
    value: Mapped[str | None] = mapped_column(Text, nullable=True)  # None if skipped
