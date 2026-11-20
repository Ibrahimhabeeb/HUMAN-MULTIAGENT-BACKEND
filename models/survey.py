from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from db import Base
from models.common import JSONData


class QuestionnaireItem(Base):
    # One question, copied from content/questionnaire.json at startup, so answers can be analysed in SQL.
    __tablename__ = "questionnaire_items"

    key: Mapped[str] = mapped_column(String(60), primary_key=True)
    number: Mapped[int] = mapped_column(Integer)
    section: Mapped[str] = mapped_column(String(200))
    asked_for: Mapped[str] = mapped_column(String(10))  # each_mode | team | once
    type: Mapped[str] = mapped_column(String(10))  # choice | scale | number | text
    text: Mapped[str] = mapped_column(Text)
    options: Mapped[list] = mapped_column(JSONData, default=list)  # choice questions, in order
    # The range of value_num, e.g. 1-5 for five ordered options ("Not applicable" isn't counted); empty for text.
    scale_min: Mapped[int | None] = mapped_column(Integer)
    scale_max: Mapped[int | None] = mapped_column(Integer)
    reverse_scored: Mapped[bool] = mapped_column(Boolean, default=False)  # negatively worded: higher is worse
    version: Mapped[str] = mapped_column(String(20))


class SurveyResponse(Base):
    # One questionnaire answer. The participant code is the only thing stored with it: no timestamps or other details.
    __tablename__ = "survey_responses"
    __table_args__ = (
        UniqueConstraint("participant_code", "condition", "item"),
        CheckConstraint("condition IN ('team', 'single', 'none')"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    participant_code: Mapped[str] = mapped_column(String(10), ForeignKey("participants.code"), index=True)
    condition: Mapped[str] = mapped_column(String(10))  # team | single (per-mode and team-only questions) | none
    item: Mapped[str] = mapped_column(String(60), ForeignKey("questionnaire_items.key"))  # the question's key
    value: Mapped[str | None] = mapped_column(Text, nullable=True)  # the answer as given; None if skipped
    # The answer as a number: the option's position for a choice (1 = first), or the number itself. None if skipped,
    # "Not applicable" or text.
    value_num: Mapped[int | None] = mapped_column(Integer)
