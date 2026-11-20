from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from db import Base


class Participant(Base):
    __tablename__ = "participants"

    n: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    code: Mapped[str] = mapped_column(String(10), unique=True)  # P01, P02... or X01 for pilots
    status: Mapped[str] = mapped_column(String(20), default="active")  # active | complete | incomplete | withdrawn
    mode: Mapped[str] = mapped_column(String(10), default="team")  # the mode currently open


class ConsentRecord(Base):
    # Its existence means every consent statement was ticked. Deliberately no timestamp or other details.
    __tablename__ = "consent_records"

    participant_code: Mapped[str] = mapped_column(String(10), ForeignKey("participants.code"), primary_key=True)
    consent_version: Mapped[str] = mapped_column(String(50))
