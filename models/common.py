from datetime import UTC, datetime
from uuid import uuid4


def utc_now() -> datetime:
    return datetime.now(UTC)


def as_utc(value: datetime) -> datetime:
    # SQLite drops the timezone, so values read back from the database are naive; they were stored as UTC.
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def new_id() -> str:
    return str(uuid4())
