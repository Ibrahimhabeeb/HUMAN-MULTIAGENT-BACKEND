from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from config import get_settings

HERE = Path(__file__).resolve().parent


class Base(DeclarativeBase):
    pass


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite:///"):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    # FastAPI may handle a request on a different thread from the one that opened the connection.
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args, pool_pre_ping=not url.startswith("sqlite"))


engine = make_engine(get_settings().database_url)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def _migrate(bind: Engine) -> None:
    # PostgreSQL is set up by the Alembic migrations (migrations/versions): the tables and the analysis views.
    from alembic import command
    from alembic.config import Config

    config = Config(str(HERE / "alembic.ini"))
    config.set_main_option("script_location", str(HERE / "migrations"))
    with bind.begin() as connection:
        config.attributes["connection"] = connection
        command.upgrade(config, "head")


def init_db(bind: Engine = engine) -> None:
    import models  # noqa: F401  (registers the tables on Base)

    if bind.dialect.name == "postgresql":
        _migrate(bind)
    else:  # the tests' throwaway SQLite (or a local SQLite file): just the tables
        Base.metadata.create_all(bind)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
