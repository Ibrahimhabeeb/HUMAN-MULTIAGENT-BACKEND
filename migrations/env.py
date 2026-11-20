"""Alembic: versioned changes to the PostgreSQL database (tables and the analysis views).

The app runs these itself at startup (db.init_db). By hand, from backend/:
    uv run alembic upgrade head          # bring the database up to date
    uv run alembic revision --autogenerate -m "what changed"   # after changing the models
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

import models  # noqa: F401  (registers the tables on Base)
from config import get_settings
from db import Base

config = context.config
target_metadata = Base.metadata

# Only when run from the command line: inside the app, uvicorn's logging stays as it is.
if config.config_file_name is not None and "connection" not in config.attributes:
    fileConfig(config.config_file_name)


def run_migrations_offline() -> None:
    # Writes the SQL instead of running it: alembic upgrade head --sql
    context.configure(
        url=get_settings().database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connection = config.attributes.get("connection")  # the app passes its own (db.init_db)
    if connection is not None:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
        return
    engine = create_engine(get_settings().database_url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
