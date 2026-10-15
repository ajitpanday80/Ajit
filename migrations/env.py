import os

from alembic import context
from sqlalchemy import create_engine

from backend import models  # noqa: F401  (register tables)
from backend.db import Base

target_metadata = Base.metadata


def _url() -> str:
    return os.environ.get("DATABASE_URL", "sqlite:///msp_dev.db")


def run_migrations_offline():
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True, compare_type=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    engine = create_engine(_url())
    with engine.connect() as conn:
        context.configure(connection=conn, target_metadata=target_metadata, compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
