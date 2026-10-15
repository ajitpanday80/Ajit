"""Database engine and session management (SQLAlchemy 2.x)."""
from __future__ import annotations

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, scoped_session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


_engine = None
_Session: scoped_session | None = None


def init_db(url: str, echo: bool = False):
    global _engine, _Session
    kwargs: dict = {"echo": echo, "future": True}
    if url.startswith("sqlite"):
        kwargs["connect_args"] = {"check_same_thread": False}
        if ":memory:" in url or url == "sqlite://":
            kwargs["poolclass"] = StaticPool
    else:
        kwargs["pool_pre_ping"] = True
        kwargs["pool_recycle"] = 1800
    _engine = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(_engine, "connect")
        def _fk(dbapi_conn, _):  # pragma: no cover - trivial
            dbapi_conn.execute("PRAGMA foreign_keys=ON")
    _Session = scoped_session(sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False))
    return _engine


def engine():
    assert _engine is not None, "init_db() not called"
    return _engine


def session():
    assert _Session is not None, "init_db() not called"
    return _Session()


def remove_session() -> None:
    if _Session is not None:
        _Session.remove()


def create_all() -> None:
    from backend import models  # noqa: F401  (register tables)
    Base.metadata.create_all(engine())
