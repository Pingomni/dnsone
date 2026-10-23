"""SQLAlchemy engine and sessions. Every connection runs in UTC with READ COMMITTED isolation."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings


@lru_cache(maxsize=1)
def get_engine() -> Engine:
    engine = create_engine(
        get_settings().database_url,
        pool_pre_ping=True,
        pool_recycle=1800,
        pool_size=10,
        max_overflow=10,
        isolation_level="READ COMMITTED",
    )

    @event.listens_for(engine, "connect")
    def _utc(dbapi_connection, _record):  # noqa: ANN001 - DB-API connection
        with dbapi_connection.cursor() as cursor:
            cursor.execute("SET time_zone = '+00:00'")

    return engine


@lru_cache(maxsize=1)
def _factory() -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(), autoflush=False, expire_on_commit=False)


def new_session() -> Session:
    return _factory()()


def get_db() -> Iterator[Session]:
    """FastAPI dependency: one session per request, rolled back if the handler raised."""
    db = new_session()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


@contextmanager
def session_scope() -> Iterator[Session]:
    """Session for jobs and the CLI: commits on success, rolls back on error."""
    db = new_session()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


class NamedLock:
    """MySQL advisory lock (GET_LOCK) held on its own connection.

    Serialises the zone and RPZ generators across API workers, timers and the CLI; with a
    shared MySQL in Phase 2 it also serialises across nodes when the name has no node in it.
    """

    def __init__(self, name: str, timeout: int = 60):
        self.name = name[:64]
        self.timeout = timeout
        self._conn = None

    def __enter__(self) -> "NamedLock":
        self._conn = get_engine().connect()
        got = self._conn.execute(text("SELECT GET_LOCK(:n, :t)"), {"n": self.name, "t": self.timeout}).scalar()
        if got != 1:
            self._conn.close()
            self._conn = None
            raise TimeoutError(f"Another job holds the lock {self.name!r}; try again shortly.")
        return self

    def __exit__(self, *exc) -> None:
        if self._conn is not None:
            try:
                self._conn.execute(text("SELECT RELEASE_LOCK(:n)"), {"n": self.name})
            finally:
                self._conn.close()
                self._conn = None
