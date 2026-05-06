"""SQLAlchemy 2.0 engine and session factory.

This service owns its OAuth-token data directly because refresh
tokens are sensitive enough to belong in a database with its own
security boundary, separate from any other service that may share
the same identity provider.

Engine model
------------
One module-level engine, lazily initialized. Connection pool defaults
are kept conservative: pool_size=5, max_overflow=5. The service handles
one request at a time per replica (Python async with synchronous DB
calls inside short-lived sessions); 10 connections is plenty.

Session model
-------------
Each request opens a session, does its work, commits or rolls back,
and closes. There is no module-level Session.

We use synchronous SQLAlchemy (not asyncpg/AsyncSession) to keep the
codebase boringly compatible with Alembic, fixtures, and the broader
Python data tooling ecosystem. Inside FastAPI's async event loop, the
synchronous DB calls run on a worker thread (FastAPI handles this for
sync dependencies). Total request budget is well under what httpx +
uvicorn can absorb.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


class Base(DeclarativeBase):
    """SQLAlchemy 2.0 declarative base for all ORM models in this service."""


_engine: Engine | None = None
_SessionFactory: sessionmaker[Session] | None = None


_PSYCOPG_DRIVER = "postgresql+psycopg"

# Schemes we leave alone. SQLAlchemy's default for a bare `postgresql://`
# is psycopg2, but psycopg2 is intentionally NOT a dependency of this
# service: pyproject.toml installs psycopg v3 only. Anything that
# already names an explicit driver (psycopg, psycopg2, asyncpg, ...) is
# the operator's deliberate choice and we honor it.
_EXPLICIT_PG_DRIVER_PREFIXES: tuple[str, ...] = (
    "postgresql+psycopg://",
    "postgresql+psycopg2://",
    "postgresql+asyncpg://",
    "postgresql+pg8000://",
    "postgresql+psycopg2cffi://",
)


def _normalize_database_url(database_url: str) -> str:
    """Rewrite Postgres URL schemes to bind SQLAlchemy to psycopg v3.

    Background
    ----------
    The mcp-gmail service ships with `psycopg[binary]>=3.2` and does
    NOT depend on psycopg2. SQLAlchemy 2.0's default driver for a bare
    `postgresql://` (or the legacy `postgres://` form some providers
    emit) is psycopg2, so without rewriting the URL the engine raises
    `ModuleNotFoundError: No module named 'psycopg2'` when the first
    connection is opened. This helper normalizes both bare schemes to
    the explicit `postgresql+psycopg://` form so SQLAlchemy resolves
    psycopg v3 and the driver mismatch cannot occur.

    Behavior
    --------
    - `postgresql://...`               -> `postgresql+psycopg://...`
    - `postgres://...`                 -> `postgresql+psycopg://...`
    - `postgresql+<driver>://...`      -> unchanged (operator chose a driver)
    - `sqlite:...`, anything else      -> unchanged (no Postgres rewrite)
    - `""` or no-scheme strings        -> unchanged (let SQLAlchemy raise
      its own error rather than masking it here)

    The substring after the rewritten scheme is preserved byte-exact so
    URL-encoded passwords (e.g. `p%40ss`) survive untouched. We use a
    prefix `str.replace` rather than `urllib.parse.urlsplit/urlunsplit`
    on purpose: the round-trip parsers have historical edge cases
    around password URL-encoding that this function is meant to dodge.

    Case sensitivity
    ----------------
    Match is case-sensitive. Operators who type `Postgresql://` get the
    SQLAlchemy default behavior (and thus the original error). Standard
    convention is lowercase scheme; hard-baking that contract is safer
    than silently second-guessing operator input.

    Whitespace
    ----------
    Caller is responsible for stripping whitespace. This helper does
    NOT call `.strip()`. The two existing call sites
    (`init_engine` in this module and `_database_url` in
    `migrations/env.py`) handle stripping at their boundaries.

    Logging
    -------
    This helper does NOT log the URL at any level. Production URLs
    contain the database password; logging the input or output here
    would be a credential leak.
    """
    # Already names a driver explicitly; leave it.
    if database_url.startswith(_EXPLICIT_PG_DRIVER_PREFIXES):
        return database_url
    if database_url.startswith("postgresql://"):
        return _PSYCOPG_DRIVER + database_url[len("postgresql") :]
    if database_url.startswith("postgres://"):
        return _PSYCOPG_DRIVER + database_url[len("postgres") :]
    # Anything else (sqlite, mysql+pymysql, empty string, no scheme):
    # leave alone so SQLAlchemy surfaces a clean error if it is wrong.
    return database_url


def init_engine(database_url: str) -> Engine:
    """Create the engine and session factory. Idempotent across calls.

    Called from server.py lifespan startup. The Alembic env.py also
    initializes its own engine independently, so this function is the
    runtime path only, not the migration path.
    """
    global _engine, _SessionFactory
    if _engine is not None:
        return _engine

    # Bind SQLAlchemy to psycopg v3 (the driver we actually ship) for
    # bare `postgresql://` / `postgres://` URLs. See the helper docstring
    # for the full rationale. Idempotent for already-qualified URLs.
    database_url = _normalize_database_url(database_url)

    # `future=True` is the default in SQLAlchemy 2.0 but stating it
    # explicitly documents intent and survives library upgrades.
    #
    # SQLite uses a single-connection pool (SingletonThreadPool by
    # default) that does not accept `pool_size` / `max_overflow`. We
    # only configure those kwargs for the production-class drivers
    # where they apply. Tests run against SQLite in-memory and would
    # otherwise crash inside SQLAlchemy on the unknown kwargs.
    kwargs: dict[str, object] = {
        "future": True,
        "pool_pre_ping": True,  # cheap reconnect after Postgres restart
    }
    if not database_url.startswith("sqlite"):
        kwargs["pool_size"] = 5
        kwargs["max_overflow"] = 5

    _engine = create_engine(database_url, **kwargs)
    _SessionFactory = sessionmaker(bind=_engine, autoflush=False, expire_on_commit=False)
    return _engine


def get_engine() -> Engine:
    """Return the initialized engine. Raises if init_engine was not called."""
    if _engine is None:
        raise RuntimeError("init_engine() must be called before get_engine()")
    return _engine


@contextmanager
def session_scope() -> Iterator[Session]:
    """Yield a session that commits on clean exit, rolls back on exception.

    Standard SQLAlchemy unit-of-work pattern. Callers should NOT call
    session.commit() inside the block; the context manager handles it.
    Callers MAY call session.flush() to force SQL execution mid-block
    when the next operation depends on a generated primary key.
    """
    if _SessionFactory is None:
        raise RuntimeError("init_engine() must be called before session_scope()")
    session = _SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def reset_for_tests() -> None:
    """Test helper: drop the cached engine + factory so each test reinitializes."""
    global _engine, _SessionFactory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionFactory = None
