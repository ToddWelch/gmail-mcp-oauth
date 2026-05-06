"""Postgres-in-CI regression tests for mcp-gmail.

Why this module exists
----------------------
An earlier deploy of mcp-gmail shipped a production crash: SQLAlchemy
2.0's default driver for a bare ``postgresql://`` URL is psycopg2, but
this service installs psycopg v3 only (see ``pyproject.toml``:
``psycopg[binary]``).
On first connect, the engine raised ``ModuleNotFoundError: No module
named 'psycopg2'``. The hotfix added ``_normalize_database_url`` in
``mcp_gmail.db`` and ``mcp_gmail.migrations.env`` to rewrite bare
``postgresql://`` URLs to ``postgresql+psycopg://`` before they reach
SQLAlchemy.

The original CI lane could not catch this bug class: tests ran against
SQLite in-memory and never invoked ``alembic upgrade head`` against a
real Postgres. This module closes the gap.

Bare-scheme contract (non-negotiable)
-------------------------------------
Every test here uses the bare ``postgresql://`` URL form (no
``+psycopg``, no ``+psycopg2``, no ``+asyncpg``). That is what Railway
injects in production. Rewriting the test fixtures to a driver-explicit
form silently disables the regression guard. If a future engineer is
tempted to "fix" the URL here because the helper rewrites it anyway:
that helper is exactly what is being tested. Don't.

What is bound by these tests
----------------------------
1. ``test_alembic_upgrade_against_real_postgres`` proves the Alembic
   path (``mcp_gmail/migrations/env.py``) honors the bare-scheme
   contract end-to-end against real Postgres.
2. ``test_lowercase_email_check_constraint_enforced`` proves the
   migration produced the production schema, not just any schema:
   the Postgres-only CHECK constraint on ``account_email`` actually
   enforces lowercase.
3. ``test_init_engine_against_real_postgres_with_bare_scheme`` proves
   the runtime path (``mcp_gmail.db.init_engine``) honors the
   bare-scheme contract too. Without this test, a future PR could
   remove the ``_normalize_database_url`` call from ``init_engine``,
   keep the env.py call, and ship a service that boots in CI but
   crashes on first request in production.
4. ``test_psycopg2_must_not_be_importable`` guards the dependency
   boundary. If anyone adds ``psycopg2-binary`` to ``pyproject.toml``,
   a broken env.py emitting bare ``postgresql://`` would default to
   psycopg2 and pass CI silently. This test fails loudly if that
   happens.

Skip gating
-----------
The whole module is gated on ``MCPGMAIL_POSTGRES_TEST_URL``. Local
developers running ``pytest`` without a Postgres available are not
forced into the integration lane; CI sets the env var and runs the
full suite.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from mcp_gmail import db as db_module

# Module-level skip: only run when the CI lane provides a real Postgres.
pytestmark = pytest.mark.skipif(
    not os.environ.get("MCPGMAIL_POSTGRES_TEST_URL"),
    reason=(
        "Postgres-backed integration tests require MCPGMAIL_POSTGRES_TEST_URL "
        "(set by the CI workflow's mcp-gmail job). Skipped in the default "
        "developer pytest run, where SQLite-in-memory remains the unit suite."
    ),
)


@pytest.fixture(scope="module")
def postgres_url() -> str:
    """Return the bare-scheme Postgres URL the CI workflow injected.

    The URL must remain bare (``postgresql://...``, no driver suffix).
    See module docstring for why; do not "normalize" it before yielding.
    """
    url = os.environ["MCPGMAIL_POSTGRES_TEST_URL"]
    # Belt-and-suspenders: if a future contributor sets the env var to a
    # driver-explicit form, fail with a loud message rather than silently
    # neutering the regression guard.
    assert url.startswith("postgresql://"), (
        "MCPGMAIL_POSTGRES_TEST_URL must use the bare 'postgresql://' scheme "
        "(no '+psycopg' or other driver suffix). The whole point of this lane "
        "is to exercise the production URL shape. Got: %r" % url
    )
    return url


@pytest.fixture(scope="module")
def postgres_migrated(postgres_url: str) -> str:
    """Run ``alembic upgrade head`` against ``postgres_url`` and yield it.

    Module-scoped so two tests share one migration run instead of
    paying the cost twice. Both tests that need schema take this
    fixture by parameter; pytest then guarantees ordering (schema
    exists before either test body runs).

    Implementation note: we shell out to the ``alembic`` CLI rather
    than calling ``alembic.command.upgrade`` in-process. Reason:
    ``alembic.ini`` declares logging in its ``[loggers]`` section, and
    Alembic's env.py calls ``fileConfig(config.config_file_name)``
    which by default sets ``disable_existing_loggers=True``. Running
    the migration in-process inside a long-lived pytest run would
    silently disable the ``mcp_gmail`` logger for the rest of the
    session and break unrelated tests that use ``caplog`` against
    that logger. The CLI invocation runs in a subprocess, so its
    logging config dies with the subprocess. This also more faithfully
    mirrors production: the Dockerfile CMD literally runs
    ``alembic upgrade head`` as a shell command before uvicorn.

    Teardown drops the two domain tables and ``alembic_version`` so
    re-runs of the test module on the same Postgres instance start
    clean. ``DROP TABLE IF EXISTS`` is safe to issue blindly.
    """
    import subprocess
    import sys
    from pathlib import Path

    # alembic.ini lives at mcp-gmail/alembic.ini. This file is at
    # mcp-gmail/tests/test_postgres_migration.py, so go up one level.
    mcp_gmail_root = Path(__file__).resolve().parent.parent
    alembic_ini = mcp_gmail_root / "alembic.ini"

    # env.py reads DATABASE_URL from the environment. Pass it through
    # to the subprocess. Bare scheme on purpose.
    env = {**os.environ, "DATABASE_URL": postgres_url}

    # Use `python -m alembic` rather than the bare `alembic` script so
    # we are guaranteed to invoke the alembic installed in the same
    # interpreter that is running pytest. ``cwd=mcp_gmail_root`` so
    # alembic.ini's relative ``script_location = migrations`` resolves
    # against the right directory.
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(alembic_ini), "upgrade", "head"],
        cwd=str(mcp_gmail_root),
        env=env,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        # Surface alembic's own error so failures here are debuggable
        # rather than mysterious.
        raise RuntimeError(
            "alembic upgrade head failed (exit %s).\n"
            "STDOUT:\n%s\nSTDERR:\n%s" % (result.returncode, result.stdout, result.stderr)
        )

    try:
        yield postgres_url
    finally:
        # Teardown: drop the schema so re-runs against a persistent
        # Postgres start clean. CI's service container is ephemeral so
        # this is mostly belt-and-suspenders; locally it matters.
        # Use the same normalization the production path does so we
        # don't accidentally bind to psycopg2 inside teardown.
        teardown_engine = create_engine(
            db_module._normalize_database_url(postgres_url),
            future=True,
            pool_pre_ping=True,
        )
        try:
            with teardown_engine.begin() as conn:
                conn.execute(text("DROP TABLE IF EXISTS oauth_state_nonces CASCADE"))
                conn.execute(text("DROP TABLE IF EXISTS gmail_oauth_tokens CASCADE"))
                conn.execute(text("DROP TABLE IF EXISTS alembic_version CASCADE"))
        finally:
            teardown_engine.dispose()


def test_alembic_upgrade_against_real_postgres(postgres_migrated: str) -> None:
    """Alembic migration runs end-to-end against Postgres with a bare-scheme URL.

    The fixture ran ``alembic upgrade head`` already; this test
    asserts the result. We reflect the schema and confirm the two
    domain tables plus the lowercase CHECK exist, which together
    prove that:

    1. ``mcp_gmail/migrations/env.py`` resolved the bare-scheme URL
       to a working driver (regression guard against the original
       ImportError bug).
    2. The migration produced the schema we expect.
    """
    # Use the same normalization the production path uses so this
    # assertion is about migration output, not driver wiring.
    engine = create_engine(
        db_module._normalize_database_url(postgres_migrated),
        future=True,
        pool_pre_ping=True,
    )
    try:
        inspector = inspect(engine)
        tables = set(inspector.get_table_names())
        assert "gmail_oauth_tokens" in tables, (
            "alembic upgrade head did not create gmail_oauth_tokens. "
            "Inspector saw: %r" % sorted(tables)
        )
        assert "oauth_state_nonces" in tables, (
            "alembic upgrade head did not create oauth_state_nonces. "
            "Inspector saw: %r" % sorted(tables)
        )

        # Confirm the lowercase CHECK constraint shipped, by name. The
        # behavioral test below will exercise it; this is just a
        # structural sanity check that the migration was actually
        # applied (not a no-op).
        check_names = {c["name"] for c in inspector.get_check_constraints("gmail_oauth_tokens")}
        assert "ck_gmail_tokens_email_lowercase" in check_names, (
            "Expected CHECK 'ck_gmail_tokens_email_lowercase' on "
            "gmail_oauth_tokens. Found: %r" % sorted(check_names)
        )
    finally:
        engine.dispose()


def test_lowercase_email_check_constraint_enforced(postgres_migrated: str) -> None:
    """The Postgres CHECK on account_email rejects mixed-case writes.

    Independent of any application code path that might lowercase the
    value first (e.g. ``token_store.upsert_token``). The DB itself
    enforces the contract. SQLite does not parse this CHECK with the
    same semantics, which is why this assertion only runs in the
    Postgres lane.
    """
    engine = create_engine(
        db_module._normalize_database_url(postgres_migrated),
        future=True,
        pool_pre_ping=True,
    )
    try:
        with pytest.raises(IntegrityError):
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO gmail_oauth_tokens "
                        "(auth0_sub, account_email, encrypted_refresh_token, "
                        " scope, created_at, updated_at) "
                        "VALUES (:sub, :email, :tok, :scope, NOW(), NOW())"
                    ),
                    {
                        "sub": "auth0|check-test",
                        # Mixed case on purpose. The CHECK should reject this.
                        "email": "Mixed.Case@Example.COM",
                        "tok": b"not-real-ciphertext",
                        "scope": "https://www.googleapis.com/auth/gmail.readonly",
                    },
                )
    finally:
        engine.dispose()


def test_init_engine_against_real_postgres_with_bare_scheme(postgres_url: str) -> None:
    """Runtime engine path (``init_engine``) honors the bare-scheme contract.

    This is the regression guard that binds the FastAPI lifespan path to the
    same regression class the alembic test guards. If a future PR
    removes the ``_normalize_database_url`` call from
    ``mcp_gmail.db.init_engine`` (line ~137 at time of writing), this
    test fails with a ModuleNotFoundError when ``engine.connect()``
    tries to load psycopg2.

    The test runs ``SELECT 1`` rather than just constructing the
    engine because ``create_engine`` is lazy: it does not import the
    driver until the first connection is opened. Skipping the
    connect-and-execute step would skip the actual binding check.
    """
    # Reset module state so this test owns the engine. The autouse env
    # fixture in conftest.py also calls reset_for_tests, but doing it
    # here makes the precondition explicit at the test boundary.
    db_module.reset_for_tests()

    engine = db_module.init_engine(postgres_url)
    try:
        # The URL the engine was bound to must NOT be the bare scheme.
        # The helper should have rewritten it to postgresql+psycopg.
        # If a future change makes init_engine accept the bare scheme
        # verbatim, SQLAlchemy will resolve to psycopg2 and the
        # subsequent connect() will raise ModuleNotFoundError.
        bound_url = str(engine.url)
        assert not bound_url.startswith("postgresql://"), (
            "init_engine kept the bare scheme. _normalize_database_url "
            "appears to have been bypassed; SQLAlchemy will try to "
            "resolve psycopg2 on connect. Bound URL: %r" % bound_url
        )
        assert bound_url.startswith("postgresql+"), (
            "init_engine bound an unexpected URL shape: %r" % bound_url
        )

        # Decisive proof: actually open a connection and execute SQL.
        # If the binding is broken, this is the line that raises
        # ModuleNotFoundError (psycopg2). If the binding is correct,
        # we get a 1.
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1")).scalar_one()
        assert result == 1
    finally:
        # Tear down the cached engine so other tests get a fresh one.
        db_module.reset_for_tests()


def test_psycopg2_must_not_be_importable() -> None:
    """Defensive guard against psycopg2-binary creeping into the deps.

    Why this matters: if a future PR adds ``psycopg2-binary`` to
    ``pyproject.toml``, a broken env.py emitting bare
    ``postgresql://`` (which SQLAlchemy resolves to psycopg2) would
    pass CI. The whole regression test silently becomes a no-op.

    Failing this test is a forcing function: a contributor who needs
    psycopg2 for some legitimate reason has to either (a) remove this
    test with a real justification in the PR description, or (b)
    explain why the bare-scheme contract should change. Either is
    fine; silently flipping the dependency without flagging is not.

    Gated on ``MCPGMAIL_POSTGRES_TEST_URL`` (via the module-level
    pytestmark) so developers running pytest locally without Postgres
    don't see this fail unrelatedly.
    """
    with pytest.raises(ImportError):
        import psycopg2  # noqa: F401
