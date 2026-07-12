"""Dialect-aware advisory lock: db_locks.acquire_user_upload_lock.

Targets: mcp-gmail/src/mcp_gmail/db_locks.py

The helper serializes a user's concurrent upload byte-cap transactions on
PostgreSQL via a transaction-scoped advisory lock, and no-ops on SQLite
(the test harness), which has no advisory-lock primitive and serializes
writes anyway. These tests assert both branches of the dialect guard.

A true multi-connection race (two real DB connections uploading for the
same user at once, proving the cap holds) requires a live PostgreSQL and
is out of scope for these single-process, SQLite-backed unit tests; it is
covered by the design of pg_advisory_xact_lock rather than asserted here.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from sqlalchemy.dialects import postgresql

from mcp_gmail.db_locks import UPLOAD_BYTE_CAP_LOCK_NAMESPACE, acquire_user_upload_lock


def test_sqlite_dialect_is_a_noop(in_memory_session):
    """On SQLite the helper issues no SQL and returns False."""
    result = acquire_user_upload_lock(in_memory_session, "auth0|alice")
    assert result is False


def test_postgresql_dialect_issues_advisory_lock():
    """On PostgreSQL the helper executes pg_advisory_xact_lock(namespace, hashtext(sub))."""
    # Spy session whose bind reports the postgresql dialect. Capture the
    # statement handed to execute() so we can compile and inspect it.
    session = MagicMock()
    session.get_bind.return_value.dialect.name = "postgresql"

    result = acquire_user_upload_lock(session, "auth0|alice")

    assert result is True
    session.execute.assert_called_once()
    stmt = session.execute.call_args.args[0]
    compiled = stmt.compile(dialect=postgresql.dialect())
    sql = str(compiled)
    # Transaction-scoped lock (auto-released at commit/rollback), namespaced.
    assert "pg_advisory_xact_lock" in sql
    assert "hashtext" in sql
    # auth0_sub is a bound parameter, never interpolated into the SQL text.
    assert "auth0|alice" not in sql
    assert "auth0_sub" in compiled.params
    assert compiled.params["auth0_sub"] == "auth0|alice"
    # The fixed feature namespace is the first lock argument.
    assert UPLOAD_BYTE_CAP_LOCK_NAMESPACE in compiled.params.values()


def test_none_bind_is_a_noop():
    """A session with no bound engine no-ops rather than raising."""
    session = MagicMock()
    session.get_bind.return_value = None

    assert acquire_user_upload_lock(session, "auth0|alice") is False
    session.execute.assert_not_called()
