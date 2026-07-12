"""Dialect-aware PostgreSQL advisory locks.

The upload byte-cap check (attachment_routes -> sum_active_bytes +
finalize_upload) reads a per-user total and then commits a new row in the
same transaction. Without serialization, N concurrent uploads for the SAME
user each read the same pre-upload total and all commit, overrunning the
per-user byte cap (up to MAX_ACTIVE_SLOTS_PER_USER x MAX_UPLOAD_BYTES).

A transaction-scoped PostgreSQL advisory lock keyed by the user serializes
those transactions: the second waiter blocks until the first commits, then
observes the first's bytes and correctly rejects if over cap.

SQLite (the test harness) serializes writes at the file/connection level and
cannot reproduce the race, and has no advisory-lock primitive, so the helper
is a no-op there. This keeps the SQLite-backed unit tests unchanged.
"""

from __future__ import annotations

from sqlalchemy import bindparam, func, select
from sqlalchemy.orm import Session

# Namespace for pg_advisory_xact_lock's two-int4 form. The first int4
# partitions the advisory-lock keyspace by feature so an unrelated future
# advisory lock that hashes a user id to the same second int4 cannot
# collide with this one. Value is arbitrary but fixed: "upload byte cap".
# Never reuse this constant for a different advisory-lock feature.
UPLOAD_BYTE_CAP_LOCK_NAMESPACE = 0x55424331  # "UBC1"


def acquire_user_upload_lock(session: Session, auth0_sub: str) -> bool:
    """Take the per-user upload byte-cap advisory lock for this transaction.

    On PostgreSQL, issues ``pg_advisory_xact_lock(namespace, hashtext(sub))``
    within the caller's active transaction (session_scope), so the lock is
    released automatically at commit/rollback. Concurrent uploads for the same
    user serialize on it. Returns True.

    On any other dialect (SQLite in tests), issues no SQL and returns False.

    ``auth0_sub`` is bound as a parameter; it is never interpolated into SQL.
    ``hashtext`` returns int4, which is the exact argument type of the
    two-int4 ``pg_advisory_xact_lock`` overload, so no cast is needed.
    """
    bind = session.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return False
    stmt = select(
        func.pg_advisory_xact_lock(
            UPLOAD_BYTE_CAP_LOCK_NAMESPACE,
            func.hashtext(bindparam("auth0_sub", value=auth0_sub)),
        )
    )
    session.execute(stmt).scalar_one()
    return True
