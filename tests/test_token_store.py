"""Token store schema, CRUD, and per-key asyncio.Lock primitives.

Targets: mcp-gmail/src/mcp_gmail/token_store.py:upsert_token
Targets: mcp-gmail/src/mcp_gmail/token_store.py:get_token
Targets: mcp-gmail/src/mcp_gmail/token_store.py:get_decrypted_refresh_token
Targets: mcp-gmail/src/mcp_gmail/token_store.py:mark_used
Targets: mcp-gmail/src/mcp_gmail/token_store.py:soft_revoke
Targets: mcp-gmail/src/mcp_gmail/token_store.py:get_refresh_lock
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.fernet import Fernet

from mcp_gmail.crypto import decrypt
from mcp_gmail.token_store import (
    GmailOAuthToken,
    get_decrypted_refresh_token,
    get_refresh_lock,
    get_token,
    mark_used,
    soft_revoke,
    upsert_token,
)


@pytest.fixture
def encryption_key() -> str:
    return Fernet.generate_key().decode("ascii")


def test_upsert_creates_row(in_memory_session, encryption_key):
    row = upsert_token(
        in_memory_session,
        auth0_sub="auth0|abc123",
        account_email="user@example.com",
        refresh_token="1//refresh-secret",
        scope="https://mail.google.com/",
        encryption_key=encryption_key,
    )
    assert row.id is not None
    assert row.auth0_sub == "auth0|abc123"
    assert row.account_email == "user@example.com"
    # Plaintext never touches the row.
    assert b"refresh-secret" not in bytes(row.encrypted_refresh_token)
    # Round-trips correctly.
    assert decrypt(row.encrypted_refresh_token, encryption_key) == "1//refresh-secret"


def test_upsert_lowercases_email(in_memory_session, encryption_key):
    row = upsert_token(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="MixedCase@Example.com",
        refresh_token="rt",
        scope="s",
        encryption_key=encryption_key,
    )
    assert row.account_email == "mixedcase@example.com"


def test_upsert_updates_existing(in_memory_session, encryption_key):
    upsert_token(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="user@example.com",
        refresh_token="rt-old",
        scope="old",
        encryption_key=encryption_key,
    )
    row = upsert_token(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="user@example.com",
        refresh_token="rt-new",
        scope="new",
        encryption_key=encryption_key,
        google_sub="google-user-id",
    )
    assert decrypt(row.encrypted_refresh_token, encryption_key) == "rt-new"
    assert row.scope == "new"
    assert row.google_sub == "google-user-id"
    # Re-link clears revoked_at if it was set.
    assert row.revoked_at is None


def test_upsert_revoke_then_relink_clears_revoked(in_memory_session, encryption_key):
    row = upsert_token(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="user@example.com",
        refresh_token="rt1",
        scope="s",
        encryption_key=encryption_key,
    )
    soft_revoke(in_memory_session, row)
    assert row.revoked_at is not None
    relinked = upsert_token(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="user@example.com",
        refresh_token="rt2",
        scope="s",
        encryption_key=encryption_key,
    )
    assert relinked.revoked_at is None


def test_upsert_unique_per_user_and_email(in_memory_session, encryption_key):
    """Different humans linking the same Gmail address get distinct rows.

    The unique constraint is on the pair (auth0_sub, account_email),
    not account_email alone. Two distinct auth0_sub values for the
    same address must coexist.
    """
    row1 = upsert_token(
        in_memory_session,
        auth0_sub="auth0|user-1",
        account_email="shared@example.com",
        refresh_token="rt1",
        scope="s",
        encryption_key=encryption_key,
    )
    row2 = upsert_token(
        in_memory_session,
        auth0_sub="auth0|user-2",
        account_email="shared@example.com",
        refresh_token="rt2",
        scope="s",
        encryption_key=encryption_key,
    )
    assert row1.id != row2.id


def test_upsert_rejects_empty_inputs(in_memory_session, encryption_key):
    with pytest.raises(ValueError):
        upsert_token(
            in_memory_session,
            auth0_sub="",
            account_email="user@example.com",
            refresh_token="rt",
            scope="s",
            encryption_key=encryption_key,
        )
    with pytest.raises(ValueError):
        upsert_token(
            in_memory_session,
            auth0_sub="auth0|abc",
            account_email="",
            refresh_token="rt",
            scope="s",
            encryption_key=encryption_key,
        )
    with pytest.raises(ValueError):
        upsert_token(
            in_memory_session,
            auth0_sub="auth0|abc",
            account_email="   ",
            refresh_token="rt",
            scope="s",
            encryption_key=encryption_key,
        )


def test_get_token_lowercases(in_memory_session, encryption_key):
    upsert_token(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="user@example.com",
        refresh_token="rt",
        scope="s",
        encryption_key=encryption_key,
    )
    found = get_token(in_memory_session, auth0_sub="auth0|abc", account_email="USER@Example.com")
    assert found is not None
    assert found.account_email == "user@example.com"


def test_get_token_returns_none_when_missing(in_memory_session):
    assert get_token(in_memory_session, auth0_sub="auth0|nope", account_email="x@y.com") is None


def test_get_decrypted_refresh_token_round_trip(in_memory_session, encryption_key):
    row = upsert_token(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="user@example.com",
        refresh_token="1//rt-secret",
        scope="s",
        encryption_key=encryption_key,
    )
    assert get_decrypted_refresh_token(row, encryption_key) == "1//rt-secret"


def test_mark_used_bumps_timestamps(in_memory_session, encryption_key):
    row = upsert_token(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="user@example.com",
        refresh_token="rt",
        scope="s",
        encryption_key=encryption_key,
    )
    assert row.last_used_at is None
    mark_used(in_memory_session, row)
    assert row.last_used_at is not None
    assert row.updated_at == row.last_used_at


def test_soft_revoke_sets_revoked_at(in_memory_session, encryption_key):
    row = upsert_token(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="user@example.com",
        refresh_token="rt",
        scope="s",
        encryption_key=encryption_key,
    )
    soft_revoke(in_memory_session, row)
    assert row.revoked_at is not None


def test_access_token_expiry_persists(in_memory_session, encryption_key):
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    row = upsert_token(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="user@example.com",
        refresh_token="rt",
        scope="s",
        encryption_key=encryption_key,
        access_token_expires_at=expires,
    )
    fetched = get_token(in_memory_session, auth0_sub="auth0|abc", account_email="user@example.com")
    assert fetched is not None
    assert fetched.access_token_expires_at == row.access_token_expires_at


def test_get_refresh_lock_is_per_key():
    lock_a = get_refresh_lock("auth0|user-1", "user@example.com")
    lock_b = get_refresh_lock("auth0|user-1", "other@example.com")
    lock_a_again = get_refresh_lock("auth0|user-1", "user@example.com")
    assert lock_a is lock_a_again
    assert lock_a is not lock_b


@pytest.mark.asyncio
async def test_per_key_lock_serializes_concurrent_callers():
    """Two coroutines targeting the same key serialize through the lock.

    The lock invariant is asserted by interleaving two tasks and
    checking that the second only proceeds after the first releases.
    This is the minimum guarantee the OAuth refresh path relies on.
    """
    lock = get_refresh_lock("auth0|user-1", "user@example.com")
    order: list[str] = []

    async def worker(name: str, hold_seconds: float):
        async with lock:
            order.append(f"{name}-acquired")
            await asyncio.sleep(hold_seconds)
            order.append(f"{name}-released")

    await asyncio.gather(
        worker("first", 0.05),
        worker("second", 0.0),
    )
    # Whatever order they entered, "released" must immediately precede
    # the next "acquired" (no overlap), proving serialization.
    assert order[0].endswith("-acquired")
    assert order[1].endswith("-released")
    assert order[2].endswith("-acquired")
    assert order[3].endswith("-released")


def test_email_lowercase_check_constraint_present_in_metadata():
    """The CheckConstraint is wired into the SQLAlchemy table.

    SQLite does not enforce CHECK on every dialect quirk the same way
    Postgres does, so we don't assert via a failing INSERT here. The
    SQL-level enforcement is the responsibility of the Alembic
    migration (CHECK constraint emitted in 0001), which runs against
    Postgres in deployed environments. This test guarantees that the
    ORM table object carries the constraint metadata, so a future
    developer who copies the model cannot drop the constraint silently.
    """
    constraints = {c.name for c in GmailOAuthToken.__table__.constraints}
    assert "ck_gmail_tokens_email_lowercase" in constraints
