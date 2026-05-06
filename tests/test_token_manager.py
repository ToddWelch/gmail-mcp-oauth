"""Token manager: cache + lock + refresh + disconnect.

Targets: mcp-gmail/src/mcp_gmail/token_manager.py:get_access_token
Targets: mcp-gmail/src/mcp_gmail/token_manager.py:disconnect_account

Six cases per the agreed test matrix.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mcp_gmail import db as db_module
from mcp_gmail import token_manager as tm
from mcp_gmail.db import Base
from mcp_gmail.oauth_http import TOKEN_URL, REVOKE_URL
from mcp_gmail.token_store import get_token, upsert_token


@pytest.fixture
def encryption_key() -> str:
    return Fernet.generate_key().decode("ascii")


@pytest.fixture
def shared_engine():
    """Single shared SQLite engine that all session_scope calls reuse.

    The token_manager opens new sessions internally. To make tests
    deterministic we replace the module-level _SessionFactory with one
    bound to a shared in-memory database. That way the row we seed in
    a fixture is visible to every internal session_scope() call inside
    the manager.
    """
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    # Inject our engine + factory into db_module so session_scope() uses them.
    db_module._engine = engine
    db_module._SessionFactory = factory

    # Reset cache so we start clean.
    tm.reset_cache_for_tests()

    yield engine

    db_module.reset_for_tests()
    tm.reset_cache_for_tests()


@pytest.fixture
def seeded_session(shared_engine, encryption_key):
    """Yield a session for fixture seeding; the manager opens its own sessions."""
    factory = db_module._SessionFactory
    s = factory()
    try:
        yield s, encryption_key
        s.commit()
    finally:
        s.close()


# Case 1: cache hit short-circuits.
@pytest.mark.asyncio
async def test_cache_hit_skips_google(seeded_session):
    session, encryption_key = seeded_session
    upsert_token(
        session,
        auth0_sub="auth0|u1",
        account_email="user@example.com",
        refresh_token="rt-1",
        scope="s",
        encryption_key=encryption_key,
        access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
    )
    session.commit()
    # Pre-populate the cache so a fresh token is available.
    tm._store_cache(("auth0|u1", "user@example.com"), "ya29.cached", _ttl_future_epoch(3600))

    # No respx mock = if the manager calls Google, the test fails with
    # a network error.
    out = await tm.get_access_token(
        auth0_sub="auth0|u1",
        account_email="user@example.com",
        google_client_id="cid",
        google_client_secret="csec",
        encryption_key=encryption_key,
    )
    assert out == "ya29.cached"


# Case 2: cache miss triggers refresh; result is cached + DB row updated.
@pytest.mark.asyncio
async def test_cache_miss_refreshes_and_updates(seeded_session):
    session, encryption_key = seeded_session
    upsert_token(
        session,
        auth0_sub="auth0|u1",
        account_email="user@example.com",
        refresh_token="rt-1",
        scope="old-scope",
        encryption_key=encryption_key,
        access_token_expires_at=datetime.now(timezone.utc) - timedelta(seconds=120),
    )
    session.commit()

    refresh_response = {
        "access_token": "ya29.fresh",
        "expires_in": 3600,
        "scope": "new-scope",
        "token_type": "Bearer",
    }
    with respx.mock(assert_all_called=True) as router:
        router.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=refresh_response))
        out = await tm.get_access_token(
            auth0_sub="auth0|u1",
            account_email="user@example.com",
            google_client_id="cid",
            google_client_secret="csec",
            encryption_key=encryption_key,
        )
    assert out == "ya29.fresh"
    # Cache populated.
    assert tm._cache_hit(("auth0|u1", "user@example.com")) == "ya29.fresh"
    # DB row scope updated.
    fresh_session = db_module._SessionFactory()
    try:
        row = get_token(fresh_session, auth0_sub="auth0|u1", account_email="user@example.com")
        assert row is not None
        assert row.scope == "new-scope"
    finally:
        fresh_session.close()


# Case 3: missing row -> TokenUnavailableError.
@pytest.mark.asyncio
async def test_missing_row_raises_unavailable(shared_engine, encryption_key):
    with pytest.raises(tm.TokenUnavailableError, match="no Google account"):
        await tm.get_access_token(
            auth0_sub="auth0|nope",
            account_email="missing@x.com",
            google_client_id="cid",
            google_client_secret="csec",
            encryption_key=encryption_key,
        )


# Case 4: revoked row -> TokenUnavailableError.
@pytest.mark.asyncio
async def test_revoked_row_raises_unavailable(seeded_session):
    session, encryption_key = seeded_session
    row = upsert_token(
        session,
        auth0_sub="auth0|u1",
        account_email="user@example.com",
        refresh_token="rt-1",
        scope="s",
        encryption_key=encryption_key,
    )
    from mcp_gmail.token_store import soft_revoke

    soft_revoke(session, row)
    session.commit()

    with pytest.raises(tm.TokenUnavailableError, match="soft-revoked"):
        await tm.get_access_token(
            auth0_sub="auth0|u1",
            account_email="user@example.com",
            google_client_id="cid",
            google_client_secret="csec",
            encryption_key=encryption_key,
        )


# Case 5: invalid_grant from Google soft-revokes the row.
@pytest.mark.asyncio
async def test_invalid_grant_soft_revokes(seeded_session):
    session, encryption_key = seeded_session
    upsert_token(
        session,
        auth0_sub="auth0|u1",
        account_email="user@example.com",
        refresh_token="rt-bad",
        scope="s",
        encryption_key=encryption_key,
        access_token_expires_at=datetime.now(timezone.utc) - timedelta(seconds=120),
    )
    session.commit()

    with respx.mock(assert_all_called=True) as router:
        router.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={"error": "invalid_grant", "error_description": "expired or revoked"},
            )
        )
        with pytest.raises(tm.TokenUnavailableError, match="invalid_grant"):
            await tm.get_access_token(
                auth0_sub="auth0|u1",
                account_email="user@example.com",
                google_client_id="cid",
                google_client_secret="csec",
                encryption_key=encryption_key,
            )

    fresh_session = db_module._SessionFactory()
    try:
        row = get_token(fresh_session, auth0_sub="auth0|u1", account_email="user@example.com")
        assert row is not None
        assert row.revoked_at is not None
    finally:
        fresh_session.close()


# Case 6: disconnect_account: best-effort revoke + soft-revoke + idempotent.
@pytest.mark.asyncio
async def test_disconnect_account_round_trip(seeded_session):
    session, encryption_key = seeded_session
    upsert_token(
        session,
        auth0_sub="auth0|u1",
        account_email="user@example.com",
        refresh_token="rt-discon",
        scope="s",
        encryption_key=encryption_key,
    )
    session.commit()

    # Pre-seed the access-token cache so we can verify disconnect drops it.
    tm._store_cache(
        ("auth0|u1", "user@example.com"),
        "ya29.before-disconnect",
        _ttl_future_epoch(3600),
    )
    assert tm._cache_hit(("auth0|u1", "user@example.com")) == "ya29.before-disconnect"

    with respx.mock(assert_all_called=False) as router:
        router.post(REVOKE_URL).mock(return_value=httpx.Response(200))
        ok = await tm.disconnect_account(
            auth0_sub="auth0|u1",
            account_email="user@example.com",
            encryption_key=encryption_key,
        )
    assert ok is True

    # Cache was dropped by disconnect.
    assert tm._cache_hit(("auth0|u1", "user@example.com")) is None

    # Row is soft-revoked.
    fresh_session = db_module._SessionFactory()
    try:
        row = get_token(fresh_session, auth0_sub="auth0|u1", account_email="user@example.com")
        assert row is not None
        assert row.revoked_at is not None
    finally:
        fresh_session.close()

    # Second call is idempotent and returns True.
    second = await tm.disconnect_account(
        auth0_sub="auth0|u1",
        account_email="user@example.com",
        encryption_key=encryption_key,
    )
    assert second is True

    # Disconnect on a missing row returns False.
    third = await tm.disconnect_account(
        auth0_sub="auth0|missing",
        account_email="ghost@x.com",
        encryption_key=encryption_key,
    )
    assert third is False


# disconnect clears the idempotency cache so a re-link
# inside the same process does not return the previous link's cached
# send result.
@pytest.mark.asyncio
async def test_oauth_disconnect_relink_within_60s_does_not_return_stale_cache(
    seeded_session,
):
    """Connect -> populate idempotency cache via send -> disconnect -> re-link
    same email by same auth0_sub -> cache miss on the previously-used key.

    This proves token_manager.disconnect_account calls
    cache.clear_for_actor at the end of its critical section, so the
    re-link callers cannot reach a stale cached send_email response on
    the previous link.
    """
    from mcp_gmail.gmail_tools.idempotency import default_cache

    # Clean slate for the global idempotency cache so a previous
    # test's stale entry cannot satisfy the post-disconnect cache-miss
    # assertion below.
    default_cache.clear()

    session, encryption_key = seeded_session
    auth0_sub = "auth0|relink-user"
    account_email = "relinker@example.com"

    upsert_token(
        session,
        auth0_sub=auth0_sub,
        account_email=account_email,
        refresh_token="rt-relink",
        scope="s",
        encryption_key=encryption_key,
    )
    session.commit()

    # Populate the idempotency cache with a result that "send_email"
    # would have stored. Any tuple key matching this actor will be
    # cleared by disconnect_account.
    cache_key = (auth0_sub, account_email, "idem-key-1")
    default_cache.set(cache_key, {"id": "previous-send"})
    assert default_cache.get(cache_key) == {"id": "previous-send"}

    # Disconnect.
    with respx.mock(assert_all_called=False) as router:
        router.post(REVOKE_URL).mock(return_value=httpx.Response(200))
        ok = await tm.disconnect_account(
            auth0_sub=auth0_sub,
            account_email=account_email,
            encryption_key=encryption_key,
        )
    assert ok is True

    # Cache must be cleared for this actor; previously-used key
    # returns None now (cache miss).
    assert default_cache.get(cache_key) is None

    # Simulate re-link: insert a new (replacement) row for the same
    # (sub, email).
    upsert_token(
        session,
        auth0_sub=auth0_sub,
        account_email=account_email,
        refresh_token="rt-relink-new",
        scope="s",
        encryption_key=encryption_key,
    )
    session.commit()

    # Even after re-link, the previously-used idempotency key must
    # still miss the cache. A re-link caller using the same key would
    # therefore go through to Gmail rather than receive the stale
    # cached result from the previous link.
    assert default_cache.get(cache_key) is None


# Case 7: refresh lock is released when Google returns invalid_grant.
#
# `async with lock:` is a Python language guarantee that the lock is
# released on exception, but a regression that converted to a manual
# acquire/release without try/finally would silently break it. This
# test asserts the lock is reusable after the invalid_grant path
# raises, by attempting to acquire it again with a tight timeout. If
# the lock had been left held, the timeout would fire.
@pytest.mark.asyncio
async def test_refresh_lock_releases_on_invalid_grant_failure(seeded_session):
    import asyncio

    from mcp_gmail.token_store import get_refresh_lock

    session, encryption_key = seeded_session
    upsert_token(
        session,
        auth0_sub="auth0|u1",
        account_email="user@example.com",
        refresh_token="rt-bad",
        scope="s",
        encryption_key=encryption_key,
        access_token_expires_at=datetime.now(timezone.utc) - timedelta(seconds=120),
    )
    session.commit()

    with respx.mock(assert_all_called=True) as router:
        router.post(TOKEN_URL).mock(
            return_value=httpx.Response(
                400,
                json={"error": "invalid_grant", "error_description": "expired or revoked"},
            )
        )
        with pytest.raises(tm.TokenUnavailableError):
            await tm.get_access_token(
                auth0_sub="auth0|u1",
                account_email="user@example.com",
                google_client_id="cid",
                google_client_secret="csec",
                encryption_key=encryption_key,
            )

    # The lock for (auth0|u1, user@example.com) must be released. Acquire
    # it with a tight timeout: if `async with lock:` did not release on
    # exception, this would block until timeout.
    lock = get_refresh_lock("auth0|u1", "user@example.com")
    await asyncio.wait_for(lock.acquire(), timeout=0.1)
    lock.release()


def _ttl_future_epoch(seconds: float) -> float:
    """Helper: epoch timestamp `seconds` in the future."""
    import time

    return time.time() + seconds
