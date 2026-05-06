"""OAuth state nonce single-use semantics.

Targets: mcp-gmail/src/mcp_gmail/state_store.py:create_nonce
Targets: mcp-gmail/src/mcp_gmail/state_store.py:consume_nonce
Targets: mcp-gmail/src/mcp_gmail/state_store.py:cleanup_expired
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from mcp_gmail import state_store as state_store_module
from mcp_gmail.state_store import (
    NONCE_TTL_MINUTES,
    OAuthStateNonce,
    cleanup_expired,
    consume_nonce,
    create_nonce,
)


def test_create_nonce_persists_row(in_memory_session):
    nonce = create_nonce(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="user@example.com",
    )
    assert isinstance(nonce, str)
    assert len(nonce) >= 40  # 32 bytes -> ~43 url-safe chars
    row = in_memory_session.query(OAuthStateNonce).filter_by(nonce=nonce).one()
    assert row.auth0_sub == "auth0|abc"
    assert row.account_email == "user@example.com"
    assert row.consumed_at is None


def test_create_nonce_lowercases_email(in_memory_session):
    nonce = create_nonce(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="MixedCase@Example.com",
    )
    row = in_memory_session.query(OAuthStateNonce).filter_by(nonce=nonce).one()
    assert row.account_email == "mixedcase@example.com"


def test_create_nonce_validates_inputs(in_memory_session):
    with pytest.raises(ValueError):
        create_nonce(in_memory_session, auth0_sub="", account_email="x@y.com")
    with pytest.raises(ValueError):
        create_nonce(in_memory_session, auth0_sub="auth0|abc", account_email="")


def test_consume_nonce_succeeds_once(in_memory_session):
    nonce = create_nonce(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="user@example.com",
    )
    first = consume_nonce(in_memory_session, nonce)
    assert first is not None
    assert first.auth0_sub == "auth0|abc"
    assert first.consumed_at is not None


def test_consume_nonce_second_attempt_fails(in_memory_session):
    """Single-use semantics: replay must not succeed.

    This is the entire point of the nonce table. A signed-but-replayable
    state token would be vulnerable to attackers sniffing the OAuth
    callback URL. The nonce table makes the second attempt a no-op.
    """
    nonce = create_nonce(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="user@example.com",
    )
    first = consume_nonce(in_memory_session, nonce)
    assert first is not None
    second = consume_nonce(in_memory_session, nonce)
    assert second is None


def test_consume_nonce_unknown_returns_none(in_memory_session):
    assert consume_nonce(in_memory_session, "nonexistent-nonce") is None


def test_consume_nonce_empty_returns_none(in_memory_session):
    assert consume_nonce(in_memory_session, "") is None


def test_consume_nonce_expired_returns_none(in_memory_session, monkeypatch):
    """A nonce older than NONCE_TTL_MINUTES must not be consumable.

    We override _now_utc instead of mutating the row to keep the
    test focused on the time-based gate rather than the row's stored
    timestamp.
    """
    nonce = create_nonce(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="user@example.com",
    )

    future = datetime.now(timezone.utc) + timedelta(minutes=NONCE_TTL_MINUTES + 1)
    monkeypatch.setattr(state_store_module, "_now_utc", lambda: future)
    assert consume_nonce(in_memory_session, nonce) is None


def test_cleanup_expired_removes_old_rows(in_memory_session, monkeypatch):
    """cleanup_expired drops rows older than the TTL and leaves fresh rows alone."""
    create_nonce(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="old@example.com",
    )
    # Walk the clock forward past the TTL.
    future = datetime.now(timezone.utc) + timedelta(minutes=NONCE_TTL_MINUTES + 5)
    monkeypatch.setattr(state_store_module, "_now_utc", lambda: future)
    create_nonce(
        in_memory_session,
        auth0_sub="auth0|abc",
        account_email="fresh@example.com",
    )
    deleted = cleanup_expired(in_memory_session)
    assert deleted == 1
    remaining = in_memory_session.query(OAuthStateNonce).all()
    assert len(remaining) == 1
    assert remaining[0].account_email == "fresh@example.com"


def test_create_nonce_uniqueness_across_calls(in_memory_session):
    """Two calls must not return identical nonces (entropy sanity check)."""
    n1 = create_nonce(in_memory_session, auth0_sub="auth0|a", account_email="a@b.com")
    n2 = create_nonce(in_memory_session, auth0_sub="auth0|a", account_email="a@b.com")
    assert n1 != n2
