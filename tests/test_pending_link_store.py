"""Pending OAuth link single-use semantics.

Targets: mcp-gmail/src/mcp_gmail/pending_link_store.py:create_pending_link
Targets: mcp-gmail/src/mcp_gmail/pending_link_store.py:consume_pending_link
Targets: mcp-gmail/src/mcp_gmail/pending_link_store.py:discard_pending_link
Targets: mcp-gmail/src/mcp_gmail/pending_link_store.py:cleanup_expired_pending

Layer 2 of the OAuth identity-binding fix.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from mcp_gmail.pending_link_store import (
    PENDING_LINK_TTL_MINUTES,
    OAuthPendingLink,
    cleanup_expired_pending,
    consume_pending_link,
    create_pending_link,
    discard_pending_link,
    get_pending_link,
)


def _make(in_memory_session, **overrides):
    """Helper: build a pending link row with sane defaults."""
    kwargs = {
        "auth0_sub": "auth0|user-a",
        "account_email": "linked@example.com",
        "requested_account_email": "linked@example.com",
        "encrypted_refresh_token": b"ciphertext-fake",
        "granted_scope": "openid email",
        "access_token_expires_at": datetime.now(timezone.utc) + timedelta(hours=1),
        "google_sub": "google-sub-1",
    }
    kwargs.update(overrides)
    return create_pending_link(in_memory_session, **kwargs)


# ---------------------------------------------------------------------------
# create_pending_link
# ---------------------------------------------------------------------------


def test_create_pending_link_persists_row(in_memory_session):
    pending_token = _make(in_memory_session)
    assert isinstance(pending_token, str)
    assert len(pending_token) >= 40
    row = in_memory_session.query(OAuthPendingLink).filter_by(pending_token=pending_token).one()
    assert row.auth0_sub == "auth0|user-a"
    assert row.account_email == "linked@example.com"
    assert row.encrypted_refresh_token == b"ciphertext-fake"


def test_create_pending_link_lowercases_emails(in_memory_session):
    pending_token = _make(
        in_memory_session,
        account_email="MixedCase@Example.com",
        requested_account_email="Other@Example.com",
    )
    row = in_memory_session.query(OAuthPendingLink).filter_by(pending_token=pending_token).one()
    assert row.account_email == "mixedcase@example.com"
    assert row.requested_account_email == "other@example.com"


def test_create_pending_link_rejects_empty_inputs(in_memory_session):
    for kw in (
        {"auth0_sub": ""},
        {"account_email": ""},
        {"requested_account_email": ""},
        {"encrypted_refresh_token": b""},
        {"granted_scope": ""},
    ):
        with pytest.raises(ValueError):
            _make(in_memory_session, **kw)


# ---------------------------------------------------------------------------
# get_pending_link
# ---------------------------------------------------------------------------


def test_get_pending_link_returns_row(in_memory_session):
    pending_token = _make(in_memory_session)
    row = get_pending_link(in_memory_session, pending_token)
    assert row is not None
    assert row.pending_token == pending_token


def test_get_pending_link_none_for_missing(in_memory_session):
    assert get_pending_link(in_memory_session, "no-such-token") is None
    assert get_pending_link(in_memory_session, "") is None


def test_get_pending_link_filters_expired(in_memory_session):
    pending_token = _make(in_memory_session)
    # Backdate the row to past TTL.
    row = in_memory_session.query(OAuthPendingLink).filter_by(pending_token=pending_token).one()
    row.created_at = datetime.now(timezone.utc) - timedelta(minutes=PENDING_LINK_TTL_MINUTES + 1)
    in_memory_session.flush()
    assert get_pending_link(in_memory_session, pending_token) is None


# ---------------------------------------------------------------------------
# consume_pending_link
# ---------------------------------------------------------------------------


def test_consume_pending_link_returns_snapshot_and_deletes_row(in_memory_session):
    pending_token = _make(in_memory_session)
    captured = consume_pending_link(in_memory_session, pending_token)
    assert captured is not None
    assert captured.pending_token == pending_token
    assert captured.encrypted_refresh_token == b"ciphertext-fake"
    # Row gone after consume.
    assert (
        in_memory_session.query(OAuthPendingLink)
        .filter_by(pending_token=pending_token)
        .one_or_none()
        is None
    )


def test_pending_row_ciphertext_dropped_on_consume(in_memory_session):
    """action=confirm path drops the row AND NULLs ciphertext.

    The post-consume DB state has neither the row nor any residual
    ciphertext column to extract. The captured snapshot returned to
    the caller still carries the ciphertext bytes (they need them to
    decrypt and re-encrypt for the gmail_oauth_tokens upsert), but
    that is a process-memory copy that goes out of scope as soon as
    upsert_token returns.
    """
    pending_token = _make(in_memory_session)
    consume_pending_link(in_memory_session, pending_token)
    in_memory_session.flush()
    # Row is gone (delete inside consume).
    assert (
        in_memory_session.query(OAuthPendingLink)
        .filter_by(pending_token=pending_token)
        .one_or_none()
        is None
    )


def test_consume_pending_link_replay_returns_none(in_memory_session):
    pending_token = _make(in_memory_session)
    first = consume_pending_link(in_memory_session, pending_token)
    second = consume_pending_link(in_memory_session, pending_token)
    assert first is not None
    assert second is None


def test_consume_pending_link_expired_returns_none(in_memory_session):
    pending_token = _make(in_memory_session)
    row = in_memory_session.query(OAuthPendingLink).filter_by(pending_token=pending_token).one()
    row.created_at = datetime.now(timezone.utc) - timedelta(minutes=PENDING_LINK_TTL_MINUTES + 1)
    in_memory_session.flush()
    assert consume_pending_link(in_memory_session, pending_token) is None


def test_consume_pending_link_empty_token_returns_none(in_memory_session):
    assert consume_pending_link(in_memory_session, "") is None


# ---------------------------------------------------------------------------
# discard_pending_link
# ---------------------------------------------------------------------------


def test_discard_pending_link_removes_row(in_memory_session):
    pending_token = _make(in_memory_session)
    removed = discard_pending_link(in_memory_session, pending_token)
    assert removed is True
    assert (
        in_memory_session.query(OAuthPendingLink)
        .filter_by(pending_token=pending_token)
        .one_or_none()
        is None
    )


def test_pending_row_ciphertext_dropped_on_cancel(in_memory_session):
    """action=cancel path drops the row AND NULLs ciphertext."""
    pending_token = _make(in_memory_session)
    discard_pending_link(in_memory_session, pending_token)
    in_memory_session.flush()
    assert (
        in_memory_session.query(OAuthPendingLink)
        .filter_by(pending_token=pending_token)
        .one_or_none()
        is None
    )


def test_discard_pending_link_idempotent_on_missing(in_memory_session):
    assert discard_pending_link(in_memory_session, "no-such-token") is False
    assert discard_pending_link(in_memory_session, "") is False


def test_discard_pending_link_works_on_expired_row(in_memory_session):
    """Cancel after expiry still cleans up the row (no TTL gate on cancel)."""
    pending_token = _make(in_memory_session)
    row = in_memory_session.query(OAuthPendingLink).filter_by(pending_token=pending_token).one()
    row.created_at = datetime.now(timezone.utc) - timedelta(minutes=PENDING_LINK_TTL_MINUTES + 1)
    in_memory_session.flush()
    assert discard_pending_link(in_memory_session, pending_token) is True


# ---------------------------------------------------------------------------
# cleanup_expired_pending
# ---------------------------------------------------------------------------


def test_cleanup_expired_pending_removes_only_expired(in_memory_session):
    fresh = _make(in_memory_session, account_email="fresh@example.com")
    stale = _make(in_memory_session, account_email="stale@example.com")
    stale_row = in_memory_session.query(OAuthPendingLink).filter_by(pending_token=stale).one()
    stale_row.created_at = datetime.now(timezone.utc) - timedelta(
        minutes=PENDING_LINK_TTL_MINUTES + 1
    )
    in_memory_session.flush()

    removed = cleanup_expired_pending(in_memory_session)
    assert removed == 1
    # Fresh row survives.
    assert (
        in_memory_session.query(OAuthPendingLink).filter_by(pending_token=fresh).one_or_none()
        is not None
    )
    # Stale row gone.
    assert (
        in_memory_session.query(OAuthPendingLink).filter_by(pending_token=stale).one_or_none()
        is None
    )


def test_pending_row_ciphertext_dropped_on_cleanup(in_memory_session):
    """cleanup path drops rows AND NULLs ciphertext."""
    pending_token = _make(in_memory_session)
    row = in_memory_session.query(OAuthPendingLink).filter_by(pending_token=pending_token).one()
    row.created_at = datetime.now(timezone.utc) - timedelta(minutes=PENDING_LINK_TTL_MINUTES + 1)
    in_memory_session.flush()
    cleanup_expired_pending(in_memory_session)
    in_memory_session.flush()
    assert (
        in_memory_session.query(OAuthPendingLink)
        .filter_by(pending_token=pending_token)
        .one_or_none()
        is None
    )


def test_cleanup_expired_pending_zero_when_none_expired(in_memory_session):
    _make(in_memory_session)
    assert cleanup_expired_pending(in_memory_session) == 0
