"""Tests for attachment_upload_store: mint, classify, finalize, consume, purge.

Store-level unit tests against an isolated in-memory SQLite session
(the `in_memory_session` conftest fixture). These assert the security
primitives directly: only the token hash is persisted, single-use is
atomic, ownership scoping rejects cross-user access, and purge NULLs
the ciphertext.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from mcp_gmail import attachment_upload_store as store

SUB = "auth0|alice"
EMAIL = "alice@example.com"


def _past(minutes: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(minutes=minutes)


def test_create_slot_persists_only_the_hash(in_memory_session):
    token, expires_at = store.create_slot(in_memory_session, auth0_sub=SUB, account_email=EMAIL)
    row = store.find_slot(in_memory_session, store.hash_token(token))
    assert row is not None
    assert row.token_hash == store.hash_token(token)
    # The raw token is NEVER stored as the PK.
    assert row.token_hash != token
    assert row.auth0_sub == SUB
    assert row.account_email == EMAIL
    assert row.encrypted_bytes is None  # minted, not yet uploaded
    assert expires_at > datetime.now(timezone.utc)


def test_create_slot_enforces_count_cap(in_memory_session):
    for _ in range(store.MAX_ACTIVE_SLOTS_PER_USER):
        store.create_slot(in_memory_session, auth0_sub=SUB, account_email=EMAIL)
    with pytest.raises(store.SlotCapExceeded):
        store.create_slot(in_memory_session, auth0_sub=SUB, account_email=EMAIL)
    # A different user is unaffected by another user's slots.
    store.create_slot(in_memory_session, auth0_sub="auth0|bob", account_email="bob@x.com")


def test_classify_slot_states(in_memory_session):
    now = datetime.now(timezone.utc)
    assert store.classify_slot(None) == store.STATUS_NOT_FOUND
    token, _ = store.create_slot(in_memory_session, auth0_sub=SUB, account_email=EMAIL)
    row = store.find_slot(in_memory_session, store.hash_token(token))
    assert store.classify_slot(row, now=now) == store.STATUS_OK
    row.uploaded_at = now
    assert store.classify_slot(row, now=now) == store.STATUS_ALREADY_UPLOADED
    row.expires_at = _past(1)
    assert store.classify_slot(row, now=now) == store.STATUS_EXPIRED
    row.consumed_at = now  # consumed takes precedence over expired
    assert store.classify_slot(row, now=now) == store.STATUS_CONSUMED


def test_finalize_upload_is_single_write(in_memory_session):
    token, _ = store.create_slot(in_memory_session, auth0_sub=SUB, account_email=EMAIL)
    th = store.hash_token(token)
    assert store.finalize_upload(
        in_memory_session,
        token_hash=th,
        encrypted=b"ciphertext",
        size_bytes=5,
        filename="a.pdf",
        mime_type="application/pdf",
    )
    row = store.find_slot(in_memory_session, th)
    assert row.uploaded_at is not None
    assert row.size_bytes == 5
    assert row.filename == "a.pdf"
    # A second write to the same slot is rejected.
    assert not store.finalize_upload(
        in_memory_session,
        token_hash=th,
        encrypted=b"other",
        size_bytes=9,
        filename="b.pdf",
        mime_type="application/pdf",
    )


def _minted_and_uploaded(session) -> str:
    token, _ = store.create_slot(session, auth0_sub=SUB, account_email=EMAIL)
    store.finalize_upload(
        session,
        token_hash=store.hash_token(token),
        encrypted=b"ciphertext",
        size_bytes=10,
        filename="f.pdf",
        mime_type="application/pdf",
    )
    return token


def test_load_for_consume_is_owner_scoped(in_memory_session):
    token = _minted_and_uploaded(in_memory_session)
    th = store.hash_token(token)
    assert (
        store.load_for_consume(in_memory_session, token_hash=th, auth0_sub=SUB, account_email=EMAIL)
        is not None
    )
    # Wrong user / wrong mailbox cannot load the bytes.
    assert (
        store.load_for_consume(
            in_memory_session, token_hash=th, auth0_sub="auth0|eve", account_email=EMAIL
        )
        is None
    )
    assert (
        store.load_for_consume(
            in_memory_session, token_hash=th, auth0_sub=SUB, account_email="other@x.com"
        )
        is None
    )


def test_consume_is_single_use_and_nulls_bytes(in_memory_session):
    token = _minted_and_uploaded(in_memory_session)
    th = store.hash_token(token)
    assert store.consume(in_memory_session, token_hash=th, auth0_sub=SUB, account_email=EMAIL)
    row = store.find_slot(in_memory_session, th)
    assert row.consumed_at is not None
    assert row.encrypted_bytes is None  # prompt deletion at consume
    # Replay is rejected.
    assert not store.consume(in_memory_session, token_hash=th, auth0_sub=SUB, account_email=EMAIL)


def test_consume_rejects_wrong_user(in_memory_session):
    token = _minted_and_uploaded(in_memory_session)
    th = store.hash_token(token)
    assert not store.consume(
        in_memory_session, token_hash=th, auth0_sub="auth0|eve", account_email=EMAIL
    )
    # Still consumable by the true owner (the failed attempt did nothing).
    assert store.consume(in_memory_session, token_hash=th, auth0_sub=SUB, account_email=EMAIL)


def test_sum_active_bytes(in_memory_session):
    _minted_and_uploaded(in_memory_session)
    _minted_and_uploaded(in_memory_session)
    assert store.sum_active_bytes(in_memory_session, SUB) == 20


def test_purge_removes_expired_and_consumed_keeps_active(in_memory_session):
    # active minted slot (kept)
    store.create_slot(in_memory_session, auth0_sub=SUB, account_email=EMAIL)
    # consumed slot (purged)
    consumed = _minted_and_uploaded(in_memory_session)
    store.consume(
        in_memory_session,
        token_hash=store.hash_token(consumed),
        auth0_sub=SUB,
        account_email=EMAIL,
    )
    # expired slot (purged)
    expired = _minted_and_uploaded(in_memory_session)
    exp_row = store.find_slot(in_memory_session, store.hash_token(expired))
    exp_row.expires_at = _past(60)
    in_memory_session.flush()

    removed = store.purge_expired_and_consumed(in_memory_session)
    assert removed == 2
    assert store.find_slot(in_memory_session, store.hash_token(consumed)) is None
    assert store.find_slot(in_memory_session, store.hash_token(expired)) is None
    assert store.count_active_slots(in_memory_session, SUB) == 1
