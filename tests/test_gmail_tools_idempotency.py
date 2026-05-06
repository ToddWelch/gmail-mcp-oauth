"""Tests for gmail_tools.idempotency.IdempotencyCache.

The cache ships but is not exercised by the read tools. These
tests pin the contract the write side relies on.
"""

from __future__ import annotations

import time

import pytest

from mcp_gmail.gmail_tools.idempotency import (
    DEFAULT_MAX_ENTRIES,
    DEFAULT_TTL_SECONDS,
    IdempotencyCache,
)


def _make() -> IdempotencyCache:
    return IdempotencyCache()


def test_default_values_match_spec():
    """Decision 2 spec: 60s TTL, 1000 entries."""
    assert DEFAULT_TTL_SECONDS == 60.0
    assert DEFAULT_MAX_ENTRIES == 1000


def test_set_get_round_trip():
    c = _make()
    key = ("user-a", "x@example.com", "idem-1")
    c.set(key, {"message_id": "abc"})
    assert c.get(key) == {"message_id": "abc"}


def test_miss_returns_none():
    c = _make()
    assert c.get(("u", "e", "k")) is None


def test_key_is_tuple_of_sub_email_idem_key():
    """Decision 2: key MUST include actor partition, not just idem_key."""
    c = _make()
    c.set(("user-a", "x@example.com", "shared-key"), {"id": "from-a"})
    c.set(("user-b", "x@example.com", "shared-key"), {"id": "from-b"})
    assert c.get(("user-a", "x@example.com", "shared-key")) == {"id": "from-a"}
    assert c.get(("user-b", "x@example.com", "shared-key")) == {"id": "from-b"}


def test_lru_eviction_drops_oldest_first():
    c = IdempotencyCache(max_entries=3)
    c.set(("a", "e", "1"), {"i": 1})
    c.set(("a", "e", "2"), {"i": 2})
    c.set(("a", "e", "3"), {"i": 3})
    # Access "1" so "2" becomes the oldest.
    c.get(("a", "e", "1"))
    c.set(("a", "e", "4"), {"i": 4})
    # "2" should have been evicted.
    assert c.get(("a", "e", "2")) is None
    assert c.get(("a", "e", "1")) == {"i": 1}
    assert c.get(("a", "e", "4")) == {"i": 4}


def test_set_on_existing_key_refreshes_ttl():
    c = IdempotencyCache(ttl_seconds=10)
    c.set(("a", "e", "k"), {"i": 1})
    c.set(("a", "e", "k"), {"i": 2})
    # Latest value wins.
    assert c.get(("a", "e", "k")) == {"i": 2}


def test_expired_entry_returns_none(monkeypatch):
    c = IdempotencyCache(ttl_seconds=0.01)
    c.set(("a", "e", "k"), {"i": 1})
    # Sleep past TTL so the entry expires.
    time.sleep(0.02)
    assert c.get(("a", "e", "k")) is None


def test_clear_empties_cache():
    c = _make()
    c.set(("a", "e", "k"), {"i": 1})
    assert len(c) == 1
    c.clear()
    assert len(c) == 0


def test_clear_for_actor_drops_only_that_actor():
    c = _make()
    c.set(("user-a", "x@example.com", "k1"), {"i": 1})
    c.set(("user-a", "x@example.com", "k2"), {"i": 2})
    c.set(("user-b", "x@example.com", "k1"), {"i": 3})
    dropped = c.clear_for_actor(auth0_sub="user-a", account_email="x@example.com")
    assert dropped == 2
    assert c.get(("user-a", "x@example.com", "k1")) is None
    assert c.get(("user-b", "x@example.com", "k1")) == {"i": 3}


def test_clear_for_actor_returns_zero_when_no_match():
    c = _make()
    c.set(("a", "e", "k"), {"i": 1})
    assert c.clear_for_actor(auth0_sub="nope", account_email="nope") == 0


def test_invalid_ttl_raises():
    with pytest.raises(ValueError):
        IdempotencyCache(ttl_seconds=0)


def test_invalid_max_entries_raises():
    with pytest.raises(ValueError):
        IdempotencyCache(max_entries=0)
