"""In-process idempotency cache for send-style tools.

the `send_email` and `reply_all` tools accept an optional
`idempotency_key`. When supplied, the server dedupes calls in-process
for a TTL (default 60 seconds): the same key from the same actor
returns the cached message id rather than sending again. This guards
against Claude.ai retrying a tool call after a transient timeout.

Cache key (Decision 2)
-----------------------------------------
The key is the tuple (auth0_sub, account_email, idempotency_key).
NOT just the idempotency_key. Two different humans (or one human's
two linked mailboxes) can legitimately use the same opaque
idempotency string; without the actor partition we would silently
return one human's message id to the other.

Replay versus reuse
-----------------------------------------
Each entry stores a fingerprint of what the key was used for
(request_fingerprint). reply_outcomes.replayed_result returns a cached
result only for the same call, and key_lock serializes calls sharing a
key, so a retry cannot send twice or inherit another message's result.

Bounded cache
-----------------------------------------------
Default capacity 1000 entries, LRU eviction on insert. The cache is
process-local; on restart the cache is empty. TTL filtering happens
at lookup time (we discard expired entries lazily rather than
sweeping). The 60-second TTL is short enough that the cache cannot
grow unbounded under normal load even without LRU; LRU is the
defense-in-depth backstop.

The cache MAY be exercised by tests even though no read-side
tool reads or writes it. The send tool wires
into this module. Disconnect should clear the cache for the affected
(auth0_sub, account_email) keys, but that integration also lands in
the write side.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from collections import OrderedDict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any


DEFAULT_TTL_SECONDS = 60.0
DEFAULT_MAX_ENTRIES = 1000


CacheKey = tuple[str, str, str]  # (auth0_sub, account_email, idempotency_key)


def request_fingerprint(*parts: Any) -> str:
    """Identify what a key was used for, so a replay can be told from a reuse.

    Hashed, so a message body or attachment is never held in the cache.
    """
    encoded = json.dumps(parts, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class _Entry:
    value: dict  # whatever the send tool returned; opaque to this module
    expires_at_epoch: float
    fingerprint: str | None = None


@dataclass
class _KeyLock:
    lock: asyncio.Lock
    holders: int = 0


class IdempotencyCache:
    """LRU + TTL idempotency cache, keyed by (sub, email, idem_key).

    Single-replica only; the cache is process-local. Multi-replica
    deployments would observe a key on replica A miss on replica B,
    which is the same caveat as token_store's per-key asyncio.Lock
    and is acceptable's deployment shape (single replica).

    Methods:
        get(key)        -> dict | None  (None on miss or expired)
        set(key, value) -> None
        clear()         -> None
        clear_for_actor(auth0_sub, account_email) -> int

    Usage from the send tools:
        async with cache.key_lock(key):
            replay = replayed_result(cache=cache, key=key, fingerprint=fingerprint)
            if replay is not None:
                return replay
            result = await send_once(...)
            if cacheable_send_result(result):
                cache.set(key, result, fingerprint=fingerprint)
            return result
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
    ):
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._ttl = ttl_seconds
        self._max = max_entries
        # OrderedDict gives us O(1) move-to-end on access, which is the
        # standard LRU primitive in stdlib. functools.lru_cache is
        # decorator-style and not suitable here; we want explicit
        # set/get with a tuple key and TTL filtering.
        self._data: OrderedDict[CacheKey, _Entry] = OrderedDict()
        self._locks: dict[CacheKey, _KeyLock] = {}

    @asynccontextmanager
    async def key_lock(self, key: CacheKey | None) -> AsyncIterator[None]:
        """Serialize calls sharing a key, from the cache read through the cache write.

        A send now spends several Gmail round trips between the two, and a
        client retrying while the first call is still in flight would otherwise
        miss the cache and send twice. Entries are dropped once idle, so this
        does not grow with the number of keys ever used. A None key is a no-op.
        """
        if key is None:
            yield
            return
        entry = self._locks.setdefault(key, _KeyLock(lock=asyncio.Lock()))
        entry.holders += 1
        try:
            async with entry.lock:
                yield
        finally:
            entry.holders -= 1
            if entry.holders == 0:
                self._locks.pop(key, None)

    def fingerprint_of(self, key: CacheKey) -> str | None:
        """The fingerprint stored with `key`, or None if absent or stored without one."""
        entry = self._data.get(key)
        return entry.fingerprint if entry is not None else None

    def get(self, key: CacheKey) -> dict | None:
        """Return cached value or None on miss / expired."""
        entry = self._data.get(key)
        if entry is None:
            return None
        if entry.expires_at_epoch <= time.time():
            # Expired; drop and report miss.
            self._data.pop(key, None)
            return None
        # LRU: bump to most-recently-used end.
        self._data.move_to_end(key)
        return entry.value

    def set(self, key: CacheKey, value: dict, *, fingerprint: str | None = None) -> None:
        """Insert or refresh `key` -> `value`. Evicts oldest if over capacity."""
        if key in self._data:
            self._data.move_to_end(key)
            self._data[key] = _Entry(
                value=value,
                expires_at_epoch=time.time() + self._ttl,
                fingerprint=fingerprint,
            )
            return

        self._data[key] = _Entry(
            value=value,
            expires_at_epoch=time.time() + self._ttl,
            fingerprint=fingerprint,
        )
        # Evict from the front (oldest) until we are within capacity.
        while len(self._data) > self._max:
            self._data.popitem(last=False)

    def clear(self) -> None:
        """Remove every entry. Used by reset_for_tests-style helpers."""
        self._data.clear()

    def clear_for_actor(self, *, auth0_sub: str, account_email: str) -> int:
        """Drop every entry whose first two key components match.

        Intended to be called from the disconnect flow: when a user
        unlinks an account, any pending idempotency entries for that
        actor are no longer meaningful and should not be returned to a
        re-link of the same account. Returns the number of entries
        evicted; tests assert >= 0 and the `_data` length decreases by
        that amount.
        """
        prefix = (auth0_sub, account_email)
        to_delete = [k for k in self._data if k[0:2] == prefix]
        for k in to_delete:
            self._data.pop(k, None)
        return len(to_delete)

    def __len__(self) -> int:
        return len(self._data)


# Module-level default instance for the write side to import. Read-side tests
# instantiate their own cache to avoid coupling test cases through a
# shared singleton.
default_cache = IdempotencyCache()
