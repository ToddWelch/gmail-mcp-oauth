"""Per-account access-token cache + refresh orchestration + disconnect.

get_access_token returns a non-expired access_token for the
(auth0_sub, account_email) tuple. In-process cache avoids hitting
Google on every tool call. On miss or near-expiry, holds the per-key
asyncio.Lock from token_store, refreshes via Google, updates the
cache, and persists the new expiry. Access tokens never persisted;
cache is process-local.

disconnect_account best-effort revokes at Google, soft-revokes in
the DB, and wipes the encrypted refresh token at
rest. Soft_revoke runs BEFORE wipe so /oauth/status's has_token
invariant flips correctly.

Errors: TokenUnavailableError = terminal state (missing / revoked /
invalid_grant). On invalid_grant we soft_revoke + wipe. Other Google
errors (network, 5xx) propagate as GoogleOAuthError so callers can
distinguish terminal from retriable.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from . import oauth_http
from .db import session_scope
from .gmail_tools.idempotency import default_cache as _idempotency_cache
from .token_store import (
    get_decrypted_refresh_token,
    get_refresh_lock,
    get_token,
    soft_revoke,
    upsert_token,
    wipe_token_ciphertext,
)

logger = logging.getLogger(__name__)


# How close to expiry should we proactively refresh? Google access
# tokens are valid for 3600s; refreshing 60s before expiry avoids
# in-flight requests racing the clock.
EXPIRY_PROACTIVE_REFRESH_SECONDS = 60


class TokenUnavailableError(Exception):
    """Raised when an access token cannot be produced for the requested account.

    Distinct from GoogleOAuthError because it represents a known
    terminal state (account missing, revoked, refresh token rejected),
    not a transient failure. Tool-dispatch callers should surface this
    as "user must re-link account" rather than "retry."
    """


@dataclass
class _CacheEntry:
    """In-memory cache of a non-expired access token.

    expires_at_epoch is the absolute time the token expires (NOT a
    relative duration). Stored as float seconds since epoch to match
    oauth_http.TokenResponse.
    """

    access_token: str
    expires_at_epoch: float


# Module-level cache. Process-local; cleared on restart. The keying
# is identical to token_store's lock dict: (auth0_sub, account_email).
_cache: dict[tuple[str, str], _CacheEntry] = {}


def reset_cache_for_tests() -> None:
    """Test helper: clear the in-process access-token cache."""
    _cache.clear()


def _now_epoch() -> float:
    import time

    return time.time()


def _cache_hit(key: tuple[str, str]) -> str | None:
    """Return cached access_token if still valid, else None."""
    entry = _cache.get(key)
    if entry is None:
        return None
    if entry.expires_at_epoch - _now_epoch() <= EXPIRY_PROACTIVE_REFRESH_SECONDS:
        # Treat as expired; force refresh.
        return None
    return entry.access_token


def _store_cache(key: tuple[str, str], token: str, expires_at_epoch: float) -> None:
    _cache[key] = _CacheEntry(access_token=token, expires_at_epoch=expires_at_epoch)


def _drop_cache(key: tuple[str, str]) -> None:
    _cache.pop(key, None)


async def get_access_token(
    *,
    auth0_sub: str,
    account_email: str,
    google_client_id: str,
    google_client_secret: str,
    encryption_key: str,
    prior_encryption_keys: tuple[str, ...] = (),
) -> str:
    """Return a non-expired access_token, refreshing from Google if needed.

    The full logic:
    1. Check cache. If hit, return immediately.
    2. Acquire per-account asyncio.Lock.
    3. Re-check cache (another coroutine may have refreshed while we
       were waiting on the lock).
    4. Open a DB session, fetch the row, fail fast if missing or revoked.
    5. Decrypt refresh token, call Google's refresh endpoint.
    6. On invalid_grant, soft-revoke the row and raise TokenUnavailableError.
    7. On success, update the row's access_token_expires_at, populate
       the cache, return the access_token.

    The DB session opened inside the lock is short-lived: open, fetch,
    refresh, update, close. We don't hold the session open across the
    Google call because Google can be slow (multi-second) and we don't
    want to hold a Postgres connection for that duration.
    """
    if not auth0_sub:
        raise ValueError("auth0_sub is required")
    if not account_email:
        raise ValueError("account_email is required")
    email = account_email.strip().lower()
    key = (auth0_sub, email)

    cached = _cache_hit(key)
    if cached is not None:
        return cached

    lock = get_refresh_lock(auth0_sub, email)
    async with lock:
        # Re-check the cache after acquiring the lock; another coroutine
        # may have refreshed while we waited.
        cached = _cache_hit(key)
        if cached is not None:
            return cached

        # Snapshot the row data we need OUTSIDE of holding a DB session
        # across the Google call. Open/close sessions narrowly.
        with session_scope() as session:
            row = get_token(session, auth0_sub=auth0_sub, account_email=email)
            if row is None:
                raise TokenUnavailableError(f"no Google account linked for {auth0_sub}/{email}")
            if row.revoked_at is not None:
                raise TokenUnavailableError(
                    f"Google account {email} is soft-revoked; user must re-link"
                )
            refresh_token_plaintext = get_decrypted_refresh_token(
                row, encryption_key, *prior_encryption_keys
            )
            stored_scope = row.scope
            stored_google_sub = row.google_sub

        try:
            response = await oauth_http.refresh_access_token(
                client_id=google_client_id,
                client_secret=google_client_secret,
                refresh_token=refresh_token_plaintext,
            )
        except oauth_http.GoogleOAuthError as exc:
            # invalid_grant from Google's refresh endpoint signals
            # "the user revoked at Google, or the refresh token has
            # expired (e.g. 7-day testing-mode limit)". This is a
            # terminal state for this row; soft-revoke it and surface
            # a TokenUnavailableError so the caller sees "needs
            # re-link" rather than "retry."
            if exc.status == 400 and "invalid_grant" in (exc.body or ""):
                # invalid_grant is terminal for this row.
                # soft_revoke FIRST so /oauth/status's has_token
                # invariant flips to False, then wipe the ciphertext at
                # rest. Both happen in the same session_scope so the
                # critical pair is atomic at the database boundary.
                with session_scope() as session:
                    row = get_token(session, auth0_sub=auth0_sub, account_email=email)
                    if row is not None:
                        if row.revoked_at is None:
                            soft_revoke(session, row)
                        wipe_token_ciphertext(session, row)
                _drop_cache(key)
                raise TokenUnavailableError(
                    "Google rejected refresh token (invalid_grant); user must re-link"
                ) from exc
            raise

        # Persist the new expiry and (if Google rotated the refresh
        # token, which is rare on refresh but documented as possible)
        # the new refresh token. Scope: keep the existing scope unless
        # Google returned a non-empty one.
        new_expires = datetime.fromtimestamp(response.expires_at_epoch, tz=timezone.utc)
        new_refresh = response.refresh_token or refresh_token_plaintext
        new_scope = response.scope or stored_scope
        with session_scope() as session:
            upsert_token(
                session,
                auth0_sub=auth0_sub,
                account_email=email,
                refresh_token=new_refresh,
                scope=new_scope,
                encryption_key=encryption_key,
                access_token_expires_at=new_expires,
                google_sub=stored_google_sub,
            )

        _store_cache(key, response.access_token, response.expires_at_epoch)
        return response.access_token


async def disconnect_account(
    *,
    auth0_sub: str,
    account_email: str,
    encryption_key: str,
    prior_encryption_keys: tuple[str, ...] = (),
) -> bool:
    """Soft-revoke + ciphertext wipe + best-effort Google revoke.

    Idempotent: already-revoked rows return True; missing rows return
    False. Google revoke is best-effort and runs before the DB writes;
    network errors at Google are logged at info, never raised.

    clears the in-process idempotency cache for this actor
    so a re-link does not return the previous link's cached send.
    also wipes the encrypted_refresh_token at rest
    AFTER soft_revoke flips revoked_at. See module docstring.
    """
    if not auth0_sub or not account_email:
        return False
    email = account_email.strip().lower()
    key = (auth0_sub, email)

    lock = get_refresh_lock(auth0_sub, email)
    async with lock:
        with session_scope() as session:
            row = get_token(session, auth0_sub=auth0_sub, account_email=email)
            if row is None:
                return False
            if row.revoked_at is not None:
                # Already disconnected; idempotent success.
                # also wipe the ciphertext if a  row still
                # carries one, so the at-rest invariant is reached on
                # the second call even when the first call ran on the
                # old code path. wipe_token_ciphertext is idempotent on
                # already-wiped (b"") rows.
                if row.encrypted_refresh_token not in (None, b""):
                    wipe_token_ciphertext(session, row)
                _drop_cache(key)
                _idempotency_cache.clear_for_actor(auth0_sub=auth0_sub, account_email=email)
                return True
            refresh_token_plaintext = get_decrypted_refresh_token(
                row, encryption_key, *prior_encryption_keys
            )

        # Best-effort Google revocation outside the DB session.
        try:
            await oauth_http.revoke_refresh_token(refresh_token_plaintext)
        except Exception as exc:  # noqa: BLE001
            # Never let a Google failure block soft-revoke.
            logger.info("Google revoke call raised: %s", type(exc).__name__)

        # soft_revoke FIRST so the /oauth/status
        # `has_token` invariant flips to False, THEN wipe the
        # ciphertext at rest so a database compromise on revoked
        # accounts does not yield an offline Fernet brute-force
        # target. Both writes share the same session_scope (atomic
        # pair). The "soft_revoke before wipe" ordering is also
        # enforced defensively inside wipe_token_ciphertext; this
        # call site documents the intent.
        with session_scope() as session:
            row = get_token(session, auth0_sub=auth0_sub, account_email=email)
            if row is not None:
                if row.revoked_at is None:
                    soft_revoke(session, row)
                wipe_token_ciphertext(session, row)

        _drop_cache(key)
        # Idempotency cache clear drop any send_email /
        # reply_all entries for this (sub, email) so a same-email
        # re-link does not return the previous link's cached message.
        _idempotency_cache.clear_for_actor(auth0_sub=auth0_sub, account_email=email)
        return True
