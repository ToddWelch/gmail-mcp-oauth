"""OAuth refresh-token storage for Gmail accounts.

Schema
------
One row per (auth0_sub, account_email) tuple. `auth0_sub` is the JWT
subject claim from the bearer token used to authenticate the MCP
request; that is the canonical identifier for "the human authorizing
this connector." `account_email` is the Google address of the Gmail
mailbox that human linked to their connector. One human can link
multiple mailboxes.

The refresh token is stored Fernet-encrypted as BYTEA. The access
token is NOT stored; it lives in memory only and is re-fetched from
Google whenever it expires. The expiry timestamp `access_token_expires_at`
is kept so the refresh path can know when to refresh proactively (e.g.
1 minute before expiry to avoid races with in-flight requests).

Audit logging discipline
------------------------
Acceptable log fields: auth0_sub, account_email, tool_name,
message_id (when applicable), and outcome. NEVER log: subject, body,
recipients, attachment data, access tokens, refresh tokens, OAuth
authorization codes, or any value that round-trips through Fernet.
This module's purpose is to keep those last categories out of every
other module's reach; logging them here would defeat that boundary.

Concurrency model: per-key asyncio.Lock + single-replica assumption
-------------------------------------------------------------------
Google serializes refreshes per refresh_token. We hold a per-
(auth0_sub, account_email) asyncio.Lock around each refresh; lock
dict is in-process. Single-replica only: at >1 replica each replica
has its own dict and refresh races are possible. The replica-count
guard makes the multi-replica configuration fail-closed at startup
unless explicitly overridden; see server.py.

`wipe_token_ciphertext` exists for the disconnect path so no
decryptable refresh-token ciphertext lingers at rest after
disconnect. The status route's has_token invariant keeps working
because soft_revoke runs before the wipe.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy import (
    TIMESTAMP,
    CheckConstraint,
    Index,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, Session, mapped_column

from .crypto import decrypt, encrypt
from .db import Base

logger = logging.getLogger(__name__)


class GmailOAuthToken(Base):
    """One Gmail account linked to one Auth0-authenticated user.

    Columns: id (surrogate PK); auth0_sub (JWT sub claim);
    account_email (lowercased, UNIQUE per (auth0_sub, account_email)
    + Postgres CHECK = LOWER()); google_sub (stable Google sub from
    id_token); encrypted_refresh_token (Fernet ciphertext, plaintext
    never in DB); scope (granted scope string from Google);
    access_token_expires_at (access token itself not stored, just
    expiry hint for refresh); last_used_at (drives day-6 re-auth ping
    cron); revoked_at (soft-delete); created_at, updated_at.
    """

    __tablename__ = "gmail_oauth_tokens"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    auth0_sub: Mapped[str] = mapped_column(String(255), nullable=False)
    account_email: Mapped[str] = mapped_column(String(320), nullable=False)
    google_sub: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # LargeBinary maps to BYTEA on Postgres and BLOB on SQLite. The
    # Item 7: nullable per migration 0002. Disconnect wipes the
    # ciphertext to b"" so /oauth/status `has_token` (is not None AND
    # revoked_at is None) flips to False on a wiped+revoked row.
    encrypted_refresh_token: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    scope: Mapped[str] = mapped_column(String(2048), nullable=False)
    access_token_expires_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("auth0_sub", "account_email", name="uq_gmail_tokens_user_email"),
        # The UNIQUE(auth0_sub, account_email) above creates a btree
        # index that already supports lookups on auth0_sub alone via
        # left-prefix scanning. No separate single-column index needed.
        # Keep an explicit name for `last_used_at` to support the
        # day-6 re-auth ping cron which scans the table by
        # last_used_at.
        Index("ix_gmail_tokens_last_used_at", "last_used_at"),
        CheckConstraint(
            "account_email = LOWER(account_email)",
            name="ck_gmail_tokens_email_lowercase",
        ),
    )


# ---------------------------------------------------------------------------
# Per-key asyncio.Lock registry
# ---------------------------------------------------------------------------
#
# A WeakValueDictionary would be nicer, but asyncio.Lock is a plain
# object and we want the same lock instance to outlive a momentary lull
# in references during a refresh (otherwise a second caller could grab
# a fresh lock and bypass the serialization). A simple dict is correct;
# memory cost is bounded by the number of distinct (auth0_sub,
# account_email) pairs, which is small (one human, a few mailboxes).

_locks: dict[tuple[str, str], asyncio.Lock] = {}


def get_refresh_lock(auth0_sub: str, account_email: str) -> asyncio.Lock:
    """Return the per-account refresh lock, creating it lazily.

    Used by the OAuth refresh path. Exposed here so tests can assert
    the lock is acquired and released around mutations.
    """
    key = (auth0_sub, account_email)
    lock = _locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _locks[key] = lock
    return lock


def reset_locks_for_tests() -> None:
    """Test helper: clear the per-key lock registry between test cases."""
    _locks.clear()


# ---------------------------------------------------------------------------
# CRUD primitives
# ---------------------------------------------------------------------------


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def upsert_token(
    session: Session,
    *,
    auth0_sub: str,
    account_email: str,
    refresh_token: str,
    scope: str,
    encryption_key: str,
    access_token_expires_at: datetime | None = None,
    google_sub: str | None = None,
) -> GmailOAuthToken:
    """Create or update a token row.

    The refresh token is encrypted with Fernet before any value reaches
    SQL. Email is lowercased here (and the DB CHECK enforces it
    independently). On update, `created_at` is preserved; `updated_at`
    is bumped. `revoked_at` is cleared on update so re-linking an
    account "un-soft-deletes" it.
    """
    if not auth0_sub:
        raise ValueError("auth0_sub is required")
    if not account_email:
        raise ValueError("account_email is required")
    email = account_email.strip().lower()
    if not email:
        raise ValueError("account_email is empty after normalization")

    encrypted = encrypt(refresh_token, encryption_key)
    now = _now_utc()

    existing = (
        session.query(GmailOAuthToken)
        .filter_by(auth0_sub=auth0_sub, account_email=email)
        .one_or_none()
    )
    if existing is None:
        row = GmailOAuthToken(
            auth0_sub=auth0_sub,
            account_email=email,
            google_sub=google_sub,
            encrypted_refresh_token=encrypted,
            scope=scope,
            access_token_expires_at=access_token_expires_at,
            created_at=now,
            updated_at=now,
        )
        session.add(row)
        session.flush()
        return row

    existing.encrypted_refresh_token = encrypted
    existing.scope = scope
    existing.access_token_expires_at = access_token_expires_at
    if google_sub is not None:
        existing.google_sub = google_sub
    existing.revoked_at = None
    existing.updated_at = now
    session.flush()
    return existing


def get_token(
    session: Session,
    *,
    auth0_sub: str,
    account_email: str,
) -> GmailOAuthToken | None:
    """Return the token row or None. Lowercases the email for lookup."""
    email = account_email.strip().lower()
    return (
        session.query(GmailOAuthToken)
        .filter_by(auth0_sub=auth0_sub, account_email=email)
        .one_or_none()
    )


class TokenCiphertextWipedError(Exception):
    """Raised when get_decrypted_refresh_token sees a wiped/NULL ciphertext.

    distinguishes "deliberately wiped on disconnect"
    from generic decrypt failures so callers can surface re-link UX.
    """


def get_decrypted_refresh_token(
    row: GmailOAuthToken,
    encryption_key: str,
    *prior_encryption_keys: str,
) -> str:
    """Decrypt and return the refresh-token plaintext. Short-lived; never store.

    when `*prior_encryption_keys` are passed (typically
    from `Settings.prior_encryption_keys`), the crypto layer routes
    through MultiFernet so ciphertext written under any prior key
    still decrypts. The default empty tuple keeps the
    single-key signature working for callers that have not threaded
    `prior_encryption_keys` through their settings access yet
    (notably the test suite, which constructs rows with the active
    key only).

    Raises TokenCiphertextWipedError when the row's ciphertext is
    NULL or b"" (disconnect-wipe state). The only
    legitimate recovery is to re-link the account.
    """
    ciphertext = row.encrypted_refresh_token
    if ciphertext is None or ciphertext == b"":
        raise TokenCiphertextWipedError(
            "refresh token ciphertext was wiped on disconnect; user must re-link"
        )
    return decrypt(ciphertext, encryption_key, *prior_encryption_keys)


def mark_used(session: Session, row: GmailOAuthToken) -> None:
    """Bump last_used_at to now. Called after a successful tool dispatch."""
    row.last_used_at = _now_utc()
    row.updated_at = row.last_used_at
    session.flush()


def soft_revoke(session: Session, row: GmailOAuthToken) -> None:
    """Mark the row revoked. Token data stays for audit; queries should filter."""
    now = _now_utc()
    row.revoked_at = now
    row.updated_at = now
    session.flush()


def wipe_token_ciphertext(session: Session, row: GmailOAuthToken) -> None:
    """Wipe the encrypted refresh token at rest.

    Sets `encrypted_refresh_token` to b"" so /oauth/status's
    `has_token` (is not None AND revoked_at is None) keeps the
    `is not None` side True while soft_revoke flips the
    `revoked_at is None` side False. Wiping without revoking would
    leave has_token=True on an unusable row, so we defensively set
    revoked_at if the caller forgot. Idempotent on already-wiped rows.
    """
    now = _now_utc()
    if row.revoked_at is None:
        row.revoked_at = now
    row.encrypted_refresh_token = b""
    row.updated_at = now
    session.flush()
