"""Pending OAuth link rows backing the post-callback confirmation page.

Layer 2 of the OAuth identity-binding fix. When
`requires_confirm_page=True` the /oauth2callback handler stashes the
verified userinfo + encrypted refresh token here and renders a
confirmation page; only after the user clicks Confirm does the row
land in `gmail_oauth_tokens`. The confirmation step blocks the
consent-phishing attack: a victim who clicks a phishing-flow URL
sees the attacker's principal label and clicks Cancel.

A separate table keeps the live `gmail_oauth_tokens` invariants
intact (a row there represents a confirmed link). A separate module
mirrors `state_store.py`'s single-responsibility shape.

Ciphertext-at-rest discipline
-----------------------------------------
On EVERY exit path (confirm consume, cancel consume, cleanup
expired), the row's `encrypted_refresh_token` is set to NULL AND the
row deleted in the same transaction. No soft-delete pattern leaves
ciphertext indefinitely. The NULL write is defense in depth against
Postgres MVCC tuple persistence pre-autovacuum.

Lifecycle
---------
1. callback.py creates a row via `create_pending_link` (multi-user
   mode only; single-user mode persists inline as ).
2. callback.py redirects to `/oauth/confirm?pending_token=...`.
3. GET renders the confirmation page.
4. POST consumes via `consume_pending_link` (action=confirm) or
   `discard_pending_link` (action=cancel).
5. `cleanup_expired_pending` deletes never-consumed rows after the
   10-minute TTL. No scheduler wired; mirrors the
   nonce cleanup helper in `state_store.py`.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import TIMESTAMP, CheckConstraint, Index, LargeBinary, String, delete, update
from sqlalchemy.orm import Mapped, Session, mapped_column

from .db import Base

logger = logging.getLogger(__name__)


PENDING_LINK_TTL_MINUTES = 10


class OAuthPendingLink(Base):
    """One row per in-flight Google account link awaiting user confirmation.

    Single-use: the `pending_token` is the primary key, and consume
    deletes the row inside the same transaction as the upsert into
    `gmail_oauth_tokens` so a replay sees no row.
    """

    __tablename__ = "oauth_pending_links"

    pending_token: Mapped[str] = mapped_column(String(64), primary_key=True)
    auth0_sub: Mapped[str] = mapped_column(String(255), nullable=False)
    account_email: Mapped[str] = mapped_column(String(320), nullable=False)
    requested_account_email: Mapped[str] = mapped_column(String(320), nullable=False)
    google_sub: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Nullable so the consume/cleanup paths can NULL the ciphertext as
    # the row is being removed (belt-and-suspenders against
    # MVCC tuple persistence).
    encrypted_refresh_token: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    granted_scope: Mapped[str] = mapped_column(String(2048), nullable=False)
    access_token_expires_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)

    __table_args__ = (
        Index("ix_oauth_pending_links_created_at", "created_at"),
        CheckConstraint(
            "account_email = LOWER(account_email)",
            name="ck_oauth_pending_links_email_lowercase",
        ),
    )


@dataclass(frozen=True)
class ConsumedPendingLink:
    """Detached snapshot returned from `consume_pending_link`.

    A plain dataclass (NOT an ORM instance) so the consumed payload
    cannot accidentally be re-attached to the session and re-flush
    a row that was just deleted. The caller decrypts the
    `encrypted_refresh_token` and upserts into `gmail_oauth_tokens`.
    """

    pending_token: str
    auth0_sub: str
    account_email: str
    requested_account_email: str
    google_sub: str | None
    encrypted_refresh_token: bytes
    granted_scope: str
    access_token_expires_at: datetime | None
    created_at: datetime


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _generate_pending_token() -> str:
    """Return a 256-bit URL-safe random string. Mirrors `_generate_nonce`."""
    return secrets.token_urlsafe(32)


def create_pending_link(
    session: Session,
    *,
    auth0_sub: str,
    account_email: str,
    requested_account_email: str,
    encrypted_refresh_token: bytes,
    granted_scope: str,
    access_token_expires_at: datetime | None,
    google_sub: str | None,
) -> str:
    """Create a fresh pending row, persist it, and return the pending_token.

    The caller (callback.py in multi-user mode) has already verified
    state, consumed the nonce, exchanged the code, fetched userinfo,
    and confirmed `email_verified=True`. `account_email` is Google's
    userinfo email (source of truth); `requested_account_email` is
    what the start-time caller asked to link. The confirmation page
    surfaces both so the user can spot a discrepancy.
    """
    if not auth0_sub:
        raise ValueError("auth0_sub is required")
    if not account_email:
        raise ValueError("account_email is required")
    if not requested_account_email:
        raise ValueError("requested_account_email is required")
    if encrypted_refresh_token is None or encrypted_refresh_token == b"":
        raise ValueError("encrypted_refresh_token is required")
    if not granted_scope:
        raise ValueError("granted_scope is required")

    pending_token = _generate_pending_token()
    row = OAuthPendingLink(
        pending_token=pending_token,
        auth0_sub=auth0_sub,
        account_email=account_email.strip().lower(),
        requested_account_email=requested_account_email.strip().lower(),
        google_sub=google_sub,
        encrypted_refresh_token=encrypted_refresh_token,
        granted_scope=granted_scope,
        access_token_expires_at=access_token_expires_at,
        created_at=_now_utc(),
    )
    session.add(row)
    session.flush()
    return pending_token


def get_pending_link(session: Session, pending_token: str) -> OAuthPendingLink | None:
    """Read-only lookup for the GET /oauth/confirm render. None if missing/expired.

    NOT for the POST consume path: that uses `consume_pending_link`
    which is atomic over the read + delete.
    """
    if not pending_token:
        return None
    cutoff = _now_utc() - timedelta(minutes=PENDING_LINK_TTL_MINUTES)
    row = (
        session.query(OAuthPendingLink)
        .filter(OAuthPendingLink.pending_token == pending_token)
        .filter(OAuthPendingLink.created_at >= cutoff)
        .one_or_none()
    )
    return row


def consume_pending_link(session: Session, pending_token: str) -> ConsumedPendingLink | None:
    """Atomically consume a pending row. Returns a detached snapshot if unused and unexpired.

    Single-use guarantee mirrors `consume_nonce`. SELECT the row
    (capturing the ciphertext into a detached dataclass so the
    caller can upsert), then a conditional UPDATE that NULLs the
    ciphertext column ONLY if it is still NOT NULL (atomic single-
    use guard against a racing consumer), then DELETE in the same
    transaction. The caller commits via session_scope after using
    the snapshot; rollback unwinds both the delete and any caller
    upsert atomically.

    NULL the ciphertext BEFORE the
    delete so MVCC's old tuple version does not retain the encrypted
    refresh token.

    Returns a detached snapshot if valid; None if missing, consumed,
    or expired.
    """
    if not pending_token:
        return None
    cutoff = _now_utc() - timedelta(minutes=PENDING_LINK_TTL_MINUTES)

    row = (
        session.query(OAuthPendingLink)
        .filter(OAuthPendingLink.pending_token == pending_token)
        .filter(OAuthPendingLink.created_at >= cutoff)
        .one_or_none()
    )
    if row is None or row.encrypted_refresh_token is None:
        return None
    captured = ConsumedPendingLink(
        pending_token=row.pending_token,
        auth0_sub=row.auth0_sub,
        account_email=row.account_email,
        requested_account_email=row.requested_account_email,
        google_sub=row.google_sub,
        encrypted_refresh_token=row.encrypted_refresh_token,
        granted_scope=row.granted_scope,
        access_token_expires_at=row.access_token_expires_at,
        created_at=row.created_at,
    )

    stmt = (
        update(OAuthPendingLink)
        .where(OAuthPendingLink.pending_token == pending_token)
        .where(OAuthPendingLink.encrypted_refresh_token.is_not(None))
        .where(OAuthPendingLink.created_at >= cutoff)
        .values(encrypted_refresh_token=None)
        .execution_options(synchronize_session=False)
    )
    result = session.execute(stmt)
    if result.rowcount != 1:
        # Lost a race; another caller already consumed.
        return None

    session.execute(delete(OAuthPendingLink).where(OAuthPendingLink.pending_token == pending_token))
    session.flush()
    return captured


def discard_pending_link(session: Session, pending_token: str) -> bool:
    """Drop a pending row without consuming it for confirm.

    Used by POST /oauth/confirm `action=cancel`. NULLs the ciphertext
    in the same transaction as the delete . Does NOT gate
    on TTL: cancel after expiry still cleans up the row. Returns
    True iff a row was removed.
    """
    if not pending_token:
        return False
    session.execute(
        update(OAuthPendingLink)
        .where(OAuthPendingLink.pending_token == pending_token)
        .values(encrypted_refresh_token=None)
        .execution_options(synchronize_session=False)
    )
    result = session.execute(
        delete(OAuthPendingLink).where(OAuthPendingLink.pending_token == pending_token)
    )
    return (result.rowcount or 0) > 0


def cleanup_expired_pending(session: Session) -> int:
    """Delete pending rows older than the TTL. Returns the number removed.

    Mirrors `cleanup_expired`. the service ships the function but does NOT
    wire a scheduler (open follow-up). ciphertext is
    NULLed in the same transaction as the delete.
    """
    cutoff = _now_utc() - timedelta(minutes=PENDING_LINK_TTL_MINUTES)
    session.execute(
        update(OAuthPendingLink)
        .where(OAuthPendingLink.created_at < cutoff)
        .values(encrypted_refresh_token=None)
        .execution_options(synchronize_session=False)
    )
    result = session.execute(delete(OAuthPendingLink).where(OAuthPendingLink.created_at < cutoff))
    return result.rowcount or 0
