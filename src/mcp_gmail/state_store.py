"""Single-use OAuth state nonces.

OAuth `state` is the parameter that the authorization server echoes
back on redirect. Its job is to bind the user's pre-redirect session
to the post-redirect session, so an attacker cannot trick the user's
browser into completing somebody else's OAuth flow (the classic
CSRF-on-OAuth attack).

Why a nonce table at all
------------------------
We could pack everything into an HMAC-signed JWT-like state blob and
verify it stateless on callback. The reason we don't: a stateless
signed blob is replayable until it expires. An attacker who sniffs the
callback URL once can replay it within the window. With a single-use
nonce table, the second redemption attempt fails because the row is
already marked consumed.

Why both a nonce table AND a signed token
-----------------------------------------
The full design is:

1. /oauth/start mints a random 32-byte nonce, stores it in the
   `oauth_state_nonces` table tied to (auth0_sub, account_email),
   and signs a state token containing {nonce, auth0_sub,
   account_email, timestamp} with STATE_SIGNING_KEY (HMAC-SHA256).
2. /oauth2callback gets the state token back from Google, verifies
   the HMAC (catches tampering), pulls the nonce out, calls
   consume_nonce(nonce) (catches replay), and only then proceeds
   to exchange the auth code.

This module owns the table and the consume primitive; the HMAC
sign/verify and the OAuth routes live alongside in `oauth_state.py`
and `oauth_routes/`.

TTL
---
10 minutes from creation. The Google OAuth flow is interactive; if a
user is sitting at the consent screen for >10 minutes they're idle
or distracted and a fresh start is fine. Cleanup of expired rows is a
best-effort cron-style job; the function is shipped in this module
but no scheduler wiring is in place.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import TIMESTAMP, Index, String, delete, update
from sqlalchemy.orm import Mapped, Session, mapped_column

from .db import Base

logger = logging.getLogger(__name__)


NONCE_TTL_MINUTES = 10


class OAuthStateNonce(Base):
    """One row per OAuth `state` nonce.

    The nonce itself is the primary key, not a serial id. That keeps
    consumption to a single UPDATE without a SELECT first, and ensures
    a stale write cannot accidentally bind to a different request's
    nonce row.
    """

    __tablename__ = "oauth_state_nonces"

    nonce: Mapped[str] = mapped_column(String(64), primary_key=True)
    auth0_sub: Mapped[str] = mapped_column(String(255), nullable=False)
    account_email: Mapped[str] = mapped_column(String(320), nullable=False)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)

    __table_args__ = (Index("ix_oauth_state_nonces_created_at", "created_at"),)


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _generate_nonce() -> str:
    """Return a 256-bit URL-safe random string.

    32 bytes via secrets.token_urlsafe gives ~43 characters of base64
    URL-safe text, well under our String(64) column. URL-safe so the
    nonce can sit inside a state token without re-encoding.
    """
    return secrets.token_urlsafe(32)


def create_nonce(
    session: Session,
    *,
    auth0_sub: str,
    account_email: str,
) -> str:
    """Create a fresh nonce, persist it, and return the value to embed in state.

    The caller (the /oauth/start handler) wraps this nonce in an
    HMAC-signed state blob before sending it to Google. Returning the
    bare value keeps the signing concern in one place (the OAuth flow
    module).
    """
    if not auth0_sub:
        raise ValueError("auth0_sub is required")
    if not account_email:
        raise ValueError("account_email is required")
    nonce = _generate_nonce()
    row = OAuthStateNonce(
        nonce=nonce,
        auth0_sub=auth0_sub,
        account_email=account_email.strip().lower(),
        created_at=_now_utc(),
        consumed_at=None,
    )
    session.add(row)
    session.flush()
    return nonce


def consume_nonce(session: Session, nonce: str) -> OAuthStateNonce | None:
    """Atomically consume a nonce. Returns the row only if it was unused and unexpired.

    Atomicity matters: two concurrent callbacks with the same nonce
    must not both succeed. We achieve atomicity with a conditional
    UPDATE: SET consumed_at = now WHERE nonce = :nonce AND consumed_at
    IS NULL AND created_at >= cutoff. If the UPDATE affects 0 rows,
    the nonce is bad (missing, already consumed, or expired). If it
    affects 1 row, this caller is the one true consumer.
    """
    if not nonce:
        return None
    cutoff = _now_utc() - timedelta(minutes=NONCE_TTL_MINUTES)
    now = _now_utc()
    stmt = (
        update(OAuthStateNonce)
        .where(OAuthStateNonce.nonce == nonce)
        .where(OAuthStateNonce.consumed_at.is_(None))
        .where(OAuthStateNonce.created_at >= cutoff)
        .values(consumed_at=now)
        .execution_options(synchronize_session=False)
    )
    result = session.execute(stmt)
    if result.rowcount != 1:
        return None
    # Re-read the row to return its bound metadata (auth0_sub, etc.).
    # We do this AFTER the conditional update so concurrent callers
    # see consistent state.
    return session.query(OAuthStateNonce).filter(OAuthStateNonce.nonce == nonce).one_or_none()


def cleanup_expired(session: Session) -> int:
    """Delete nonces older than the TTL. Returns the number of rows removed.

    Intended to run on a cron-style schedule. This module ships the
    function but does not wire it into a scheduler; that is a later
    follow-up once we have a clearer picture of operational cadence.
    """
    cutoff = _now_utc() - timedelta(minutes=NONCE_TTL_MINUTES)
    stmt = delete(OAuthStateNonce).where(OAuthStateNonce.created_at < cutoff)
    result = session.execute(stmt)
    return result.rowcount or 0
