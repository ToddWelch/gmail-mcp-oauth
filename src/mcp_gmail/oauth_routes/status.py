"""GET /oauth/status: list the bearer's linked Google accounts.

Bearer-authenticated. Returns metadata only (never refresh_token,
access_token, or any Fernet ciphertext).

Default behavior is to filter out soft-revoked rows (`revoked_at IS
NOT NULL`). Pass `?include_revoked=true` to include revoked rows; this
is intended for an admin or audit UI that needs to see the full
history.

Each account record now exposes an explicit `is_revoked` boolean so
the UI does not have to introspect `revoked_at` to know the row's
state. `is_revoked` is `false` for active rows and `true` for revoked
rows.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from sqlalchemy import select

from ..db import session_scope
from ..token_store import GmailOAuthToken
from ._helpers import require_bearer

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/oauth/status")
async def oauth_status(
    request: Request,
    include_revoked: bool = Query(
        False,
        description=(
            "When false (default), revoked rows are filtered out of the response. "
            "When true, revoked rows are included with is_revoked=true."
        ),
    ),
) -> Any:
    """Return the connection state for the bearer's auth0_sub.

    Response shape:

        {
          "accounts": [
            {
              "account_email": "user@example.com",
              "has_token": true,
              "is_revoked": false,
              "scope": "openid email https://...",
              "revoked_at": null,
              "last_used_at": null,
              "access_token_expires_at": "2026-...Z" | null
            },
            ...
          ]
        }

    Never includes refresh_token, access_token, or any Fernet
    ciphertext. has_token is the boolean the rest of the project uses
    on similar endpoints. is_revoked is `revoked_at IS NOT NULL` as a
    convenience for the UI.
    """
    settings = request.app.state.settings
    claims = await require_bearer(request)
    auth0_sub = claims.get("sub")
    if not auth0_sub or not isinstance(auth0_sub, str):
        raise HTTPException(status_code=401, detail="bearer missing sub claim")
    # allowlist gate. The bearer is valid (require_bearer
    # would have 401-ed otherwise); rejection here is "principal not
    # authorized to link Gmail accounts" so the response code is 403.
    # The message is intentionally non-leaky: it confirms the user's
    # token is recognized but does not list which subs are allowed,
    # nor does it distinguish between empty-allowlist and
    # not-on-allowlist failures.
    if not settings.is_auth0_sub_allowed(auth0_sub):
        logger.warning("oauth_status: rejected disallowed auth0_sub=%s", auth0_sub)
        raise HTTPException(
            status_code=403,
            detail="your Auth0 user is not authorized to link Gmail accounts",
        )

    with session_scope() as session:
        # SQLAlchemy 2.0-style `select()`. The legacy `session.query()`
        # API is still supported but deprecated for new code; modern
        # `select()` keeps query construction explicit and lets us
        # compose `.where()` clauses cleanly.
        stmt = select(GmailOAuthToken).where(GmailOAuthToken.auth0_sub == auth0_sub)
        if not include_revoked:
            stmt = stmt.where(GmailOAuthToken.revoked_at.is_(None))
        stmt = stmt.order_by(GmailOAuthToken.account_email)
        rows = session.execute(stmt).scalars().all()

        out = [
            {
                "account_email": r.account_email,
                "has_token": r.encrypted_refresh_token is not None and r.revoked_at is None,
                "is_revoked": r.revoked_at is not None,
                "scope": r.scope,
                "revoked_at": r.revoked_at.isoformat() if r.revoked_at else None,
                "last_used_at": r.last_used_at.isoformat() if r.last_used_at else None,
                "access_token_expires_at": r.access_token_expires_at.isoformat()
                if r.access_token_expires_at
                else None,
            }
            for r in rows
        ]
    return {"accounts": out}
