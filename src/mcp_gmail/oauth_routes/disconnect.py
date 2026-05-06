"""POST /oauth/disconnect: soft-revoke a Google account link.

Bearer-authenticated. Returns {"disconnected": bool} where bool is
True if a row existed at request time and the soft-revoke completed
(or was already completed), False if no row matched.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse

from ..db import session_scope
from ..gmail_tools.idempotency import default_cache as _idempotency_cache
from ..token_manager import disconnect_account
from ..token_store import get_token
from ._helpers import require_bearer

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/oauth/disconnect")
async def oauth_disconnect(request: Request) -> Any:
    """Soft-revoke the bearer's link to one account_email.

    Request body: {"account_email": "..."}. Returns
    {"disconnected": bool} where bool is True if a row was found AND
    soft-revoked (or was already soft-revoked), False if no row
    matched. Never raises 4xx on "not found" because disconnect of an
    absent account is a no-op success from the user's perspective; we
    return False so the UI can decide whether to surface that.
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
        logger.warning("oauth_disconnect: rejected disallowed auth0_sub=%s", auth0_sub)
        raise HTTPException(
            status_code=403,
            detail="your Auth0 user is not authorized to link Gmail accounts",
        )

    try:
        body = await request.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="request body is not valid JSON") from None
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="request body must be a JSON object")
    account_email = body.get("account_email")
    if not isinstance(account_email, str) or "@" not in account_email:
        raise HTTPException(status_code=400, detail="account_email required")

    # Confirm a row actually exists before invoking the manager so we
    # can return False on absent accounts. token_manager.disconnect_account
    # also returns False on absent rows; we double-check at this layer
    # because manager.disconnect treats "already revoked" as True.
    with session_scope() as session:
        existing = get_token(session, auth0_sub=auth0_sub, account_email=account_email)
        existed = existing is not None

    ok = await disconnect_account(
        auth0_sub=auth0_sub,
        account_email=account_email,
        encryption_key=settings.encryption_key,
        prior_encryption_keys=settings.prior_encryption_keys,
    )
    # route-boundary belt-and-braces idempotency-cache clear.
    # token_manager.disconnect_account already calls clear_for_actor at
    # the end of its critical section; this second call runs strictly
    # AFTER disconnect_account returns and catches any late cache
    # writes that landed during the manager's lock release window. Cost
    # is negligible (in-memory dict scan over an LRU cache).
    _idempotency_cache.clear_for_actor(
        auth0_sub=auth0_sub,
        account_email=account_email.strip().lower(),
    )
    return JSONResponse({"disconnected": bool(ok and existed)})
