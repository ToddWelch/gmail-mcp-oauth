"""GET /oauth/start: begin a Google OAuth handshake.

Bearer-authenticated. Mints a single-use nonce, signs an HMAC state
token, and either returns Google's consent URL as JSON or 302-redirects
the browser to it.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import RedirectResponse

from .. import oauth_state, pkce
from ..db import session_scope
from ..state_store import create_nonce
from ._helpers import require_bearer

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/oauth/start")
async def oauth_start(
    request: Request,
    account_email: str = Query(..., min_length=3, max_length=320),
    redirect: bool = Query(False),
) -> Any:
    """Begin a Google OAuth handshake for the bearer's auth0_sub + account_email.

    Behavior
    --------
    - 401 if bearer is missing or invalid.
    - 400 if account_email is not an email-shape string.
    - Mints a nonce, persists it in oauth_state_nonces, signs a state
      token, returns either:
        - JSON {"authorization_url": "..."} if redirect=false (default), or
        - 302 redirect to Google if redirect=true (preferred for browser
          flows; the JSON shape is for programmatic clients that want to
          drive the redirect themselves).

    The bearer's auth0_sub is taken from the validated JWT's `sub`
    claim. account_email comes from the query string because one human
    may link multiple mailboxes; the connector UX pins which one this
    handshake is for.
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
        logger.warning("oauth_start: rejected disallowed auth0_sub=%s", auth0_sub)
        raise HTTPException(
            status_code=403,
            detail="your Auth0 user is not authorized to link Gmail accounts",
        )
    email = account_email.strip().lower()
    if "@" not in email or len(email) < 3:
        raise HTTPException(status_code=400, detail="account_email is not an email address")

    with session_scope() as session:
        nonce = create_nonce(session, auth0_sub=auth0_sub, account_email=email)

    # PKCE: mint per-flow verifier + S256 challenge. Verifier stays in
    # the HMAC-signed state; challenge goes on the auth URL. Never log
    # the verifier (audit() has no `code_verifier` kwarg, structurally
    # blocking misuse; this site has no log line for it either).
    code_verifier = pkce.generate_verifier()
    code_challenge = pkce.compute_challenge(code_verifier)

    state = oauth_state.sign_state(
        nonce=nonce,
        auth0_sub=auth0_sub,
        account_email=email,
        signing_key=settings.state_signing_key,
        code_verifier=code_verifier,
    )
    auth_url = oauth_state.build_authorization_url(
        client_id=settings.google_oauth_client_id,
        redirect_uri=settings.google_oauth_redirect_url,
        scopes=list(settings.gmail_oauth_scopes),
        state=state,
        login_hint=email,
        code_challenge=code_challenge,
    )
    # Audit log: never log the state token (contains the nonce; even
    # though single-use, no need to expose). auth0_sub + email are
    # acceptable per token_store's audit discipline.
    logger.info("oauth_start: auth0_sub=%s account_email=%s", auth0_sub, email)

    if redirect:
        # 307 would also work, but 302 is the conventional choice for
        # OAuth start redirects and matches what Google docs recommend.
        return RedirectResponse(url=auth_url, status_code=302)
    return {"authorization_url": auth_url}
