"""FastAPI routers for the Google OAuth flow.

Endpoints
---------
GET  /oauth/start         Bearer-authenticated. Mints a nonce, signs a
                          state token, returns Google's consent URL
                          (or 302-redirects there). See start.py.
GET  /oauth2callback      No bearer. Trust comes from the HMAC-signed
                          state token + single-use nonce + sub
                          fingerprint. Exchanges the code, fetches
                          userinfo, persists the encrypted refresh
                          token. See callback.py.
GET  /oauth/status        Bearer-authenticated. Returns the connection
                          state for the bearer's auth0_sub. Defaults
                          to active rows only; pass
                          ?include_revoked=true to see revoked rows.
                          Never returns secret material; only has_token
                          and is_revoked booleans. See status.py.
POST /oauth/disconnect    Bearer-authenticated. Soft-revokes the
                          bearer's link to a specific account_email.
                          See disconnect.py.

Why no bearer at /oauth2callback
--------------------------------
Google performs the redirect from a third-party browser context where
the original Auth0 bearer is not available. The trust chain at the
callback is:

1. HMAC-SHA256 over the state payload, verified with STATE_SIGNING_KEY.
   Tampering breaks the signature.
2. Single-use nonce table (state_store), verified atomically. Replay
   breaks because the second consume returns 0 rows.
3. sub_fingerprint inside the state payload, recomputed from the
   verified payload's auth0_sub + email and the signing key. A
   structural mismatch (e.g. an attacker who somehow swaps the email
   field) is caught here even if the HMAC happened to validate.

This trade-off (no bearer at the OAuth callback) is bounded by the
HMAC + nonce + sub-fingerprint chain documented above. PKCE is a
worthwhile follow-up but not required for confidential clients with
this nonce + HMAC layering. See docs/GMAIL_MCP_OAUTH.md for the
explicit revisit conditions.

Why a package, not a single module
----------------------------------
The original `oauth_routes.py` reached 421 LOC, which violates the
project's "files under 300 LOC" rule. The endpoints have nothing in
common except shared bearer-validation and an HTML callback helper, so
splitting one file per endpoint is the natural division. Each module
exposes its own `APIRouter()`; this `__init__.py` aggregates them into
the single `router` that server.py mounts.
"""

from __future__ import annotations

from fastapi import APIRouter

from . import callback, confirm, disconnect, start, status

router = APIRouter()
router.include_router(start.router)
router.include_router(callback.router)
router.include_router(confirm.router)
router.include_router(status.router)
router.include_router(disconnect.router)

__all__ = ["router"]
