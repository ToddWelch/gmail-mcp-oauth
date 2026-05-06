"""GET /oauth/confirm and POST /oauth/confirm: post-callback confirmation page.

Layer 2 of the OAuth identity-binding fix. Active
when `settings.requires_confirm_page=True` (multi-user mode or
emergency `MCP_ALLOW_ANY_AUTH0_SUB=true`). Dormant in single-user
mode; the callback persists the token inline and never redirects
here.

GET flow
--------
The /oauth2callback handler redirects the user's browser to
`/oauth/confirm?pending_token=...` after Google OAuth completes,
the email is verified, and the encrypted refresh token is stashed
in `oauth_pending_links`. The GET handler renders an HTML page that
displays:
  - The Auth0 principal label that owns the linkage.
  - The mailbox the user was asked to link vs the mailbox Google
    actually authenticated.
  - Confirm and Cancel buttons that POST back to /oauth/confirm.

The page is rendered via `oauth_routes/_helpers.confirm_page_html`
which enforces the HTML escape contract and the
anti-phishing wording.

POST flow
---------
The form POSTs `pending_token` (hidden input) and `action`
(confirm or cancel) as form-encoded fields. The handler:
  1. Re-checks the allowlist for the pending row's auth0_sub.
     If the principal has been removed from the allowlist
     during the 10-minute confirmation window, fail with 403
     and drop the row.
  2. On action=confirm: atomically consume the row via
     `consume_pending_link` and upsert into `gmail_oauth_tokens`
     in the SAME transaction. Returns the standard "Connected"
     callback HTML on success.
  3. On action=cancel: drop the row via `discard_pending_link`.
     Returns a "Cancelled" HTML page; nothing else happens.
  4. On unknown / missing token / expired / replay: returns the
     generic "Connection state was invalid or expired" HTML.

NO bearer auth on these routes
------------------------------
Like /oauth2callback, these routes are reachable from a browser
context where the original Auth0 bearer is not available. Trust
comes from:
  1. The opaque `pending_token` (single-use, 10-minute TTL).
  2. The pending row's stored auth0_sub being on the allowlist
     at the moment of POST (re-check).
"""

from __future__ import annotations

import logging
from typing import Any

from urllib.parse import parse_qs

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse

from ..crypto import decrypt
from ..db import session_scope
from ..pending_link_store import (
    ConsumedPendingLink,
    consume_pending_link,
    discard_pending_link,
    get_pending_link,
)
from ..token_store import upsert_token
from ._helpers import callback_html, confirm_page_html

logger = logging.getLogger(__name__)

router = APIRouter()


def _principal_label(auth0_sub: str) -> str:
    """Best-effort human-readable label for an Auth0 sub.

    open question (deferred to multi-user phase): a future
    iteration may pull the label from Auth0 userinfo or a
    `MCP_AUTH0_SUB_LABELS` env-var map. For now we display the raw
    sub so the page is honest about what is bound to the link.
    """
    return auth0_sub


@router.get("/oauth/confirm")
async def oauth_confirm_get(
    request: Request,
    pending_token: str = Query(..., min_length=20, max_length=64),
) -> HTMLResponse:
    """Render the confirmation page for a pending OAuth link."""
    settings = request.app.state.settings
    # If the service is not running with the confirm flow active,
    # this endpoint should not be reachable as part of any flow we
    # mint. Return generic failure to keep the surface narrow.
    if not settings.requires_confirm_page:
        logger.info("oauth_confirm_get: confirm flow not active in this mode")
        return callback_html(False, "Connection state was invalid or expired. Please retry.")

    with session_scope() as session:
        row = get_pending_link(session, pending_token)
        if row is None:
            logger.info("oauth_confirm_get: pending row missing or expired")
            return callback_html(False, "Connection state was invalid or expired. Please retry.")
        # Snapshot the fields we need to render. The session closes
        # after the with-block; the ORM instance becomes detached.
        snapshot = {
            "auth0_sub": row.auth0_sub,
            "account_email": row.account_email,
            "requested_account_email": row.requested_account_email,
            "granted_scope": row.granted_scope,
        }

    return confirm_page_html(
        pending_token=pending_token,
        principal_label=_principal_label(snapshot["auth0_sub"]),
        requested_account_email=snapshot["requested_account_email"],
        actual_account_email=snapshot["account_email"],
        granted_scope=snapshot["granted_scope"],
    )


def _finalize_confirm(
    *,
    captured: ConsumedPendingLink,
    settings: Any,
    session: Any,
) -> None:
    """Decrypt, re-encrypt, and upsert into gmail_oauth_tokens.

    Called inside the same session_scope as `consume_pending_link`
    so the pending-row delete and the live-row upsert commit (or
    rollback) atomically. Decrypt + re-encrypt is intentional: the
    encryption key may have rotated between create and consume; the
    upsert path enforces the current key.
    """
    plaintext = decrypt(
        captured.encrypted_refresh_token,
        settings.encryption_key,
        *settings.prior_encryption_keys,
    )
    upsert_token(
        session,
        auth0_sub=captured.auth0_sub,
        account_email=captured.account_email,
        refresh_token=plaintext,
        scope=captured.granted_scope,
        encryption_key=settings.encryption_key,
        access_token_expires_at=captured.access_token_expires_at,
        google_sub=captured.google_sub,
    )


def _parse_form(raw: bytes) -> dict[str, str]:
    """Parse `application/x-www-form-urlencoded` bodies without python-multipart.

    The confirmation page only sends two fields, both small. Using
    `urllib.parse.parse_qs` keeps the dependency surface minimal
    (mcp-gmail does not ship python-multipart and adding one
    cross-PR for one form would be a flag-worthy dep bump).
    """
    parsed = parse_qs(raw.decode("utf-8", errors="replace"), keep_blank_values=False)
    out: dict[str, str] = {}
    for key, values in parsed.items():
        if values:
            out[key] = values[0]
    return out


@router.post("/oauth/confirm")
async def oauth_confirm_post(request: Request) -> HTMLResponse:
    """Consume a pending row according to the user's action.

    Form fields parsed manually from the request body to avoid the
    `python-multipart` dependency that FastAPI's `Form(...)` requires.
    """
    settings = request.app.state.settings
    raw_body = await request.body()
    form = _parse_form(raw_body)
    pending_token = form.get("pending_token", "").strip()
    action = form.get("action", "").strip()
    if not pending_token or len(pending_token) < 20 or len(pending_token) > 64:
        logger.info("oauth_confirm_post: pending_token missing or wrong length")
        return callback_html(False, "Connection state was invalid or expired. Please retry.")
    if not settings.requires_confirm_page:
        logger.info("oauth_confirm_post: confirm flow not active in this mode")
        return callback_html(False, "Connection state was invalid or expired. Please retry.")
    if action not in ("confirm", "cancel"):
        logger.info("oauth_confirm_post: unknown action=%s", action)
        return callback_html(False, "Connection state was invalid or expired. Please retry.")

    if action == "cancel":
        with session_scope() as session:
            removed = discard_pending_link(session, pending_token)
        if removed:
            logger.info("oauth_confirm_post: user cancelled pending link")
        else:
            logger.info("oauth_confirm_post: cancel on missing/expired pending row")
        return callback_html(
            True if removed else False,
            "Connection cancelled. No mailbox was linked."
            if removed
            else "Connection state was invalid or expired. Please retry.",
        )

    # action == "confirm"
    # re-check the allowlist BEFORE consuming the pending
    # row. If the principal was removed from MCP_ALLOWED_AUTH0_SUBS
    # during the 10-minute confirm window, drop the row and fail
    # with 403. The discard happens in the same session as a
    # peek-then-discard so we do not leave the row decryptable.
    with session_scope() as session:
        peek = get_pending_link(session, pending_token)
        if peek is None:
            logger.info("oauth_confirm_post: pending row missing or expired")
            return callback_html(False, "Connection state was invalid or expired. Please retry.")
        peek_sub = peek.auth0_sub
        if not settings.is_auth0_sub_allowed(peek_sub):
            # Drop the row; do NOT consume.
            discard_pending_link(session, pending_token)
            logger.warning(
                "oauth_confirm_post: principal not on allowlist at confirm auth0_sub=%s",
                peek_sub,
            )
            return callback_html(
                False,
                "Your Auth0 user is not authorized to link Gmail accounts.",
            )

    # Atomic consume + upsert in the same transaction.
    with session_scope() as session:
        captured = consume_pending_link(session, pending_token)
        if captured is None:
            logger.info("oauth_confirm_post: pending row already consumed or expired")
            return callback_html(False, "Connection state was invalid or expired. Please retry.")
        try:
            _finalize_confirm(captured=captured, settings=settings, session=session)
        except Exception as exc:  # noqa: BLE001
            # Rollback unwinds both the consume_pending_link delete
            # AND the upsert; the pending row stays available for a
            # retry inside its TTL window.
            logger.warning("oauth_confirm_post: upsert failed: %s", type(exc).__name__)
            raise
        persisted_email = captured.account_email
        auth0_sub = captured.auth0_sub

    logger.info(
        "oauth_confirm_post: linked auth0_sub=%s account_email=%s",
        auth0_sub,
        persisted_email,
    )
    return callback_html(True, f"Connected {persisted_email}.")
