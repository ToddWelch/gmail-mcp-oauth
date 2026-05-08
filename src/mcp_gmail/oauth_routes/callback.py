"""GET /oauth2callback: Google's redirect target after consent.

NO bearer auth here. Trust comes from the HMAC-signed state token +
single-use nonce + sub fingerprint. Documented in detail in
docs/GMAIL_MCP_OAUTH.md.

Email-mismatch handling
-----------------------
If Google's /userinfo returns a different email than the one
/oauth/start was called with, we DO persist the row (keyed under the
email Google actually authenticated, which is the source of truth) and
return HTTP 200 JSON with status="connected_with_different_email".
The user's connector UI is responsible for displaying the discrepancy.
We log the mismatch at WARN with the requested vs actual emails for
operator visibility. This shape is the documented contract; see
audit-log shape tests for the regression guard.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse

from .. import oauth_http, oauth_state
from ..crypto import encrypt
from ..db import session_scope
from ..pending_link_store import create_pending_link
from ..state_store import consume_nonce
from ..token_store import upsert_token
from ._helpers import callback_html

logger = logging.getLogger(__name__)

router = APIRouter()


@router.get("/oauth2callback")
async def oauth2callback(
    request: Request,
    code: str | None = Query(None),
    state: str | None = Query(None),
    error: str | None = Query(None),
) -> Any:
    """Handle Google's redirect after consent.

    NO bearer auth here. Trust chain documented in module docstring.
    """
    settings = request.app.state.settings

    # Google may redirect with ?error=access_denied if the user
    # declined consent. Render a friendly page rather than a 400 JSON.
    if error:
        logger.info("oauth2callback: google returned error=%s", error)
        return callback_html(False, f"Google reported: {error}")

    if not code or not state:
        logger.info("oauth2callback: missing code or state")
        return callback_html(False, "Missing code or state. Please retry the connection flow.")

    try:
        ctx = oauth_state.verify_state(state, settings.state_signing_key)
    except oauth_state.StateVerificationError as exc:
        # Generic message to the user; specific reason in logs only.
        logger.info("oauth2callback: state verification failed: %s", exc)
        return callback_html(False, "Connection state was invalid or expired. Please retry.")

    # PKCE: state tokens minted before PKCE rollout have no `v` field.
    # Hard-reject rather than silently downgrade so the security
    # property holds for every accepted callback. The deploy window is
    # short and the user can simply restart the flow.
    if ctx.code_verifier is None:
        logger.info("oauth2callback: state missing pkce verifier (legacy)")
        return callback_html(False, "Connection state was invalid or expired. Please retry.")

    # Single-use nonce check. Atomically marks the nonce consumed.
    with session_scope() as session:
        consumed = consume_nonce(session, ctx.nonce)
        if consumed is None:
            logger.info("oauth2callback: nonce missing or already consumed")
            return callback_html(
                False, "This connection link has already been used or expired. Please retry."
            )
        # Defense in depth: the nonce row's stored auth0_sub + email
        # must match the state's claim. The HMAC + fingerprint already
        # bind this, but a row-level mismatch would mean the database
        # was tampered with mid-flow.
        if consumed.auth0_sub != ctx.auth0_sub or consumed.account_email != ctx.account_email:
            logger.warning(
                "oauth2callback: nonce row mismatch for state.sub=%s state.email=%s",
                ctx.auth0_sub,
                ctx.account_email,
            )
            return callback_html(False, "Connection state mismatch. Please retry.")

    # Exchange the code for tokens. Google can be slow here; the
    # session is closed so we don't hold a Postgres connection.
    try:
        tokens = await oauth_http.exchange_code(
            client_id=settings.google_oauth_client_id,
            client_secret=settings.google_oauth_client_secret,
            code=code,
            redirect_uri=settings.google_oauth_redirect_url,
            code_verifier=ctx.code_verifier,
            timeout=settings.http_timeout_seconds,
        )
    except oauth_http.GoogleOAuthError as exc:
        logger.info("oauth2callback: token exchange failed (status=%s)", exc.status)
        return callback_html(False, "Could not exchange Google authorization code. Please retry.")

    if tokens.refresh_token is None:
        # Without prompt=consent + access_type=offline, Google may skip
        # the refresh token. We DO request both, but a previously-linked
        # account can still come back without one. Treat as a hard
        # failure rather than persisting an unusable row.
        logger.info("oauth2callback: google did not return refresh_token")
        return callback_html(
            False,
            "Google did not return a refresh token. Try removing the app at "
            "myaccount.google.com/permissions and retrying.",
        )

    # Userinfo lookup confirms the email + Google sub.
    try:
        info = await oauth_http.fetch_userinfo(
            tokens.access_token, timeout=settings.http_timeout_seconds
        )
    except oauth_http.GoogleOAuthError as exc:
        logger.info("oauth2callback: userinfo failed (status=%s)", exc.status)
        return callback_html(False, "Could not verify Google account. Please retry.")

    # refuse to persist a token row when Google
    # reports the email as unverified. A consumer Google account with
    # an unverified email could be used to impersonate any
    # not-yet-claimed Workspace mailbox of the same address. Setting
    # this gate AFTER fetch_userinfo means the unverified-email
    # bearer never reaches upsert_token. WARN log so operators can
    # see denied links in production logs without leaking the email
    # at INFO (the email is on the WARN line and only WARN; this
    # line is rare).
    if info.email_verified is not True:
        logger.warning(
            "oauth2callback: Google reported email_verified=false "
            "auth0_sub=%s requested=%s actual=%s",
            ctx.auth0_sub,
            ctx.account_email,
            info.email,
        )
        return callback_html(
            False,
            "Google reported email as unverified for this account. "
            "Verify the address with Google and try again.",
        )

    # Persist. The granted scope (tokens.scope) is what we record, NOT
    # the requested scope; Google may grant fewer scopes than asked.
    # The expiry is computed from Google's expires_in.
    #
    # Source-of-truth for which mailbox is linked is Google's userinfo
    # email, NOT the requested account_email. If the user signed in
    # with a different Google account than they asked to link, we
    # persist under info.email and surface the discrepancy in the
    # response so the connector UI can display it.
    expires_at = datetime.fromtimestamp(tokens.expires_at_epoch, tz=timezone.utc)
    granted_scope = tokens.scope or ""
    persisted_email = info.email

    # split the persist path on `requires_confirm_page`.
    # Single-user mode (False, the default in current production)
    # upserts inline as . Multi-user mode (True) stashes
    # the encrypted refresh token in `oauth_pending_links` and
    # redirects to /oauth/confirm so the user can spot a phishing-
    # induced linkage before any token row is created.
    if settings.requires_confirm_page:
        encrypted = encrypt(tokens.refresh_token, settings.encryption_key)
        with session_scope() as session:
            pending_token = create_pending_link(
                session,
                auth0_sub=ctx.auth0_sub,
                account_email=persisted_email,
                requested_account_email=ctx.account_email,
                encrypted_refresh_token=encrypted,
                granted_scope=granted_scope,
                access_token_expires_at=expires_at,
                google_sub=info.sub,
            )
        logger.info(
            "oauth2callback: pending link created auth0_sub=%s account_email=%s",
            ctx.auth0_sub,
            persisted_email,
        )
        # 303 See Other so the browser issues a GET on the redirect
        # target (it would have done so for 302/307 too in this
        # context but 303 is the spec-correct answer when the
        # callback is effectively the result of a form-style POST
        # at Google's end).
        return RedirectResponse(
            url=f"/oauth/confirm?pending_token={pending_token}",
            status_code=303,
        )

    with session_scope() as session:
        upsert_token(
            session,
            auth0_sub=ctx.auth0_sub,
            account_email=persisted_email,
            refresh_token=tokens.refresh_token,
            scope=granted_scope,
            encryption_key=settings.encryption_key,
            access_token_expires_at=expires_at,
            google_sub=info.sub,
        )

    if persisted_email != ctx.account_email:
        # Different mailbox than was requested. Persist already happened
        # under the actual mailbox; surface the discrepancy as a 200 JSON
        # so the connector UI can show "Connected as info.email even
        # though you asked for ctx.account_email." Logging at WARN so
        # operators see the mismatch in production logs.
        logger.warning(
            "oauth2callback: connected_with_different_email auth0_sub=%s requested=%s actual=%s",
            ctx.auth0_sub,
            ctx.account_email,
            persisted_email,
        )
        return JSONResponse(
            status_code=200,
            content={
                "status": "connected_with_different_email",
                "requested": ctx.account_email,
                "actual": persisted_email,
            },
        )

    logger.info(
        "oauth2callback: linked auth0_sub=%s account_email=%s",
        ctx.auth0_sub,
        persisted_email,
    )
    return callback_html(True, f"Connected {persisted_email}.")
