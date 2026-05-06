"""Shared helpers for the OAuth FastAPI routes.

The four route modules (start, callback, status, disconnect) all need
to validate inbound bearer tokens or render minimal HTML pages. Those
helpers live here so each route module stays focused on its endpoint
logic.
"""

from __future__ import annotations

import html
from typing import Any

from fastapi import HTTPException, Request
from fastapi.responses import HTMLResponse

from ..auth import AuthError, build_www_authenticate, validate_bearer_token


def extract_bearer(request: Request) -> str | None:
    """Pull the bearer token out of the Authorization header. None if absent."""
    auth_header = request.headers.get("Authorization", "")
    prefix = "Bearer "
    if not auth_header.startswith(prefix):
        return None
    return auth_header[len(prefix) :].strip()


async def require_bearer(request: Request) -> dict[str, Any]:
    """Validate the inbound bearer token and return its claims.

    Raises HTTPException(401) on any auth failure with the same
    WWW-Authenticate shape as /mcp uses, so the MCP client's
    auth-discovery chain works identically against /oauth/* and /mcp.
    """
    settings = request.app.state.settings
    token = extract_bearer(request)
    if token is None:
        raise HTTPException(
            status_code=401,
            detail="missing_bearer_token",
            headers={"WWW-Authenticate": build_www_authenticate(settings, "invalid_token")},
        )
    try:
        return await validate_bearer_token(token, settings)
    except AuthError as exc:
        raise HTTPException(
            status_code=401,
            detail=exc.reason,
            headers={"WWW-Authenticate": build_www_authenticate(settings, exc.reason)},
        ) from exc


def confirm_page_html(
    *,
    pending_token: str,
    principal_label: str,
    requested_account_email: str,
    actual_account_email: str,
    granted_scope: str,
) -> HTMLResponse:
    """Render the post-callback confirmation page.

    The page asks the signed-in user to confirm or cancel a pending
    Gmail link before the service persists the encrypted refresh
    token. It exists to defeat consent-phishing: an attacker who has
    started an OAuth flow under their own MCP principal but lured a
    victim to complete Google's consent step is exposed by the page
    because the victim sees the attacker's principal label rather
    than their own.

    Three contracts the helper must preserve:

    1. HTML-escape every interpolated dynamic value via
       `html.escape(..., quote=True)`. The surface area is four
       caller-supplied strings; an unescaped value would let the
       operator label or an email address inject markup that breaks
       out of the surrounding context.

    2. The anti-phishing wording (the sentence beginning "If you did
       not start this connection request yourself") is bound
       verbatim. Paraphrasing weakens the cue the page is meant to
       provide.

    3. `pending_token` travels via a hidden form input on the POST,
       not the URL path or query. The token MAY appear in the GET
       URL when the callback redirects here, but the form action
       does NOT echo it back into a query-string attribute.
    """
    safe_token = html.escape(pending_token, quote=True)
    safe_principal = html.escape(principal_label, quote=True)
    safe_requested = html.escape(requested_account_email, quote=True)
    safe_actual = html.escape(actual_account_email, quote=True)
    safe_scope = html.escape(granted_scope, quote=True)
    title = "Confirm Gmail account link"
    body = (
        "<!DOCTYPE html>"
        f"<html><head><meta charset='utf-8'><title>{html.escape(title)}</title></head>"
        "<body style='font-family: system-ui, sans-serif; padding: 2em; max-width: 640px;'>"
        f"<h1 style='color: #0f3f6f'>{html.escape(title)}</h1>"
        f"<p>This service is asking to link the Google mailbox "
        f"<strong>{safe_actual}</strong> under the user: "
        f"<strong>{safe_principal}</strong>.</p>"
        f"<p>You requested to link <strong>{safe_requested}</strong>; the "
        f"actual signed-in Google account is <strong>{safe_actual}</strong>. "
        f"The granted scope is <code>{safe_scope}</code>.</p>"
        "<p>If you started this connection request yourself and recognize "
        "the user above, click Confirm.</p>"
        "<p>If you did not start this connection request yourself, click "
        "Cancel. Someone may be trying to gain access to your mail.</p>"
        "<form method='POST' action='/oauth/confirm' "
        "style='display: flex; gap: 1em; margin-top: 2em;'>"
        f"<input type='hidden' name='pending_token' value='{safe_token}'>"
        "<button type='submit' name='action' value='confirm' "
        "style='background: #0f6f3f; color: white; border: none; "
        "padding: 0.75em 1.5em; font-size: 1em; cursor: pointer;'>"
        "Confirm</button>"
        "<button type='submit' name='action' value='cancel' "
        "style='background: #a01010; color: white; border: none; "
        "padding: 0.75em 1.5em; font-size: 1em; cursor: pointer;'>"
        "Cancel</button>"
        "</form>"
        "</body></html>"
    )
    return HTMLResponse(content=body, status_code=200)


def callback_html(success: bool, message: str) -> HTMLResponse:
    """Minimal HTML response for the /oauth2callback redirect target.

    OAuth callbacks must render something when the user lands on them
    after Google's redirect. We render a tiny self-contained page
    rather than an external template so the static build never grows
    a templates directory just for this one endpoint.

    Every interpolated value is run through `html.escape(..., quote=True)`.
    The title and color come from static literals and the message comes
    from compile-time strings, so the surface for stored / reflected
    XSS is theoretical. The escape calls future-proof the helper: if a
    later change adds an interpolated user-supplied value (e.g. an
    error string from Google's callback) the escape is already there.
    """
    title = "Connected" if success else "Connection failed"
    color = "#0f6f3f" if success else "#a01010"
    safe_title = html.escape(title, quote=True)
    safe_color = html.escape(color, quote=True)
    safe_message = html.escape(message, quote=True)
    body = (
        "<!DOCTYPE html>"
        f"<html><head><meta charset='utf-8'><title>{safe_title}</title></head>"
        "<body style='font-family: system-ui, sans-serif; padding: 2em;'>"
        f"<h1 style='color: {safe_color}'>{safe_title}</h1>"
        f"<p>{safe_message}</p>"
        "<p>You can close this window and return to your MCP client.</p>"
        "</body></html>"
    )
    status = 200 if success else 400
    return HTMLResponse(content=body, status_code=status)
