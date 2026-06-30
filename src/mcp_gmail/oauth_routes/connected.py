"""GET /oauth/connected: static post-link success page.

This is the terminal page of the Post/Redirect/Get flow. After a
successful Google OAuth link, the callback (single-user mode) and the
multi-user confirm POST 303-redirect here instead of rendering the
result inline at the consuming URL.

Why a separate static page
--------------------------
The /oauth2callback URL is single-use: the state nonce is consumed
atomically on the first hit. Rendering the success result inline at
that URL meant any reload, prefetch, or duplicate navigation re-ran the
nonce consume, which now returns nothing, and the page flipped to the
"already used or expired" failure page even though the link had
genuinely succeeded. This page consumes nothing (no code, state, nonce,
pending_token, or email), so a browser reload is a pure re-render.

No bearer auth, no database access, no query parameters. The page
interpolates no per-account data, so it discloses nothing about any
specific linkage.
"""

from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from ._helpers import callback_html

router = APIRouter()


@router.get("/oauth/connected")
async def oauth_connected() -> HTMLResponse:
    """Render the static, reload-safe success page (display-only)."""
    return callback_html(True, "Your Gmail account is connected.")
