"""Google OAuth HTTP exchanges (httpx, async).

Split out of the original `google_oauth.py` so the network layer is
reviewable independently of the state-token crypto. This module owns
every outbound HTTP call mcp-gmail makes to Google for OAuth purposes:
code-for-token exchange, refresh-token exchange, userinfo lookup,
revocation.

Surfaces
--------
- Constants: TOKEN_URL, USERINFO_URL, REVOKE_URL
- Dataclasses: TokenResponse, UserInfo
- Exception: GoogleOAuthError
- Async helpers: exchange_code, refresh_access_token, fetch_userinfo,
  revoke_refresh_token

Why this is a separate module
-----------------------------
- Pure crypto (state HMAC, fingerprint) lives in oauth_state.py and
  is fully unit-testable without mocking httpx.
- Every call here mocks against `respx` in tests; keeping the surface
  narrow makes those tests easier to read.
- A future replacement for httpx (or a different transport entirely)
  swaps this file alone, leaving oauth_state.py and oauth_routes/*
  untouched.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Google OAuth HTTP endpoints. AUTHORIZE_URL is in oauth_state.py because
# build_authorization_url is a pure synchronous helper.
# ---------------------------------------------------------------------------

TOKEN_URL = "https://oauth2.googleapis.com/token"
USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"
REVOKE_URL = "https://oauth2.googleapis.com/revoke"


# ---------------------------------------------------------------------------
# Exceptions and dataclasses
# ---------------------------------------------------------------------------


class GoogleOAuthError(Exception):
    """Raised when a Google OAuth HTTP exchange fails or returns an error."""

    def __init__(self, message: str, *, status: int | None = None, body: str | None = None):
        super().__init__(message)
        self.status = status
        # `body` may contain Google's error description; callers MUST
        # NOT log it raw because some error responses echo the
        # offending refresh_token back. The redacting filter will
        # catch it, but the discipline is still no-log-at-callsite.
        self.body = body


@dataclass(frozen=True)
class TokenResponse:
    """Subset of Google's /token response we care about.

    `expires_at_epoch` is computed at exchange time so callers get an
    absolute timestamp, not a relative seconds-from-now that they
    have to interpret.
    """

    access_token: str
    refresh_token: str | None
    scope: str
    expires_at_epoch: float
    id_token: str | None


@dataclass(frozen=True)
class UserInfo:
    """Subset of Google's /userinfo response we care about."""

    sub: str
    email: str
    email_verified: bool


def _now_epoch() -> float:
    return time.time()


# ---------------------------------------------------------------------------
# Token endpoint exchanges
# ---------------------------------------------------------------------------


async def exchange_code(
    *,
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
    timeout: float = 10.0,
    client: httpx.AsyncClient | None = None,
) -> TokenResponse:
    """Exchange an authorization code for tokens. Async, raises on error.

    The httpx client is injectable for tests via respx. When not
    supplied, a short-lived AsyncClient is constructed for this call.
    """
    body = {
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    return await _post_token_request(body, timeout=timeout, client=client)


async def refresh_access_token(
    *,
    client_id: str,
    client_secret: str,
    refresh_token: str,
    timeout: float = 10.0,
    client: httpx.AsyncClient | None = None,
) -> TokenResponse:
    """Exchange a refresh_token for a new access token. Async."""
    body = {
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }
    return await _post_token_request(body, timeout=timeout, client=client)


async def _post_token_request(
    body: dict[str, str],
    *,
    timeout: float,
    client: httpx.AsyncClient | None,
) -> TokenResponse:
    """Send a form-urlencoded POST to TOKEN_URL and parse the response."""
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=timeout)
    try:
        try:
            resp = await client.post(
                TOKEN_URL,
                data=body,
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise GoogleOAuthError(f"token endpoint network error: {exc}") from exc
        if resp.status_code >= 400:
            # Body may contain refresh_token echoed back on error;
            # callers must not log it. The redacting filter is the
            # backstop, but we still strip it from the exception arg.
            raise GoogleOAuthError(
                f"token endpoint returned {resp.status_code}",
                status=resp.status_code,
                body=resp.text,
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise GoogleOAuthError("token endpoint returned non-JSON body") from exc
    finally:
        if own_client and client is not None:
            await client.aclose()

    if not isinstance(payload, dict):
        raise GoogleOAuthError("token endpoint returned non-object body")
    access = payload.get("access_token")
    if not access or not isinstance(access, str):
        raise GoogleOAuthError("token response missing access_token")
    expires_in = payload.get("expires_in")
    try:
        expires_in_seconds = float(expires_in) if expires_in is not None else 3600.0
    except (TypeError, ValueError):
        expires_in_seconds = 3600.0
    return TokenResponse(
        access_token=access,
        refresh_token=payload.get("refresh_token"),
        # Google sometimes omits scope on refresh; default to empty
        # string so the caller can choose to keep the existing stored
        # scope rather than overwrite it with None.
        scope=str(payload.get("scope") or ""),
        expires_at_epoch=_now_epoch() + expires_in_seconds,
        id_token=payload.get("id_token"),
    )


# ---------------------------------------------------------------------------
# Userinfo and revocation
# ---------------------------------------------------------------------------


async def fetch_userinfo(
    access_token: str,
    *,
    timeout: float = 10.0,
    client: httpx.AsyncClient | None = None,
) -> UserInfo:
    """Call Google's /userinfo endpoint with the access token. Async.

    We fetch userinfo (rather than parsing the id_token JWT) because
    it gives us a verified email + sub without us needing to fetch
    Google's JWKS. The access token check on Google's side is the
    trust mechanism.
    """
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=timeout)
    try:
        try:
            resp = await client.get(
                USERINFO_URL,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise GoogleOAuthError(f"userinfo endpoint network error: {exc}") from exc
        if resp.status_code >= 400:
            raise GoogleOAuthError(
                f"userinfo endpoint returned {resp.status_code}",
                status=resp.status_code,
                body=resp.text,
            )
        try:
            payload = resp.json()
        except ValueError as exc:
            raise GoogleOAuthError("userinfo endpoint returned non-JSON body") from exc
    finally:
        if own_client and client is not None:
            await client.aclose()

    if not isinstance(payload, dict):
        raise GoogleOAuthError("userinfo endpoint returned non-object body")
    sub = payload.get("sub")
    email = payload.get("email")
    if not sub or not email:
        raise GoogleOAuthError("userinfo response missing sub or email")
    return UserInfo(
        sub=str(sub),
        email=str(email).strip().lower(),
        email_verified=bool(payload.get("email_verified", False)),
    )


async def revoke_refresh_token(
    refresh_token: str,
    *,
    timeout: float = 10.0,
    client: httpx.AsyncClient | None = None,
) -> bool:
    """Best-effort revocation at Google's revoke endpoint. Async.

    Returns True if Google accepted the revocation (200), False
    otherwise. Callers should NOT raise on False because soft-revoke
    in the database is the primary disconnect path; the Google call
    is best-effort. We still log the outcome (without the token) so
    operators can see when revocation fails.
    """
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=timeout)
    try:
        try:
            resp = await client.post(
                REVOKE_URL,
                data={"token": refresh_token},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            logger.warning("revoke endpoint network error: %s", exc)
            return False
    finally:
        if own_client and client is not None:
            await client.aclose()
    if resp.status_code == 200:
        return True
    logger.info("revoke endpoint returned %d", resp.status_code)
    return False
