"""Email-verified-guard additions to oauth_routes tests.

Targets:
- src/mcp_gmail/oauth_routes/callback.py: email_verified guard
- src/mcp_gmail/oauth_routes/_helpers.py: html.escape (low-severity hardening)

Kept in a separate file so the existing test_oauth_routes.py (already
800+ lines covering the full flow) does not balloon further.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mcp_gmail import db as db_module
from mcp_gmail import token_manager as tm
from mcp_gmail.db import Base
from mcp_gmail.oauth_http import TOKEN_URL, USERINFO_URL
from mcp_gmail.oauth_routes._helpers import callback_html
from mcp_gmail.server import app

from .conftest import TEST_JWKS_URL


# ---------------------------------------------------------------------------
# Fixture: bootstrap the schema-backed app with respx mocks for upstream calls
# ---------------------------------------------------------------------------


@pytest.fixture
def client(jwks_document):
    """See test_oauth_routes.py:client for the rationale (StaticPool+thread)."""
    with respx.mock(assert_all_called=False) as router:
        router.get(TEST_JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_document))
        with TestClient(app) as c:
            engine = create_engine(
                "sqlite+pysqlite:///:memory:",
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
                future=True,
            )
            Base.metadata.create_all(engine)
            db_module._engine = engine  # type: ignore[attr-defined]
            db_module._SessionFactory = sessionmaker(  # type: ignore[attr-defined]
                bind=engine, autoflush=False, expire_on_commit=False
            )
            tm.reset_cache_for_tests()
            c._respx_router = router  # type: ignore[attr-defined]
            yield c
    db_module.reset_for_tests()
    tm.reset_cache_for_tests()


def _bearer(jwt_factory, **claims):
    return f"Bearer {jwt_factory(claims)}"


def _drive_to_callback(client, signed_jwt, *, account_email: str, sub: str) -> str:
    """Helper: hit /oauth/start and return the state token from the auth URL."""
    headers = {"Authorization": _bearer(signed_jwt, sub=sub)}
    resp = client.get(
        "/oauth/start",
        params={"account_email": account_email},
        headers=headers,
    )
    assert resp.status_code == 200
    auth_url = resp.json()["authorization_url"]
    state = parse_qs(urlparse(auth_url).query)["state"][0]
    return state


# ---------------------------------------------------------------------------
# Item 3: email_verified guard
# ---------------------------------------------------------------------------


def test_callback_rejects_when_email_unverified(client, signed_jwt):
    """unverified Google email blocks the link.

    The token row must NOT be persisted. The user sees the failure
    HTML page so they know to verify the email upstream and retry."""
    state = _drive_to_callback(client, signed_jwt, account_email="user@example.com", sub="user-abc")

    client._respx_router.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "ya29.fresh",
                "refresh_token": "1//rt",
                "expires_in": 3600,
                "scope": "openid email",
                "token_type": "Bearer",
            },
        )
    )
    client._respx_router.get(USERINFO_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "sub": "google-1",
                "email": "user@example.com",
                # Crucial: Google reports the address unverified.
                "email_verified": False,
            },
        )
    )

    resp = client.get("/oauth2callback", params={"code": "auth-x", "state": state})
    assert resp.status_code == 400
    assert "unverified" in resp.text.lower()


def test_callback_rejects_when_email_verified_missing(client, signed_jwt):
    """Defense-in-depth: a userinfo payload with no email_verified
    field at all is treated as unverified (the dataclass default is
    False)."""
    state = _drive_to_callback(
        client, signed_jwt, account_email="user2@example.com", sub="user-abc"
    )

    client._respx_router.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "ya29.fresh",
                "refresh_token": "1//rt2",
                "expires_in": 3600,
                "scope": "openid email",
                "token_type": "Bearer",
            },
        )
    )
    client._respx_router.get(USERINFO_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "sub": "google-2",
                "email": "user2@example.com",
                # Field omitted entirely.
            },
        )
    )

    resp = client.get("/oauth2callback", params={"code": "auth-x", "state": state})
    assert resp.status_code == 400


def test_callback_warns_on_unverified_email(client, signed_jwt, caplog):
    """The unverified-email guard logs at WARN with auth0_sub +
    requested + actual email, so operators can spot rejected links
    in production logs."""
    import logging

    state = _drive_to_callback(client, signed_jwt, account_email="warn@example.com", sub="user-abc")

    client._respx_router.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "ya29.fresh",
                "refresh_token": "1//rt3",
                "expires_in": 3600,
                "scope": "openid email",
                "token_type": "Bearer",
            },
        )
    )
    client._respx_router.get(USERINFO_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "sub": "google-3",
                "email": "warn@example.com",
                "email_verified": False,
            },
        )
    )

    with caplog.at_level(logging.WARNING, logger="mcp_gmail.oauth_routes.callback"):
        client.get("/oauth2callback", params={"code": "auth-x", "state": state})

    warning_records = [
        r
        for r in caplog.records
        if r.name == "mcp_gmail.oauth_routes.callback" and r.levelname == "WARNING"
    ]
    assert any("email_verified=false" in r.getMessage() for r in warning_records)


# ---------------------------------------------------------------------------
# Item 5: HTML-escape callback errors (low-severity hardening)
# ---------------------------------------------------------------------------


def test_callback_html_escapes_message():
    """callback_html must escape HTML special chars in the message
    parameter so a future caller passing user-supplied strings (e.g.
    Google's ?error= query param) cannot inject markup."""
    resp = callback_html(False, "<script>alert(1)</script>")
    body = resp.body.decode("utf-8")
    # The raw script tag must NOT survive into the response body.
    assert "<script>" not in body
    # The escaped form MUST be present.
    assert "&lt;script&gt;" in body


def test_callback_html_escapes_quotes_in_message():
    """Quotes are escaped (quote=True) to defend against attribute
    breakouts in future markup variations."""
    resp = callback_html(True, 'connected as "user"@evil.com')
    body = resp.body.decode("utf-8")
    assert '"user"' not in body
    assert "&quot;user&quot;" in body
