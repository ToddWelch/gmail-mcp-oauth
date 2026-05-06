"""adversarial consent-phishing simulation.

Targets: mcp-gmail/src/mcp_gmail/oauth_routes/start.py
Targets: mcp-gmail/src/mcp_gmail/oauth_routes/callback.py
Targets: mcp-gmail/src/mcp_gmail/oauth_routes/confirm.py

The vulnerability under test: an attacker A with a valid bearer can
mint an authorization URL bound to A's auth0_sub but ANY account_email,
sends the URL to victim B, B signs in with their own Google account,
and a refresh token for B's mailbox lands keyed under A's auth0_sub.

Layer 1 (allowlist) collapses the attack surface in single-user mode:
B (or A, if not allowlisted) gets 403 at /oauth/start. Layer 2
(post-callback confirmation page) blocks the attack in multi-user
mode: B sees a confirmation page naming A as the principal and
clicks Cancel.

This file exercises both attack scenarios end-to-end and asserts
that NO `gmail_oauth_tokens` row exists at the end.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
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
from mcp_gmail.crypto import encrypt
from mcp_gmail.db import Base
from mcp_gmail.oauth_http import TOKEN_URL, USERINFO_URL
from mcp_gmail.pending_link_store import (
    OAuthPendingLink,
    create_pending_link,
)
from mcp_gmail.server import app
from mcp_gmail.token_store import GmailOAuthToken

from .conftest import TEST_ENCRYPTION_KEY, TEST_JWKS_URL


def _bearer(jwt_factory, **claims):
    return f"Bearer {jwt_factory(claims)}"


@pytest.fixture
def single_user_client(jwks_document, monkeypatch):
    monkeypatch.setenv("MCP_ALLOWED_AUTH0_SUBS", "auth0|sample-user")
    monkeypatch.setenv("MCP_ALLOW_ANY_AUTH0_SUB", "false")
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
            db_module._engine = engine
            db_module._SessionFactory = sessionmaker(
                bind=engine, autoflush=False, expire_on_commit=False
            )
            tm.reset_cache_for_tests()
            c._respx_router = router
            yield c
    db_module.reset_for_tests()
    tm.reset_cache_for_tests()


@pytest.fixture
def multi_user_client(jwks_document, monkeypatch):
    monkeypatch.setenv("MCP_ALLOWED_AUTH0_SUBS", "auth0|sample-user,auth0|attacker")
    monkeypatch.setenv("MCP_ALLOW_ANY_AUTH0_SUB", "false")
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
            db_module._engine = engine
            db_module._SessionFactory = sessionmaker(
                bind=engine, autoflush=False, expire_on_commit=False
            )
            tm.reset_cache_for_tests()
            c._respx_router = router
            yield c
    db_module.reset_for_tests()
    tm.reset_cache_for_tests()


# ---------------------------------------------------------------------------
# Single-user mode: allowlist blocks the attack at /oauth/start
# ---------------------------------------------------------------------------


def test_consent_phishing_single_user_mode_blocked_by_allowlist(single_user_client, signed_jwt):
    """Attacker is NOT allowlisted; /oauth/start returns 403.

    Closes the consent-phishing defense in single-user mode by
    collapsing the attack surface. No state row, no nonce, no token
    row, no pending row.
    """
    resp = single_user_client.get(
        "/oauth/start",
        params={"account_email": "victim@example.com"},
        headers={"Authorization": _bearer(signed_jwt, sub="auth0|attacker")},
    )
    assert resp.status_code == 403
    fresh = db_module._SessionFactory()
    try:
        assert fresh.query(GmailOAuthToken).count() == 0
        assert fresh.query(OAuthPendingLink).count() == 0
    finally:
        fresh.close()


# ---------------------------------------------------------------------------
# Multi-user mode: confirm page blocks the attack at /oauth/confirm
# ---------------------------------------------------------------------------


def test_consent_phishing_multi_user_mode_pending_only_until_confirm(multi_user_client, signed_jwt):
    """Both the attacker and the legitimate user are allowlisted (multi-user). Attacker
    starts a flow; victim hits the callback. The callback creates a
    pending row and 303s to /oauth/confirm. Until the user clicks
    Confirm, gmail_oauth_tokens has NO row."""
    start = multi_user_client.get(
        "/oauth/start",
        params={"account_email": "victim@example.com"},
        headers={"Authorization": _bearer(signed_jwt, sub="auth0|attacker")},
    )
    assert start.status_code == 200
    state = parse_qs(urlparse(start.json()["authorization_url"]).query)["state"][0]
    multi_user_client._respx_router.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "ya29.fresh",
                "refresh_token": "1//rt-secret",
                "expires_in": 3600,
                "scope": "openid email https://www.googleapis.com/auth/gmail.readonly",
                "token_type": "Bearer",
            },
        )
    )
    multi_user_client._respx_router.get(USERINFO_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "sub": "google-victim",
                "email": "victim@example.com",
                "email_verified": True,
            },
        )
    )
    cb = multi_user_client.get(
        "/oauth2callback",
        params={"code": "auth-code-x", "state": state},
        follow_redirects=False,
    )
    assert cb.status_code == 303

    fresh = db_module._SessionFactory()
    try:
        # Pending row exists (held under attacker's auth0_sub but with
        # victim's email captured); no live token row.
        pending = fresh.query(OAuthPendingLink).all()
        assert len(pending) == 1
        assert pending[0].auth0_sub == "auth0|attacker"
        assert pending[0].account_email == "victim@example.com"
        assert fresh.query(GmailOAuthToken).count() == 0
    finally:
        fresh.close()


def test_consent_phishing_multi_user_mode_blocked_when_victim_cancels(
    multi_user_client, signed_jwt
):
    """Victim sees confirmation page naming the attacker, clicks Cancel.

    No live row is ever created.
    """
    start = multi_user_client.get(
        "/oauth/start",
        params={"account_email": "victim@example.com"},
        headers={"Authorization": _bearer(signed_jwt, sub="auth0|attacker")},
    )
    state = parse_qs(urlparse(start.json()["authorization_url"]).query)["state"][0]
    multi_user_client._respx_router.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "ya29.fresh",
                "refresh_token": "1//rt-secret",
                "expires_in": 3600,
                "scope": "openid email https://www.googleapis.com/auth/gmail.readonly",
                "token_type": "Bearer",
            },
        )
    )
    multi_user_client._respx_router.get(USERINFO_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "sub": "google-victim",
                "email": "victim@example.com",
                "email_verified": True,
            },
        )
    )
    cb = multi_user_client.get(
        "/oauth2callback",
        params={"code": "auth-code-x", "state": state},
        follow_redirects=False,
    )
    pending_token = parse_qs(urlparse(cb.headers["location"]).query)["pending_token"][0]

    # Inspect the confirmation page: must name the attacker as principal.
    page = multi_user_client.get(f"/oauth/confirm?pending_token={pending_token}")
    assert "auth0|attacker" in page.text
    # Anti-phishing wording is bound verbatim .
    assert "Someone may be trying to gain access to your mail." in page.text

    # Victim clicks Cancel.
    post = multi_user_client.post(
        "/oauth/confirm",
        content=f"pending_token={pending_token}&action=cancel".encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert post.status_code == 200

    # No gmail_oauth_tokens row, no pending row.
    fresh = db_module._SessionFactory()
    try:
        assert fresh.query(GmailOAuthToken).count() == 0
        assert fresh.query(OAuthPendingLink).count() == 0
    finally:
        fresh.close()


# ---------------------------------------------------------------------------
# allowlist re-check at confirm
# ---------------------------------------------------------------------------


def test_allowlist_revoked_during_confirm_window(multi_user_client, signed_jwt, monkeypatch):
    """If the principal is REMOVED from MCP_ALLOWED_AUTH0_SUBS during
    the 10-minute confirm window, the POST /oauth/confirm fails with
    a non-success and drops the pending row.

    Design decision: implementation re-reads `request.app.state.settings`
    on each request (Settings is loaded once at lifespan start).
    Mid-flight env-var changes that the fixture monkeypatch makes do
    NOT propagate to the already-loaded Settings. To exercise this
    test path we mutate the Settings dataclass via dataclasses.replace
    in a test-only context.
    """
    # First create a pending row under an allowlisted sub.
    fresh = db_module._SessionFactory()
    try:
        pending_token = create_pending_link(
            fresh,
            auth0_sub="auth0|sample-user",
            account_email="user@example.com",
            requested_account_email="user@example.com",
            encrypted_refresh_token=encrypt("1//rt-secret", TEST_ENCRYPTION_KEY),
            granted_scope="openid email",
            access_token_expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            google_sub="google-sample",
        )
        fresh.commit()
    finally:
        fresh.close()

    # Now mutate the loaded Settings to remove auth0|sample-user from allowlist.
    import dataclasses

    old_settings = app.state.settings
    # Keep `requires_confirm_page=True` (length > 1) but drop
    # auth0|sample-user from the allowlist so the re-check at confirm POST
    # rejects.
    new_settings = dataclasses.replace(
        old_settings,
        allowed_auth0_subs=("auth0|other-user", "auth0|third"),
    )
    app.state.settings = new_settings
    try:
        post = multi_user_client.post(
            "/oauth/confirm",
            content=f"pending_token={pending_token}&action=confirm".encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    finally:
        app.state.settings = old_settings

    # Must NOT have written a live row.
    fresh = db_module._SessionFactory()
    try:
        assert fresh.query(GmailOAuthToken).count() == 0
        # Pending row should also be dropped on cancel.
        assert fresh.query(OAuthPendingLink).count() == 0
    finally:
        fresh.close()
    assert post.status_code != 200 or b"not authorized" in post.content.lower()
