"""Post-callback confirmation page tests.

Targets: src/mcp_gmail/oauth_routes/callback.py (mode-split persist)
Targets: src/mcp_gmail/oauth_routes/confirm.py (GET + POST)
Targets: src/mcp_gmail/oauth_routes/_helpers.py:confirm_page_html

Active in multi-user mode (allowlist length > 1) or under
MCP_ALLOW_ANY_AUTH0_SUB=true. In single-user mode the callback
persists inline and these routes are dormant.
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
    PENDING_LINK_TTL_MINUTES,
    OAuthPendingLink,
    create_pending_link,
)
from mcp_gmail.server import app
from mcp_gmail.token_store import GmailOAuthToken

from .conftest import TEST_ENCRYPTION_KEY, TEST_JWKS_URL


@pytest.fixture
def multi_user_client(jwks_document, monkeypatch):
    """Boot the app in multi-user mode (allowlist length > 1)."""
    monkeypatch.setenv("MCP_ALLOWED_AUTH0_SUBS", "auth0|sample-user,auth0|other-user")
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
def single_user_client(jwks_document, monkeypatch):
    """Boot the app in single-user mode (allowlist length == 1)."""
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


def _bearer(jwt_factory, **claims):
    return f"Bearer {jwt_factory(claims)}"


def _drive_to_callback(
    client,
    signed_jwt,
    *,
    sub: str,
    requested_email: str,
    actual_email: str,
):
    """Run /oauth/start, mock Google, and execute /oauth2callback.

    Returns the callback's Response object.
    """
    start = client.get(
        "/oauth/start",
        params={"account_email": requested_email},
        headers={"Authorization": _bearer(signed_jwt, sub=sub)},
    )
    assert start.status_code == 200
    state = parse_qs(urlparse(start.json()["authorization_url"]).query)["state"][0]
    client._respx_router.post(TOKEN_URL).mock(
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
    client._respx_router.get(USERINFO_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "sub": "google-user-1",
                "email": actual_email,
                "email_verified": True,
            },
        )
    )
    return client.get(
        "/oauth2callback",
        params={"code": "auth-code-x", "state": state},
        follow_redirects=False,
    )


# ---------------------------------------------------------------------------
# Single-user mode: confirm flow dormant; callback persists inline
# ---------------------------------------------------------------------------


def test_single_user_mode_persists_inline(single_user_client, signed_jwt):
    """Allowlist length 1 keeps requires_confirm_page=False and the
    callback writes directly into gmail_oauth_tokens."""
    resp = _drive_to_callback(
        single_user_client,
        signed_jwt,
        sub="auth0|sample-user",
        requested_email="user@example.com",
        actual_email="user@example.com",
    )
    assert resp.status_code == 200
    assert b"Connected" in resp.content

    fresh = db_module._SessionFactory()
    try:
        rows = fresh.query(GmailOAuthToken).all()
        assert len(rows) == 1
        assert rows[0].account_email == "user@example.com"
        # No pending row in single-user mode.
        assert fresh.query(OAuthPendingLink).count() == 0
    finally:
        fresh.close()


# ---------------------------------------------------------------------------
# Multi-user mode: callback redirects, confirm POST persists
# ---------------------------------------------------------------------------


def test_multi_user_mode_redirects_to_confirm(multi_user_client, signed_jwt):
    """In multi-user mode the callback creates a pending row and 303s
    to /oauth/confirm. No gmail_oauth_tokens row exists yet."""
    resp = _drive_to_callback(
        multi_user_client,
        signed_jwt,
        sub="auth0|sample-user",
        requested_email="user@example.com",
        actual_email="user@example.com",
    )
    assert resp.status_code == 303
    location = resp.headers["location"]
    assert location.startswith("/oauth/confirm?pending_token=")

    fresh = db_module._SessionFactory()
    try:
        # Pending row exists; gmail_oauth_tokens row does NOT.
        pending = fresh.query(OAuthPendingLink).all()
        assert len(pending) == 1
        assert pending[0].auth0_sub == "auth0|sample-user"
        assert pending[0].account_email == "user@example.com"
        assert fresh.query(GmailOAuthToken).count() == 0
    finally:
        fresh.close()


def test_confirm_get_renders_page(multi_user_client, signed_jwt):
    """GET /oauth/confirm with a valid token renders the HTML form."""
    resp = _drive_to_callback(
        multi_user_client,
        signed_jwt,
        sub="auth0|sample-user",
        requested_email="user@example.com",
        actual_email="user@example.com",
    )
    pending_token = parse_qs(urlparse(resp.headers["location"]).query)["pending_token"][0]

    page = multi_user_client.get(f"/oauth/confirm?pending_token={pending_token}")
    assert page.status_code == 200
    body = page.text
    assert "auth0|sample-user" in body  # principal label
    assert "user@example.com" in body  # actual / requested email
    # anti-phishing wording is bound verbatim.
    assert (
        "If you did not start this connection request yourself, click Cancel. "
        "Someone may be trying to gain access to your mail."
    ) in body
    # Form posts to /oauth/confirm.
    assert 'action="/oauth/confirm"' in body or "action='/oauth/confirm'" in body
    # pending_token in hidden form input, not URL action.
    assert (
        f'name="pending_token" value="{pending_token}"' in body
        or f"name='pending_token' value='{pending_token}'" in body
    )


def test_confirm_post_confirm_persists_token(multi_user_client, signed_jwt):
    """POST action=confirm consumes the pending row and creates the
    gmail_oauth_tokens row."""
    resp = _drive_to_callback(
        multi_user_client,
        signed_jwt,
        sub="auth0|sample-user",
        requested_email="user@example.com",
        actual_email="user@example.com",
    )
    pending_token = parse_qs(urlparse(resp.headers["location"]).query)["pending_token"][0]

    post = multi_user_client.post(
        "/oauth/confirm",
        content=f"pending_token={pending_token}&action=confirm".encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert post.status_code == 200
    assert b"Connected" in post.content

    fresh = db_module._SessionFactory()
    try:
        rows = fresh.query(GmailOAuthToken).all()
        assert len(rows) == 1
        assert rows[0].auth0_sub == "auth0|sample-user"
        assert rows[0].account_email == "user@example.com"
        # Pending row consumed.
        assert fresh.query(OAuthPendingLink).count() == 0
    finally:
        fresh.close()


def test_confirm_post_cancel_drops_pending_no_token_row(multi_user_client, signed_jwt):
    """POST action=cancel deletes the pending row and writes NO live row."""
    resp = _drive_to_callback(
        multi_user_client,
        signed_jwt,
        sub="auth0|sample-user",
        requested_email="user@example.com",
        actual_email="user@example.com",
    )
    pending_token = parse_qs(urlparse(resp.headers["location"]).query)["pending_token"][0]

    post = multi_user_client.post(
        "/oauth/confirm",
        content=f"pending_token={pending_token}&action=cancel".encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert post.status_code == 200
    assert b"cancelled" in post.content.lower() or b"Cancelled" in post.content

    fresh = db_module._SessionFactory()
    try:
        assert fresh.query(GmailOAuthToken).count() == 0
        assert fresh.query(OAuthPendingLink).count() == 0
    finally:
        fresh.close()


def test_confirm_post_replay_rejected(multi_user_client, signed_jwt):
    """Second POST with the same pending_token fails (single-use)."""
    resp = _drive_to_callback(
        multi_user_client,
        signed_jwt,
        sub="auth0|sample-user",
        requested_email="user@example.com",
        actual_email="user@example.com",
    )
    pending_token = parse_qs(urlparse(resp.headers["location"]).query)["pending_token"][0]
    body = f"pending_token={pending_token}&action=confirm".encode("utf-8")
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    first = multi_user_client.post("/oauth/confirm", content=body, headers=headers)
    second = multi_user_client.post("/oauth/confirm", content=body, headers=headers)
    assert first.status_code == 200
    assert b"Connected" in first.content
    # Replay returns the generic failure HTML.
    assert b"invalid or expired" in second.content


def test_confirm_post_expired_pending_rejected(multi_user_client):
    """A pending row that has aged past TTL fails the confirm."""
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
            google_sub="google-1",
        )
        # Backdate.
        row = fresh.query(OAuthPendingLink).filter_by(pending_token=pending_token).one()
        row.created_at = datetime.now(timezone.utc) - timedelta(
            minutes=PENDING_LINK_TTL_MINUTES + 1
        )
        fresh.commit()
    finally:
        fresh.close()

    post = multi_user_client.post(
        "/oauth/confirm",
        content=f"pending_token={pending_token}&action=confirm".encode("utf-8"),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert post.status_code != 200 or b"invalid or expired" in post.content


def test_confirm_get_unknown_token_renders_failure(multi_user_client):
    """GET with a missing pending_token returns the generic failure page."""
    resp = multi_user_client.get(
        "/oauth/confirm?pending_token=" + "x" * 32,
    )
    assert b"invalid or expired" in resp.content


def test_callback_hit_twice_in_multi_user_mode(multi_user_client, signed_jwt):
    """Replaying the same /oauth2callback fails (nonce already consumed),
    even after the first hit created a pending row."""
    start = multi_user_client.get(
        "/oauth/start",
        params={"account_email": "user@example.com"},
        headers={"Authorization": _bearer(signed_jwt, sub="auth0|sample-user")},
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
                "sub": "google-user-1",
                "email": "user@example.com",
                "email_verified": True,
            },
        )
    )
    first = multi_user_client.get(
        "/oauth2callback",
        params={"code": "auth-code-x", "state": state},
        follow_redirects=False,
    )
    second = multi_user_client.get(
        "/oauth2callback",
        params={"code": "auth-code-x", "state": state},
        follow_redirects=False,
    )
    assert first.status_code == 303
    # Second hit fails the nonce consume.
    assert second.status_code != 303
