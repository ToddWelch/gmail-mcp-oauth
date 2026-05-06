"""allowlist enforcement at the OAuth-link entry points.

Targets: mcp-gmail/src/mcp_gmail/oauth_routes/start.py:oauth_start
Targets: mcp-gmail/src/mcp_gmail/gmail_tools/bootstrap.py:handle_connect_gmail_account
Targets: mcp-gmail/src/mcp_gmail/server.py:mcp_endpoint (allowlist gate)

Three layers cover the same allowlist invariant:
  - HTTP /oauth/start: 403 with non-leaky message
  - MCP tool connect_gmail_account: bad_request_error (-32001)
  - /mcp itself: 403 with {"error": "auth0_sub_not_allowlisted"}, NO
    WWW-Authenticate
"""

from __future__ import annotations

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mcp_gmail import db as db_module
from mcp_gmail.db import Base
from mcp_gmail.gmail_tools import bootstrap as bootstrap_module
from mcp_gmail.gmail_tools.bootstrap import handle_connect_gmail_account
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.server import app
from mcp_gmail.state_store import OAuthStateNonce

from .conftest import TEST_JWKS_URL


@pytest.fixture
def client(jwks_document, monkeypatch):
    """Boots the app with a single-user allowlist (only auth0|sample-user allowed)."""
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
            c._respx_router = router
            yield c
    db_module.reset_for_tests()


def _bearer(jwt_factory, **claims):
    return f"Bearer {jwt_factory(claims)}"


# ---------------------------------------------------------------------------
# HTTP /oauth/start
# ---------------------------------------------------------------------------


def test_oauth_start_accepts_allowed_sub(client, signed_jwt, in_memory_session):
    """Bearer with allowlisted sub gets 200 + authorization_url."""
    resp = client.get(
        "/oauth/start",
        params={"account_email": "user@example.com"},
        headers={"Authorization": _bearer(signed_jwt, sub="auth0|sample-user")},
    )
    assert resp.status_code == 200
    assert "authorization_url" in resp.json()


def test_oauth_start_rejects_disallowed_sub(client, signed_jwt):
    """Bearer with non-allowlisted sub gets 403 with non-leaky message."""
    resp = client.get(
        "/oauth/start",
        params={"account_email": "victim@example.com"},
        headers={"Authorization": _bearer(signed_jwt, sub="auth0|attacker")},
    )
    assert resp.status_code == 403
    detail = resp.json().get("detail", "")
    assert "not authorized to link Gmail accounts" in detail
    # Non-leaky: must NOT enumerate the allowlist or reveal config.
    assert "auth0|sample-user" not in detail


def test_oauth_start_rejection_does_not_persist_nonce(client, signed_jwt):
    """A 403 from disallowed sub must NOT mint a nonce row."""
    resp = client.get(
        "/oauth/start",
        params={"account_email": "victim@example.com"},
        headers={"Authorization": _bearer(signed_jwt, sub="auth0|attacker")},
    )
    assert resp.status_code == 403
    # No nonce row should exist.
    fresh = db_module._SessionFactory()
    try:
        rows = fresh.query(OAuthStateNonce).all()
        assert rows == []
    finally:
        fresh.close()


# ---------------------------------------------------------------------------
# MCP tool connect_gmail_account
# ---------------------------------------------------------------------------


@pytest.fixture
def init_engine_for_bootstrap(monkeypatch):
    """Same StaticPool engine setup as test_gmail_tools_bootstrap."""
    monkeypatch.setenv("MCP_ALLOWED_AUTH0_SUBS", "auth0|sample-user")
    monkeypatch.setenv("MCP_ALLOW_ANY_AUTH0_SUB", "false")
    db_module.reset_for_tests()
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    db_module._engine = engine
    db_module._SessionFactory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
    yield
    db_module.reset_for_tests()


@pytest.mark.asyncio
async def test_connect_gmail_account_accepts_allowed_sub(init_engine_for_bootstrap, settings):
    result = await handle_connect_gmail_account(
        auth0_sub="auth0|sample-user",
        arguments={"account_email": "user@example.com"},
        settings=settings,
    )
    assert "authorization_url" in result


@pytest.mark.asyncio
async def test_connect_gmail_account_rejects_disallowed_sub(init_engine_for_bootstrap, settings):
    """MCP-tool path mirrors HTTP: bad_request_error with non-leaky message."""
    result = await handle_connect_gmail_account(
        auth0_sub="auth0|attacker",
        arguments={"account_email": "victim@example.com"},
        settings=settings,
    )
    assert result.get("code") == ToolErrorCode.BAD_REQUEST
    msg = result.get("message", "")
    assert "not authorized to link Gmail accounts" in msg


@pytest.mark.asyncio
async def test_connect_gmail_account_rejection_skips_create_nonce(
    init_engine_for_bootstrap, settings, monkeypatch
):
    """A disallowed sub returns the error WITHOUT calling create_nonce."""
    from unittest.mock import patch

    with patch.object(bootstrap_module, "create_nonce") as mock_create:
        result = await handle_connect_gmail_account(
            auth0_sub="auth0|attacker",
            arguments={"account_email": "victim@example.com"},
            settings=settings,
        )
    assert result.get("code") == ToolErrorCode.BAD_REQUEST
    mock_create.assert_not_called()


# ---------------------------------------------------------------------------
# /mcp endpoint allowlist gate
# ---------------------------------------------------------------------------


def test_mcp_rejects_disallowed_sub_with_403_not_401(client, signed_jwt):
    """/mcp on a non-allowlisted sub returns 403 with the
    canonical body and NO WWW-Authenticate header.

    The bearer is valid (we just validated it); only the principal is
    denied. A 401-shaped envelope would mislead Claude.ai's connector
    into an OAuth-discovery retry loop.
    """
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": _bearer(signed_jwt, sub="auth0|attacker")},
    )
    assert resp.status_code == 403
    assert resp.json() == {"error": "auth0_sub_not_allowlisted"}
    assert "WWW-Authenticate" not in resp.headers


def test_mcp_accepts_allowed_sub(client, signed_jwt):
    """The happy path on /mcp is unchanged for an allowlisted sub.

    A tools/list call on the empty-tool surface returns OK
    even before any Gmail tool is registered.
    """
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": _bearer(signed_jwt, sub="auth0|sample-user")},
    )
    # 200 because the bearer + allowlist both pass; the JSON-RPC body
    # may carry an error or empty list depending on the registered
    # tool surface.
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# HTTP /oauth/status allowlist gate
# ---------------------------------------------------------------------------


def test_oauth_status_rejects_disallowed_sub(client, signed_jwt):
    """A delisted Auth0 sub with a valid bearer cannot read mailbox metadata.

    Mirrors the /oauth/start gate: 403 with the same non-leaky message,
    so a removed allowlist entry takes effect on /oauth/status without
    waiting for the bearer to expire.
    """
    resp = client.get(
        "/oauth/status",
        headers={"Authorization": _bearer(signed_jwt, sub="auth0|attacker")},
    )
    assert resp.status_code == 403
    detail = resp.json().get("detail", "")
    assert "not authorized to link Gmail accounts" in detail
    # Non-leaky: must NOT enumerate the allowlist or reveal config.
    assert "auth0|sample-user" not in detail


# ---------------------------------------------------------------------------
# HTTP /oauth/disconnect allowlist gate
# ---------------------------------------------------------------------------


def test_oauth_disconnect_rejects_disallowed_sub(client, signed_jwt):
    """A delisted Auth0 sub with a valid bearer cannot soft-revoke rows.

    Mirrors the /oauth/start gate: 403 with the same non-leaky message,
    so a removed allowlist entry takes effect on /oauth/disconnect
    without waiting for the bearer to expire.
    """
    resp = client.post(
        "/oauth/disconnect",
        json={"account_email": "user@example.com"},
        headers={"Authorization": _bearer(signed_jwt, sub="auth0|attacker")},
    )
    assert resp.status_code == 403
    detail = resp.json().get("detail", "")
    assert "not authorized to link Gmail accounts" in detail
    assert "auth0|sample-user" not in detail
