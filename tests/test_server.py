"""FastAPI server endpoints.

Targets: mcp-gmail/src/mcp_gmail/server.py:health
Targets: mcp-gmail/src/mcp_gmail/server.py:protected_resource_metadata
Targets: mcp-gmail/src/mcp_gmail/server.py:mcp_endpoint
Targets: mcp-gmail/src/mcp_gmail/server.py:_extract_bearer
Targets: mcp-gmail/src/mcp_gmail/server.py:_maybe_warn_about_replicas
"""

from __future__ import annotations

import logging

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from mcp_gmail.server import (
    _enforce_replica_constraint,
    _maybe_warn_about_replicas,
    app,
)

from .conftest import TEST_JWKS_URL, TEST_RESOURCE


@pytest.fixture
def client(jwks_document):
    with respx.mock(assert_all_called=False) as router:
        router.get(TEST_JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_document))
        with TestClient(app) as c:
            c._respx_router = router
            yield c


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_prm_document(client):
    resp = client.get("/.well-known/oauth-protected-resource")
    assert resp.status_code == 200
    data = resp.json()
    assert data["resource"] == TEST_RESOURCE
    assert data["authorization_servers"] == ["https://issuer.test.local"]
    assert data["bearer_methods_supported"] == ["header"]
    assert data["scopes_supported"] == []


def test_mcp_unauthenticated_returns_401_with_www_authenticate(client):
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
    )
    assert resp.status_code == 401
    auth = resp.headers.get("WWW-Authenticate", "")
    assert auth.startswith("Bearer ")
    assert "resource_metadata=" in auth
    assert TEST_RESOURCE in auth


def test_mcp_invalid_bearer_returns_401(client):
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        headers={"Authorization": "Bearer not-a-jwt"},
    )
    assert resp.status_code == 401
    assert "WWW-Authenticate" in resp.headers


def test_mcp_wrong_scheme_returns_401(client):
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        headers={"Authorization": "Basic abcdef"},
    )
    assert resp.status_code == 401


def test_mcp_valid_token_initialize(client, signed_jwt):
    token = signed_jwt()
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "initialize"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["result"]["serverInfo"]["name"] == "mcp-gmail"


def test_mcp_valid_token_tools_list_returns_full_tool_surface(client, signed_jwt):
    """All four manifests register 32 tools
    (11 read + 18 write + 1 bootstrap + 2 fanout extras). tools/list
    reflects that."""
    token = signed_jwt()
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    tools = data["result"]["tools"]
    assert len(tools) == 32
    names = {t["name"] for t in tools}
    # Bootstrap tool
    assert "connect_gmail_account" in names
    # Read side
    assert "read_email" in names
    assert "search_emails" in names
    # Write side (14-tool write surface)
    assert "send_email" in names
    assert "delete_email" in names
    assert "batch_delete_emails" in names
    # Cleanup tools (4)
    assert "reply_all" in names
    assert "batch_modify_emails" in names
    assert "get_or_create_label" in names
    assert "create_filter_from_template" in names
    # Fanout tools (2)
    assert "multi_search_emails" in names
    assert "batch_read_emails" in names


def test_mcp_valid_token_tools_call_unknown_tool_returns_method_not_found(client, signed_jwt):
    """tools/call with a name not in the manifest returns -32601."""
    token = signed_jwt()
    resp = client.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "not_a_real_tool", "arguments": {}},
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200  # JSON-RPC errors are 200 + error object
    data = resp.json()
    assert "error" in data
    assert data["error"]["code"] == -32601


def test_mcp_ping(client, signed_jwt):
    token = signed_jwt()
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "id": 3, "method": "ping"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["result"] == {}


def test_mcp_notification_returns_204(client, signed_jwt):
    token = signed_jwt()
    resp = client.post(
        "/mcp",
        json={"jsonrpc": "2.0", "method": "notifications/initialized"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 204


def test_mcp_malformed_json_body(client, signed_jwt):
    token = signed_jwt()
    resp = client.post(
        "/mcp",
        content="not json",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 400


def test_mcp_body_is_list_rejected(client, signed_jwt):
    token = signed_jwt()
    resp = client.post(
        "/mcp",
        json=[{"jsonrpc": "2.0", "id": 1, "method": "ping"}],
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 400


def test_replica_fail_closed_when_count_explicit(monkeypatch):
    """MCP_GMAIL_REPLICA_COUNT > 1 raises at startup unless
    MCP_GMAIL_ALLOW_MULTI_REPLICA=true."""
    monkeypatch.setenv("MCP_GMAIL_REPLICA_COUNT", "3")
    monkeypatch.delenv("MCP_GMAIL_ALLOW_MULTI_REPLICA", raising=False)
    with pytest.raises(RuntimeError, match="Multiple replicas detected"):
        _enforce_replica_constraint()


def test_replica_allow_override_unblocks_multi_replica(monkeypatch, caplog):
    """MCP_GMAIL_ALLOW_MULTI_REPLICA=true converts the fail-close into a WARN."""
    monkeypatch.setenv("MCP_GMAIL_REPLICA_COUNT", "3")
    monkeypatch.setenv("MCP_GMAIL_ALLOW_MULTI_REPLICA", "true")
    with caplog.at_level(logging.WARNING, logger="mcp_gmail"):
        _enforce_replica_constraint()
    assert any("Multiple replicas allowed" in rec.getMessage() for rec in caplog.records)


def test_replica_silent_at_one(monkeypatch, caplog):
    monkeypatch.setenv("MCP_GMAIL_REPLICA_COUNT", "1")
    monkeypatch.delenv("RAILWAY_REPLICA_ID", raising=False)
    with caplog.at_level(logging.WARNING, logger="mcp_gmail"):
        _enforce_replica_constraint()
    assert not any("Multiple replicas" in rec.getMessage() for rec in caplog.records)


def test_replica_info_when_railway_replica_id_set(monkeypatch, caplog):
    """RAILWAY_REPLICA_ID alone emits an INFO note; does NOT fail-close
    (replica guard design contract: only MCP_GMAIL_REPLICA_COUNT > 1 triggers raise)."""
    monkeypatch.delenv("MCP_GMAIL_REPLICA_COUNT", raising=False)
    monkeypatch.setenv("RAILWAY_REPLICA_ID", "abc-123")
    with caplog.at_level(logging.INFO, logger="mcp_gmail"):
        _enforce_replica_constraint()
    assert any("RAILWAY_REPLICA_ID is set" in rec.getMessage() for rec in caplog.records)


def test_replica_invalid_count_no_crash(monkeypatch):
    """A garbage value for MCP_GMAIL_REPLICA_COUNT must not crash the app."""
    monkeypatch.setenv("MCP_GMAIL_REPLICA_COUNT", "not-an-int")
    monkeypatch.delenv("RAILWAY_REPLICA_ID", raising=False)
    # Should silently swallow the parse error and emit nothing.
    _enforce_replica_constraint()


def test_legacy_alias_still_works(monkeypatch):
    """Backward-compat: _maybe_warn_about_replicas is now a thin alias."""
    monkeypatch.setenv("MCP_GMAIL_REPLICA_COUNT", "1")
    monkeypatch.delenv("RAILWAY_REPLICA_ID", raising=False)
    # Same behavior as the new name.
    _maybe_warn_about_replicas()


def test_replica_production_unset_raises(monkeypatch):
    """In production, an unset MCP_GMAIL_REPLICA_COUNT must fail closed.

    Without a configured count the replica guard cannot detect a
    scale-out; production deploys must set the variable explicitly so
    the refresh-token serialization invariant is acknowledged.
    """
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    monkeypatch.delenv("MCP_GMAIL_REPLICA_COUNT", raising=False)
    monkeypatch.delenv("RAILWAY_REPLICA_ID", raising=False)
    with pytest.raises(RuntimeError, match="MCP_GMAIL_REPLICA_COUNT is not set"):
        _enforce_replica_constraint()


def test_replica_production_invalid_count_raises(monkeypatch):
    """In production, a non-integer MCP_GMAIL_REPLICA_COUNT must fail closed.

    Outside production the same invalid value is silently swallowed
    (see test_replica_invalid_count_no_crash); the production guard
    upgrades that to a hard RuntimeError so a misconfigured deploy
    fails to come up rather than running with an unenforced cap.
    """
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    monkeypatch.setenv("MCP_GMAIL_REPLICA_COUNT", "not-an-int")
    monkeypatch.delenv("RAILWAY_REPLICA_ID", raising=False)
    with pytest.raises(RuntimeError, match="non-integer value"):
        _enforce_replica_constraint()
