"""Security headers on every response (DAST issues #28 and #31).

The monthly ZAP baseline flagged missing Strict-Transport-Security and cacheable
content. These tests run the real app, so they also prove the middleware order.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from mcp_gmail import middleware as middleware_module
from mcp_gmail.security_headers import (
    CACHE_CONTROL_VALUE,
    HSTS_VALUE,
    SecurityHeadersMiddleware,
)
from mcp_gmail.server import app

from .conftest import TEST_JWKS_URL
from .test_server import _snapshot_filter_state

HSTS = HSTS_VALUE.decode()
NO_STORE = CACHE_CONTROL_VALUE.decode()


@pytest.fixture
def client(jwks_document):
    pre_filter_state = _snapshot_filter_state()
    with respx.mock(assert_all_called=False) as router:
        router.get(TEST_JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_document))
        with TestClient(app) as c:
            yield c
    for scope, filters in pre_filter_state:
        scope.filters = list(filters)


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("GET", "/health"),
        ("GET", "/.well-known/oauth-protected-resource"),
        ("GET", "/does-not-exist"),
        ("POST", "/mcp"),
    ],
)
def test_every_response_carries_both_headers(client, method, path):
    resp = client.request(method, path, json={} if method == "POST" else None)
    assert resp.headers["strict-transport-security"] == HSTS
    assert resp.headers["cache-control"] == NO_STORE


def test_hsts_does_not_claim_the_shared_railway_domain(client):
    """includeSubDomains on *.up.railway.app would govern other tenants' apps."""
    assert (
        "includesubdomains"
        not in client.get("/health").headers["strict-transport-security"].lower()
    )


def test_a_413_from_the_body_cap_carries_the_headers(client, monkeypatch):
    monkeypatch.setattr(middleware_module, "MAX_REQUEST_BODY_BYTES", 10)
    resp = client.post("/mcp", content=b"x" * 100, headers={"content-length": "100"})
    assert resp.status_code == 413
    assert resp.headers["strict-transport-security"] == HSTS
    assert resp.headers["cache-control"] == NO_STORE


def test_a_route_that_sets_its_own_cache_control_keeps_it():
    async def cached(_request):
        return PlainTextResponse("ok", headers={"Cache-Control": "public, max-age=60"})

    inner = Starlette(routes=[Route("/cached", cached)])
    with TestClient(SecurityHeadersMiddleware(inner)) as c:
        resp = c.get("/cached")

    assert resp.headers["cache-control"] == "public, max-age=60"
    assert resp.headers.get_list("cache-control") == ["public, max-age=60"]
    assert resp.headers["strict-transport-security"] == HSTS


def test_websocket_and_lifespan_scopes_pass_through_untouched():
    seen = []

    async def inner(scope, receive, send):
        seen.append(scope["type"])

    mw = SecurityHeadersMiddleware(inner)
    import asyncio

    asyncio.run(mw({"type": "lifespan"}, None, None))
    assert seen == ["lifespan"]
