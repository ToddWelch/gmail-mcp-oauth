"""GET /ready returns the deeper readiness probe.

Targets: mcp-gmail/src/mcp_gmail/server.py:ready
"""

from __future__ import annotations

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from mcp_gmail import health as health_module
from mcp_gmail.server import app

from .conftest import TEST_JWKS_URL


@pytest.fixture
def client_with_warm_jwks(jwks_document):
    """Standard TestClient with the JWKS endpoint mocked.

    The TestClient context-manager triggers the lifespan handler,
    which warms the JWKS cache and runs the SELECT 1 probe. With
    SQLite in-memory, the DB probe always succeeds; with the JWKS
    mock returning a valid document, jwks warm-fetch succeeds; and
    config loads from the conftest env so settings_loaded becomes
    True.

    Result: by the time TestClient enters the context, all three
    readiness flags are set and /ready returns 200.
    """
    with respx.mock(assert_all_called=False) as router:
        router.get(TEST_JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_document))
        with TestClient(app) as c:
            yield c


def test_ready_returns_200_when_all_marks_set(client_with_warm_jwks):
    resp = client_with_warm_jwks.get("/ready")
    assert resp.status_code == 200
    body = resp.json()
    assert body["ready"] is True
    assert body["settings_loaded"] is True
    assert body["db_ready"] is True
    assert body["jwks_warm"] is True


def test_ready_returns_503_when_a_mark_is_missing(client_with_warm_jwks):
    """Manually unset one of the marks and confirm /ready flips to 503."""
    # Currently all three are set. Drop jwks_warm by partial-resetting.
    health_module._state.jwks_warm = False
    resp = client_with_warm_jwks.get("/ready")
    assert resp.status_code == 503
    body = resp.json()
    assert body["ready"] is False
    assert body["jwks_warm"] is False


def test_ready_does_not_require_auth(client_with_warm_jwks):
    """No bearer token; /ready still answers (200 or 503)."""
    resp = client_with_warm_jwks.get("/ready")
    assert resp.status_code in (200, 503)


def test_ready_records_db_failure_when_probe_fails(jwks_document, monkeypatch):
    """If the SELECT 1 probe fails at boot, /ready reports it."""
    from mcp_gmail import db as db_module

    # Force the engine.connect() path to raise. A side-effect on
    # get_engine is the cleanest hook because the lifespan runs:
    #   db_module.init_engine(url)            <- this still works
    #   db_module.get_engine().connect()      <- patched to raise
    real_init = db_module.init_engine

    def init_then_break(url):
        engine = real_init(url)

        class BrokenConn:
            def __enter__(self_inner):
                raise RuntimeError("simulated db down")

            def __exit__(self_inner, *args):
                return False

        # Replace .connect on the engine instance to return a
        # context manager that raises on enter.
        engine.connect = lambda: BrokenConn()  # type: ignore[assignment]
        return engine

    monkeypatch.setattr(db_module, "init_engine", init_then_break)

    with respx.mock(assert_all_called=False) as router:
        router.get(TEST_JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_document))
        with TestClient(app) as c:
            resp = c.get("/ready")
            assert resp.status_code == 503
            body = resp.json()
            assert body["db_ready"] is False
            assert "db" in body["failures"]
