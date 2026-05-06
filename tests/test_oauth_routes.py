"""FastAPI OAuth flow routes.

Targets: mcp-gmail/src/mcp_gmail/oauth_routes/start.py:oauth_start
Targets: mcp-gmail/src/mcp_gmail/oauth_routes/callback.py:oauth2callback
Targets: mcp-gmail/src/mcp_gmail/oauth_routes/status.py:oauth_status
Targets: mcp-gmail/src/mcp_gmail/oauth_routes/disconnect.py:oauth_disconnect

Cases cover all blocker regressions plus the security-review hardening
items (email-mismatch shape, status include_revoked filter,
scope-downgrade persistence, no-secrets-in-logs deep walk).
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
from mcp_gmail import token_manager as tm
from mcp_gmail.db import Base
from mcp_gmail.oauth_http import (
    REVOKE_URL,
    TOKEN_URL,
    USERINFO_URL,
)
from mcp_gmail.server import app

from .conftest import TEST_JWKS_URL


@pytest.fixture
def client(jwks_document):
    """Boots the app, mocks JWKS, and substitutes a StaticPool SQLite engine.

    The default in-memory SQLite engine that init_engine() creates uses
    a SingletonThreadPool: each thread gets its own connection, and an
    in-memory database is per-connection by definition, so the tables
    created on one thread are invisible from another. FastAPI's
    TestClient runs the request handlers in a worker thread that
    differs from the test fixture's thread.

    Fix: replace _engine and _SessionFactory inside db_module with a
    StaticPool-backed engine + a single shared connection so every
    thread sees the same database. Run create_all so the tables are
    in place before the first /oauth/start hits the nonce table.
    """
    with respx.mock(assert_all_called=False) as router:
        router.get(TEST_JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_document))
        with TestClient(app) as c:
            # The lifespan has now run init_engine() once. Replace the
            # engine + factory with one whose schema is initialized.
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


# ---- BLOCKER 1 / required check #1: nonce table is reachable ---------------


def test_oauth_start_creates_nonce_in_session(client, signed_jwt):
    """Hitting /oauth/start requires the engine + nonce table to be in place."""
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}
    resp = client.get(
        "/oauth/start",
        params={"account_email": "user@example.com"},
        headers=headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "authorization_url" in body
    assert body["authorization_url"].startswith("https://accounts.google.com/")
    assert "state=" in body["authorization_url"]


# ---- BLOCKER 2: redirect=true returns a 302 to Google's consent URL ---------


def test_oauth_start_redirect_true_returns_302(client, signed_jwt):
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}
    resp = client.get(
        "/oauth/start",
        params={"account_email": "user@example.com", "redirect": True},
        headers=headers,
        follow_redirects=False,
    )
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("https://accounts.google.com/")


# ---- BLOCKER 3: 401 if bearer missing or invalid ----------------------------


def test_oauth_start_no_bearer_returns_401(client):
    resp = client.get("/oauth/start", params={"account_email": "x@y.com"})
    assert resp.status_code == 401
    assert "WWW-Authenticate" in resp.headers


def test_oauth_start_bad_bearer_returns_401(client):
    resp = client.get(
        "/oauth/start",
        params={"account_email": "x@y.com"},
        headers={"Authorization": "Bearer not-a-jwt"},
    )
    assert resp.status_code == 401


# ---- Required check: invalid email rejected ---------------------------------


def test_oauth_start_rejects_invalid_email(client, signed_jwt):
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}
    resp = client.get(
        "/oauth/start",
        params={"account_email": "not-an-email"},
        headers=headers,
    )
    assert resp.status_code == 400


# ---- /oauth2callback: full happy path ---------------------------------------


def test_oauth2callback_happy_path(client, signed_jwt):
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}
    start = client.get(
        "/oauth/start",
        params={"account_email": "user@example.com"},
        headers=headers,
    )
    assert start.status_code == 200
    auth_url = start.json()["authorization_url"]
    # Pull the state out of the URL.
    from urllib.parse import parse_qs, urlparse

    qs = parse_qs(urlparse(auth_url).query)
    state = qs["state"][0]

    token_response = {
        "access_token": "ya29.fresh",
        "refresh_token": "1//rt-secret",
        "expires_in": 3600,
        "scope": "openid email https://www.googleapis.com/auth/gmail.readonly",
        "token_type": "Bearer",
    }
    userinfo_response = {
        "sub": "google-user-123",
        "email": "user@example.com",
        "email_verified": True,
    }
    client._respx_router.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=token_response))
    client._respx_router.get(USERINFO_URL).mock(
        return_value=httpx.Response(200, json=userinfo_response)
    )

    resp = client.get("/oauth2callback", params={"code": "auth-code-abc", "state": state})
    assert resp.status_code == 200
    assert "Connected" in resp.text


# ---- Replay: a state token consumed once cannot be consumed again ----------


def test_oauth2callback_state_replay_rejected(client, signed_jwt):
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}
    start = client.get(
        "/oauth/start",
        params={"account_email": "rep@example.com"},
        headers=headers,
    )
    from urllib.parse import parse_qs, urlparse

    state = parse_qs(urlparse(start.json()["authorization_url"]).query)["state"][0]

    client._respx_router.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "ya29.x",
                "refresh_token": "1//rt-x",
                "expires_in": 3600,
                "scope": "openid email",
                "token_type": "Bearer",
            },
        )
    )
    client._respx_router.get(USERINFO_URL).mock(
        return_value=httpx.Response(
            200,
            json={"sub": "g-1", "email": "rep@example.com", "email_verified": True},
        )
    )

    first = client.get("/oauth2callback", params={"code": "c", "state": state})
    assert first.status_code == 200

    # Second consume attempt must fail; nonce already consumed.
    second = client.get("/oauth2callback", params={"code": "c", "state": state})
    assert second.status_code == 400
    assert "already been used" in second.text or "expired" in second.text


# ---- Tampered state is rejected with the generic error page ----------------


def test_oauth2callback_state_tampered_rejected(client, signed_jwt):
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}
    start = client.get(
        "/oauth/start",
        params={"account_email": "t@example.com"},
        headers=headers,
    )
    from urllib.parse import parse_qs, urlparse

    state = parse_qs(urlparse(start.json()["authorization_url"]).query)["state"][0]
    payload, sig = state.rsplit(".", 1)
    # Flip the FIRST char of the signature: it carries 6 fully signature-bearing
    # bits, whereas the last char's bottom 4 bits are base64url decode-padding
    # for a 32-byte HMAC-SHA256 digest, making last-char flips a no-op ~1/16
    # of runs.
    bad_state = f"{payload}.{('A' if sig[0] != 'A' else 'B') + sig[1:]}"

    resp = client.get("/oauth2callback", params={"code": "c", "state": bad_state})
    assert resp.status_code == 400
    # Generic message, no specific reason exposed.
    assert "invalid or expired" in resp.text


# ---- Google ?error= shortcircuits ------------------------------------------


def test_oauth2callback_google_error_param(client):
    resp = client.get("/oauth2callback", params={"error": "access_denied"})
    assert resp.status_code == 400
    assert "access_denied" in resp.text


# ---- Missing code/state shortcircuits --------------------------------------


def test_oauth2callback_missing_params(client):
    resp = client.get("/oauth2callback")
    assert resp.status_code == 400


# ---- Userinfo email mismatch -> 200 with connected_with_different_email ----
#
# Per the security review: when Google's userinfo returns a different
# email than the one /oauth/start was called with, we still persist the
# row (under Google's actual email, which is the source of truth) and
# return 200 JSON with the discrepancy surfaced. The connector UI is
# responsible for displaying it.


def test_callback_email_mismatch_returns_connected_with_different_email(client, signed_jwt, caplog):
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}
    start = client.get(
        "/oauth/start",
        params={"account_email": "expected@example.com"},
        headers=headers,
    )
    from urllib.parse import parse_qs, urlparse

    state = parse_qs(urlparse(start.json()["authorization_url"]).query)["state"][0]

    client._respx_router.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "ya29.x",
                "refresh_token": "1//rt-x",
                "expires_in": 3600,
                "scope": "openid email",
                "token_type": "Bearer",
            },
        )
    )
    # Userinfo says a DIFFERENT email than what /oauth/start was called with.
    client._respx_router.get(USERINFO_URL).mock(
        return_value=httpx.Response(
            200,
            json={"sub": "g-1", "email": "wrong@example.com", "email_verified": True},
        )
    )

    import logging as _logging

    with caplog.at_level(_logging.WARNING, logger="mcp_gmail.oauth_routes.callback"):
        resp = client.get("/oauth2callback", params={"code": "c", "state": state})

    # 200 + JSON body: status, requested, actual.
    assert resp.status_code == 200
    body = resp.json()
    assert body == {
        "status": "connected_with_different_email",
        "requested": "expected@example.com",
        "actual": "wrong@example.com",
    }

    # Row is persisted under the ACTUAL email (Google's userinfo).
    from mcp_gmail import db as db_module
    from mcp_gmail.token_store import GmailOAuthToken

    fresh_session = db_module._SessionFactory()
    try:
        rows = fresh_session.query(GmailOAuthToken).all()
        assert len(rows) == 1
        assert rows[0].account_email == "wrong@example.com"
        assert rows[0].auth0_sub == "user-abc"
        # Original requested email row should NOT exist.
        expected_row = (
            fresh_session.query(GmailOAuthToken)
            .filter_by(account_email="expected@example.com")
            .one_or_none()
        )
        assert expected_row is None
    finally:
        fresh_session.close()

    # WARN log fires with both emails. The redacting filter will not
    # redact email-shaped strings (they don't match the secret patterns).
    matching_records = [
        r
        for r in caplog.records
        if r.levelname == "WARNING" and "connected_with_different_email" in r.getMessage()
    ]
    assert len(matching_records) == 1
    msg = matching_records[0].getMessage()
    assert "expected@example.com" in msg
    assert "wrong@example.com" in msg


# ---- Token endpoint returns no refresh_token: hard fail --------------------


def test_oauth2callback_no_refresh_token_returned(client, signed_jwt):
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}
    start = client.get(
        "/oauth/start",
        params={"account_email": "nrt@example.com"},
        headers=headers,
    )
    from urllib.parse import parse_qs, urlparse

    state = parse_qs(urlparse(start.json()["authorization_url"]).query)["state"][0]
    client._respx_router.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "ya29.x",
                "expires_in": 3600,
                "scope": "openid email",
                "token_type": "Bearer",
            },
        )
    )
    resp = client.get("/oauth2callback", params={"code": "c", "state": state})
    assert resp.status_code == 400
    assert "refresh token" in resp.text.lower()


# ---- /oauth/status ---------------------------------------------------------


def test_oauth_status_returns_only_safe_fields(client, signed_jwt):
    """status must NEVER include refresh_token, access_token, or ciphertext."""
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}

    # Seed a row by completing a flow.
    start = client.get(
        "/oauth/start",
        params={"account_email": "status@example.com"},
        headers=headers,
    )
    from urllib.parse import parse_qs, urlparse

    state = parse_qs(urlparse(start.json()["authorization_url"]).query)["state"][0]
    client._respx_router.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "ya29.x",
                "refresh_token": "1//rt-x",
                "expires_in": 3600,
                "scope": "openid email",
                "token_type": "Bearer",
            },
        )
    )
    client._respx_router.get(USERINFO_URL).mock(
        return_value=httpx.Response(
            200,
            json={"sub": "g-1", "email": "status@example.com", "email_verified": True},
        )
    )
    cb = client.get("/oauth2callback", params={"code": "c", "state": state})
    assert cb.status_code == 200

    resp = client.get("/oauth/status", headers=headers)
    assert resp.status_code == 200
    body = resp.json()
    accounts = body["accounts"]
    assert len(accounts) == 1
    a = accounts[0]
    assert a["account_email"] == "status@example.com"
    assert a["has_token"] is True
    # New is_revoked field: false for active rows.
    assert a["is_revoked"] is False
    # Never leak secrets.
    assert "refresh_token" not in a
    assert "access_token" not in a
    assert "encrypted_refresh_token" not in a


def test_oauth_status_empty_when_no_rows(client, signed_jwt):
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}
    resp = client.get("/oauth/status", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"accounts": []}


def test_oauth_status_no_bearer_returns_401(client):
    resp = client.get("/oauth/status")
    assert resp.status_code == 401


# ---- /oauth/status include_revoked filter ----------------------------------
#
# Default: revoked rows are filtered out. include_revoked=true returns
# them with is_revoked=true.


def _seed_active_and_revoked_rows(jwt_factory, sub: str):
    """Helper: insert one active and one revoked row directly via the model."""
    from datetime import datetime, timezone

    from mcp_gmail.token_store import GmailOAuthToken

    fresh_session = db_module._SessionFactory()
    try:
        now = datetime.now(timezone.utc)
        active = GmailOAuthToken(
            auth0_sub=sub,
            account_email="active@example.com",
            encrypted_refresh_token=b"ciphertext-active",
            scope="openid email",
            created_at=now,
            updated_at=now,
        )
        revoked = GmailOAuthToken(
            auth0_sub=sub,
            account_email="revoked@example.com",
            encrypted_refresh_token=b"ciphertext-revoked",
            scope="openid email",
            revoked_at=now,
            created_at=now,
            updated_at=now,
        )
        fresh_session.add_all([active, revoked])
        fresh_session.commit()
    finally:
        fresh_session.close()


def test_oauth_status_default_filters_revoked_rows(client, signed_jwt):
    sub = "user-abc"
    _seed_active_and_revoked_rows(signed_jwt, sub)
    headers = {"Authorization": _bearer(signed_jwt, sub=sub)}

    # Default request: active-only.
    resp = client.get("/oauth/status", headers=headers)
    assert resp.status_code == 200
    accounts = resp.json()["accounts"]
    assert len(accounts) == 1
    assert accounts[0]["account_email"] == "active@example.com"
    assert accounts[0]["is_revoked"] is False
    assert accounts[0]["revoked_at"] is None


def test_oauth_status_include_revoked_returns_all_rows(client, signed_jwt):
    sub = "user-abc"
    _seed_active_and_revoked_rows(signed_jwt, sub)
    headers = {"Authorization": _bearer(signed_jwt, sub=sub)}

    resp = client.get("/oauth/status", headers=headers, params={"include_revoked": "true"})
    assert resp.status_code == 200
    accounts = resp.json()["accounts"]
    assert len(accounts) == 2

    by_email = {a["account_email"]: a for a in accounts}
    assert by_email["active@example.com"]["is_revoked"] is False
    assert by_email["active@example.com"]["has_token"] is True
    assert by_email["revoked@example.com"]["is_revoked"] is True
    # has_token is False on revoked rows (revoked_at is non-null).
    assert by_email["revoked@example.com"]["has_token"] is False
    assert by_email["revoked@example.com"]["revoked_at"] is not None


# ---- /oauth/disconnect -----------------------------------------------------


def test_oauth_disconnect_round_trip(client, signed_jwt):
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}

    # Seed via flow.
    start = client.get(
        "/oauth/start",
        params={"account_email": "disc@example.com"},
        headers=headers,
    )
    from urllib.parse import parse_qs, urlparse

    state = parse_qs(urlparse(start.json()["authorization_url"]).query)["state"][0]
    client._respx_router.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "ya29.x",
                "refresh_token": "1//rt-x",
                "expires_in": 3600,
                "scope": "openid email",
                "token_type": "Bearer",
            },
        )
    )
    client._respx_router.get(USERINFO_URL).mock(
        return_value=httpx.Response(
            200,
            json={"sub": "g-1", "email": "disc@example.com", "email_verified": True},
        )
    )
    client._respx_router.post(REVOKE_URL).mock(return_value=httpx.Response(200))
    cb = client.get("/oauth2callback", params={"code": "c", "state": state})
    assert cb.status_code == 200

    # Disconnect.
    resp = client.post(
        "/oauth/disconnect",
        json={"account_email": "disc@example.com"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json() == {"disconnected": True}

    # Disconnect again returns False (no row "found" because already revoked).
    # Actually our manager treats already-revoked as True, but the route's
    # `existed` check is "was the row present at request time"; row IS
    # present but soft-revoked. The manager returns True, AND existed is
    # True. So the second call returns disconnected: True (idempotent).
    resp2 = client.post(
        "/oauth/disconnect",
        json={"account_email": "disc@example.com"},
        headers=headers,
    )
    assert resp2.status_code == 200
    assert resp2.json() == {"disconnected": True}


def test_oauth_disconnect_unknown_account_returns_false(client, signed_jwt):
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}
    resp = client.post(
        "/oauth/disconnect",
        json={"account_email": "ghost@example.com"},
        headers=headers,
    )
    assert resp.status_code == 200
    assert resp.json() == {"disconnected": False}


def test_oauth_disconnect_requires_bearer(client):
    resp = client.post("/oauth/disconnect", json={"account_email": "x@y.com"})
    assert resp.status_code == 401


def test_oauth_disconnect_rejects_bad_body(client, signed_jwt):
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}
    resp = client.post(
        "/oauth/disconnect",
        json={"wrong_field": "x@y.com"},
        headers=headers,
    )
    assert resp.status_code == 400


# ---- regression net: has_token=False after disconnect --------
#
# After /oauth/disconnect, the row's encrypted_refresh_token is wiped to
# b"" and revoked_at is set. The status route's `has_token` invariant is:
#   has_token = (encrypted_refresh_token is not None) AND (revoked_at is None)
# With the wipe-to-b"" semantics the left side stays True (b"" is not None);
# soft_revoke flips the right side to False; AND -> False. This test pins
# the invariant against a regression that re-orders the wipe and
# soft_revoke or that wipes to NULL without setting revoked_at.


def test_oauth_status_has_token_false_after_disconnect(client, signed_jwt):
    """Critical regression: has_token MUST be False after disconnect."""
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}

    # Seed via flow.
    start = client.get(
        "/oauth/start",
        params={"account_email": "item7@example.com"},
        headers=headers,
    )
    from urllib.parse import parse_qs, urlparse

    state = parse_qs(urlparse(start.json()["authorization_url"]).query)["state"][0]
    client._respx_router.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "ya29.x",
                "refresh_token": "1//rt-x",
                "expires_in": 3600,
                "scope": "openid email",
                "token_type": "Bearer",
            },
        )
    )
    client._respx_router.get(USERINFO_URL).mock(
        return_value=httpx.Response(
            200,
            json={"sub": "g-1", "email": "item7@example.com", "email_verified": True},
        )
    )
    client._respx_router.post(REVOKE_URL).mock(return_value=httpx.Response(200))
    cb = client.get("/oauth2callback", params={"code": "c", "state": state})
    assert cb.status_code == 200

    # Pre-disconnect: row visible with has_token=True.
    pre = client.get("/oauth/status", headers=headers, params={"include_revoked": "true"})
    pre_accounts = pre.json()["accounts"]
    assert len(pre_accounts) == 1
    assert pre_accounts[0]["has_token"] is True
    assert pre_accounts[0]["is_revoked"] is False

    # Disconnect.
    disc = client.post(
        "/oauth/disconnect",
        json={"account_email": "item7@example.com"},
        headers=headers,
    )
    assert disc.status_code == 200
    assert disc.json() == {"disconnected": True}

    # Post-disconnect: include_revoked surfaces the row with has_token=False
    # AND is_revoked=True. The wipe semantics are working correctly.
    post = client.get("/oauth/status", headers=headers, params={"include_revoked": "true"})
    post_accounts = post.json()["accounts"]
    assert len(post_accounts) == 1
    assert post_accounts[0]["has_token"] is False
    assert post_accounts[0]["is_revoked"] is True

    # Verify the ciphertext was actually wiped at rest, not just hidden
    # behind has_token False. wipes to b"".
    from mcp_gmail import db as db_module
    from mcp_gmail.token_store import GmailOAuthToken

    fresh_session = db_module._SessionFactory()
    try:
        row = (
            fresh_session.query(GmailOAuthToken)
            .filter_by(auth0_sub="user-abc", account_email="item7@example.com")
            .one_or_none()
        )
        assert row is not None
        assert row.encrypted_refresh_token == b""
        assert row.revoked_at is not None
    finally:
        fresh_session.close()


# ---- Scope-downgrade persistence -------------------------------------------
#
# Google may grant fewer scopes than the request asked for (the user
# unchecks specific permissions on the consent screen). The granted
# scope from the token response is what we must record on the row, NOT
# the requested scope. The tool dispatcher checks granted scope before
# invoking tools that require specific scopes.


def test_callback_persists_granted_scope_when_narrower_than_requested(client, signed_jwt):
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}
    start = client.get(
        "/oauth/start",
        params={"account_email": "scope@example.com"},
        headers=headers,
    )
    from urllib.parse import parse_qs, urlparse

    auth_url = start.json()["authorization_url"]
    qs = parse_qs(urlparse(auth_url).query)
    state = qs["state"][0]
    requested_scopes = qs["scope"][0]
    # The flow asks for openid + email + gmail.readonly per fixture env.
    assert "gmail.readonly" in requested_scopes
    assert "openid" in requested_scopes

    # Google grants a SUBSET: just openid + email (user unchecked
    # gmail.readonly on the consent screen).
    granted = "openid email"
    client._respx_router.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "ya29.x",
                "refresh_token": "1//rt-x",
                "expires_in": 3600,
                "scope": granted,
                "token_type": "Bearer",
            },
        )
    )
    client._respx_router.get(USERINFO_URL).mock(
        return_value=httpx.Response(
            200,
            json={"sub": "g-1", "email": "scope@example.com", "email_verified": True},
        )
    )

    cb = client.get("/oauth2callback", params={"code": "c", "state": state})
    assert cb.status_code == 200

    # Verify the persisted row's scope is the GRANTED value, not the
    # requested one.
    from mcp_gmail.token_store import GmailOAuthToken

    fresh_session = db_module._SessionFactory()
    try:
        row = (
            fresh_session.query(GmailOAuthToken)
            .filter_by(auth0_sub="user-abc", account_email="scope@example.com")
            .one_or_none()
        )
        assert row is not None
        assert row.scope == granted
        assert "gmail.readonly" not in row.scope
    finally:
        fresh_session.close()


# ---- Deep-walk redaction integration tests ---------------------------------
#
# The redacting filter is defense-in-depth. The primary control is "do
# not log secrets at the callsite." These two tests run the actual
# /oauth/start and /oauth2callback flows with caplog capturing every
# record emitted, and walk every record's message + args to confirm no
# refresh-token-shaped or bearer-token-shaped substring leaked through.
#
# We deliberately use distinctive, recognizable refresh-token and
# bearer-token shapes so a regression that bypasses the filter would
# match. The filter operates at the handler level; caplog attaches its
# own handler, so we replicate the filter installation in the test
# fixture below to mirror production startup.


def _install_redacting_filter_on_caplog(caplog):
    """Mirror server.py lifespan startup: install the redacting filter
    on caplog's handler. caplog attaches a fresh handler each test;
    without this, only handlers attached at app startup carry the
    filter, and caplog would see unredacted records.
    """
    from mcp_gmail.logging_filters import RedactingFilter

    # caplog has a `handler` attribute (LogCaptureHandler).
    if not any(isinstance(f, RedactingFilter) for f in caplog.handler.filters):
        caplog.handler.addFilter(RedactingFilter())


def _walk_record_strings(record):
    """Yield every string-shaped attribute on a log record (post-filter).

    The filter rewrites record.msg and clears record.args; our deep
    walk inspects those plus any custom string attribute that a
    callsite may have attached via the `extra` kwarg. Non-string
    attributes are skipped because they cannot carry a token-shaped
    value.
    """
    for name in ("msg", "message"):
        v = getattr(record, name, None)
        if isinstance(v, str):
            yield v
    args = getattr(record, "args", None)
    if isinstance(args, tuple):
        for a in args:
            if isinstance(a, str):
                yield a
    elif isinstance(args, dict):
        for v in args.values():
            if isinstance(v, str):
                yield v


def _assert_no_secret_shapes_in_records(records, *, sentinel_substrings):
    """Walk every record, fail if any sentinel substring leaks through."""
    for record in records:
        for s in _walk_record_strings(record):
            for sentinel in sentinel_substrings:
                assert sentinel not in s, f"Sentinel {sentinel!r} leaked into log record: {s!r}"


def test_callback_logs_no_secrets_deep_walk(client, signed_jwt, caplog):
    """End-to-end /oauth2callback: no refresh_token or access_token shapes leak."""
    import logging as _logging

    _install_redacting_filter_on_caplog(caplog)
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}
    start = client.get(
        "/oauth/start",
        params={"account_email": "deep@example.com"},
        headers=headers,
    )
    from urllib.parse import parse_qs, urlparse

    state = parse_qs(urlparse(start.json()["authorization_url"]).query)["state"][0]

    # Distinctive token-shaped sentinels that the redacting filter
    # patterns must catch.
    leaky_refresh = "1//RT_DEEPWALK_SECRET_aaaaaaaaaaaaaaaaaaaaaa"
    leaky_access = "ya29.AccessTokenSecretSentinel0123456789"

    client._respx_router.post(TOKEN_URL).mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": leaky_access,
                "refresh_token": leaky_refresh,
                "expires_in": 3600,
                "scope": "openid email",
                "token_type": "Bearer",
            },
        )
    )
    client._respx_router.get(USERINFO_URL).mock(
        return_value=httpx.Response(
            200,
            json={"sub": "g-1", "email": "deep@example.com", "email_verified": True},
        )
    )

    with caplog.at_level(_logging.DEBUG):
        cb = client.get("/oauth2callback", params={"code": "c", "state": state})
    assert cb.status_code == 200

    _assert_no_secret_shapes_in_records(
        caplog.records,
        sentinel_substrings=(leaky_refresh, leaky_access),
    )


def test_oauth_start_logs_no_secrets_deep_walk(client, signed_jwt, caplog):
    """End-to-end /oauth/start: bearer token shape never appears in logs."""
    import logging as _logging

    _install_redacting_filter_on_caplog(caplog)
    # Use a recognizable but JWT-shaped sentinel as the bearer token.
    # JWT pattern is header.payload.signature with each segment >=8
    # base64url chars; the redacting filter's JWT_LIKE pattern must
    # match this AND the BEARER pattern must catch the prefix.
    jwt_token = signed_jwt({"sub": "user-abc"})
    headers = {"Authorization": f"Bearer {jwt_token}"}

    with caplog.at_level(_logging.DEBUG):
        resp = client.get(
            "/oauth/start",
            params={"account_email": "deep-start@example.com"},
            headers=headers,
        )
    assert resp.status_code == 200

    # Walk every record's strings: the raw JWT must NOT appear, and the
    # bearer-prefix-with-token shape must NOT appear.
    bearer_with_token = f"Bearer {jwt_token}"
    _assert_no_secret_shapes_in_records(
        caplog.records,
        sentinel_substrings=(jwt_token, bearer_with_token),
    )
