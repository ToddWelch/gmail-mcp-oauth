"""End-to-end PKCE coverage for the Google OAuth routes.

Targets: mcp-gmail/src/mcp_gmail/oauth_routes/start.py:oauth_start
Targets: mcp-gmail/src/mcp_gmail/oauth_routes/callback.py:oauth2callback
Targets: mcp-gmail/src/mcp_gmail/oauth_state.py:sign_state (PKCE v field)

This sibling file holds the three PKCE end-to-end cases that would
otherwise push tests/test_oauth_routes.py beyond the 300-LOC ceiling.
The pre-existing tests/test_oauth_routes.py file is at 901 LOC (a
baseline violation that predates this PR) and is intentionally left
untouched here.

Cases
-----
1. Happy path: /oauth/start -> state extraction -> mocked TOKEN_URL
   sees `code_verifier` in the form body -> /oauth2callback returns
   the success page.
2. Legacy state (no `v` field) is hard-rejected by /oauth2callback.
3. Tampered HMAC over a `v`-bearing state is rejected by the
   existing signature-mismatch path.
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
from mcp_gmail import oauth_state
from mcp_gmail import token_manager as tm
from mcp_gmail.db import Base
from mcp_gmail.oauth_http import TOKEN_URL, USERINFO_URL
from mcp_gmail.server import app
from mcp_gmail.state_store import create_nonce

from .conftest import TEST_JWKS_URL, TEST_STATE_SIGNING_KEY


@pytest.fixture
def client(jwks_document):
    """Same StaticPool fixture pattern as tests/test_oauth_routes.py.

    See that file's `client` fixture docstring for why we replace the
    db_module engine with a StaticPool-backed in-memory SQLite engine
    after the lifespan has run init_engine().
    """
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


# ---- Case 1: happy path; code_verifier travels with the token swap ---------


def test_oauth_pkce_happy_path_sends_code_verifier_to_token_endpoint(client, signed_jwt):
    """End-to-end: /oauth/start -> /oauth2callback with PKCE wired.

    Asserts that the form body POSTed to Google's TOKEN_URL contains
    `code_verifier`. Captured via respx by inspecting the recorded
    request after the route fires.
    """
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}
    start = client.get(
        "/oauth/start",
        params={"account_email": "user@example.com"},
        headers=headers,
    )
    assert start.status_code == 200
    auth_url = start.json()["authorization_url"]

    qs = parse_qs(urlparse(auth_url).query)
    state = qs["state"][0]
    # The challenge must appear on the consent URL with method=S256;
    # the verifier must NOT (it stays in the HMAC state blob).
    assert qs["code_challenge_method"] == ["S256"]
    assert "code_challenge" in qs
    assert "code_verifier" not in qs

    token_route = client._respx_router.post(TOKEN_URL).mock(
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
                "sub": "google-user-123",
                "email": "user@example.com",
                "email_verified": True,
            },
        )
    )

    resp = client.get("/oauth2callback", params={"code": "auth-code-abc", "state": state})
    assert resp.status_code == 200
    assert "Connected" in resp.text

    # Verify the captured form body POSTed to TOKEN_URL contains the verifier.
    assert token_route.called, "TOKEN_URL was never hit"
    captured = token_route.calls.last.request
    body_text = captured.content.decode("ascii")
    captured_form = parse_qs(body_text)
    assert "code_verifier" in captured_form
    assert captured_form["code_verifier"][0]
    # Sanity: the same blob fields we still need are present.
    assert captured_form["grant_type"] == ["authorization_code"]
    assert captured_form["code"] == ["auth-code-abc"]


# ---- Case 2: legacy state (no `v` field) is hard-rejected -------------------


def test_oauth2callback_legacy_state_without_pkce_verifier_rejected(client, signed_jwt):
    """A state minted before PKCE rollout (no `v` field) is hard-rejected.

    callback.py checks ctx.code_verifier is not None and surfaces the
    generic "invalid or expired" message. This guards against silent
    PKCE downgrade if an old in-flight state somehow survives a deploy.
    """
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}
    # Use the live nonce store so the consume_nonce path is real.
    with db_module.session_scope() as session:
        nonce = create_nonce(session, auth0_sub="user-abc", account_email="legacy@example.com")

    legacy_state = oauth_state.sign_state(
        nonce=nonce,
        auth0_sub="user-abc",
        account_email="legacy@example.com",
        signing_key=TEST_STATE_SIGNING_KEY,
        code_verifier=None,  # legacy: no `v` field at all
    )

    resp = client.get(
        "/oauth2callback",
        params={"code": "c", "state": legacy_state},
        headers=headers,
    )
    assert resp.status_code == 400
    assert "invalid or expired" in resp.text


# ---- Case 3: tampered HMAC over a `v`-bearing state is rejected -------------


def test_oauth2callback_tampered_pkce_state_rejected(client, signed_jwt):
    """A `v`-bearing state with a flipped signature byte fails HMAC.

    Mirrors the existing `test_oauth2callback_state_tampered_rejected`
    case in tests/test_oauth_routes.py but on a PKCE-bearing state to
    confirm `v` is inside the HMAC-protected blob.
    """
    headers = {"Authorization": _bearer(signed_jwt, sub="user-abc")}
    start = client.get(
        "/oauth/start",
        params={"account_email": "tampered@example.com"},
        headers=headers,
    )
    assert start.status_code == 200
    state = parse_qs(urlparse(start.json()["authorization_url"]).query)["state"][0]

    payload, sig = state.rsplit(".", 1)
    # Flip the FIRST char of the signature: it carries 6 fully signature-
    # bearing bits, whereas the last char's bottom 4 bits are decode-padding
    # for the 32-byte HMAC-SHA256 digest. Same trick as the legacy test.
    bad_state = f"{payload}.{('A' if sig[0] != 'A' else 'B') + sig[1:]}"

    resp = client.get(
        "/oauth2callback",
        params={"code": "c", "state": bad_state},
        headers=headers,
    )
    assert resp.status_code == 400
    assert "invalid or expired" in resp.text
