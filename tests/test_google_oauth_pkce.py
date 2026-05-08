"""PKCE-related cases for state crypto, authorization URL, and token exchange.

Targets: mcp-gmail/src/mcp_gmail/oauth_state.py:sign_state (code_verifier field)
Targets: mcp-gmail/src/mcp_gmail/oauth_state.py:verify_state (code_verifier field)
Targets: mcp-gmail/src/mcp_gmail/oauth_state.py:build_authorization_url (PKCE params)
Targets: mcp-gmail/src/mcp_gmail/oauth_http.py:exchange_code (code_verifier in form body)

Sibling of tests/test_google_oauth.py. Split out so the parent file
stays at its 230 LOC baseline and PKCE-specific cases live in one
greppable place. Same import + fixture pattern as the parent.
"""

from __future__ import annotations

import httpx
import pytest
import respx
from cryptography.fernet import Fernet

from mcp_gmail.oauth_http import (
    TOKEN_URL,
    exchange_code,
)
from mcp_gmail.oauth_state import (
    build_authorization_url,
    sign_state,
    verify_state,
)


@pytest.fixture
def signing_key() -> str:
    return Fernet.generate_key().decode("ascii")


# RFC 7636 §4.6 published test vector (also used in tests/test_pkce.py).
_PKCE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
_PKCE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


# Case 1: state round-trip preserves the PKCE code_verifier (`v`) field.
def test_state_round_trip_preserves_code_verifier(signing_key):
    state = sign_state(
        nonce="n",
        auth0_sub="auth0|v",
        account_email="v@example.com",
        signing_key=signing_key,
        code_verifier=_PKCE_VERIFIER,
    )
    assert verify_state(state, signing_key).code_verifier == _PKCE_VERIFIER


# Case 2: legacy state (no `v`) still verifies; ctx.code_verifier is None.
# Crypto must decode legacy state so callback.py can log + reject it.
def test_legacy_state_without_verifier_verifies_with_none_code_verifier(signing_key):
    state = sign_state(
        nonce="legacy-n",
        auth0_sub="auth0|legacy",
        account_email="legacy@example.com",
        signing_key=signing_key,
    )
    ctx = verify_state(state, signing_key)
    assert ctx.code_verifier is None and ctx.nonce == "legacy-n"


# Case 3: build_authorization_url emits PKCE params when challenge supplied.
def test_build_authorization_url_emits_pkce_params():
    url = build_authorization_url(
        client_id="cid",
        redirect_uri="https://mcp-gmail.test/oauth2callback",
        scopes=["openid", "email"],
        state="s",
        code_challenge=_PKCE_CHALLENGE,
    )
    assert f"code_challenge={_PKCE_CHALLENGE}" in url
    assert "code_challenge_method=S256" in url


# Case 4: build_authorization_url omits PKCE params when challenge absent.
def test_build_authorization_url_omits_pkce_when_challenge_absent():
    url = build_authorization_url(
        client_id="cid",
        redirect_uri="https://mcp-gmail.test/oauth2callback",
        scopes=["openid", "email"],
        state="s",
    )
    assert "code_challenge" not in url


# Case 5: exchange_code form body includes code_verifier ONLY when
# supplied (regression guard against an empty `code_verifier=` on the
# wire that Google would 400).
@pytest.mark.asyncio
async def test_exchange_code_form_body_includes_verifier_only_when_supplied():
    from urllib.parse import parse_qs

    fake = {
        "access_token": "x",
        "refresh_token": "1//r",
        "expires_in": 3600,
        "scope": "openid",
        "token_type": "Bearer",
    }
    captured: list[dict] = []

    def _capture(request):
        captured.append(parse_qs(request.content.decode("utf-8")))
        return httpx.Response(200, json=fake)

    redirect = "https://mcp-gmail.test/oauth2callback"
    with respx.mock(assert_all_called=True) as router:
        router.post(TOKEN_URL).mock(side_effect=_capture)
        await exchange_code(
            client_id="cid",
            client_secret="csec",
            code="c",
            redirect_uri=redirect,
            code_verifier=_PKCE_VERIFIER,
        )
        await exchange_code(client_id="cid", client_secret="csec", code="c", redirect_uri=redirect)
    assert captured[0].get("code_verifier") == [_PKCE_VERIFIER]
    assert "code_verifier" not in captured[1]
