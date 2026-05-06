"""Google OAuth helpers: state HMAC, fingerprint, exchange, refresh, userinfo, revoke.

Targets: mcp-gmail/src/mcp_gmail/oauth_state.py:sign_state
Targets: mcp-gmail/src/mcp_gmail/oauth_state.py:verify_state
Targets: mcp-gmail/src/mcp_gmail/oauth_state.py:compute_sub_fingerprint
Targets: mcp-gmail/src/mcp_gmail/oauth_state.py:build_authorization_url
Targets: mcp-gmail/src/mcp_gmail/oauth_http.py:exchange_code
Targets: mcp-gmail/src/mcp_gmail/oauth_http.py:refresh_access_token
Targets: mcp-gmail/src/mcp_gmail/oauth_http.py:fetch_userinfo
Targets: mcp-gmail/src/mcp_gmail/oauth_http.py:revoke_refresh_token
"""

from __future__ import annotations

import time

import httpx
import pytest
import respx
from cryptography.fernet import Fernet

from mcp_gmail import oauth_state
from mcp_gmail.oauth_http import (
    REVOKE_URL,
    TOKEN_URL,
    USERINFO_URL,
    GoogleOAuthError,
    exchange_code,
    fetch_userinfo,
    refresh_access_token,
    revoke_refresh_token,
)
from mcp_gmail.oauth_state import (
    AUTHORIZE_URL,
    StateVerificationError,
    build_authorization_url,
    compute_sub_fingerprint,
    sign_state,
    verify_state,
)


@pytest.fixture
def signing_key() -> str:
    return Fernet.generate_key().decode("ascii")


# Case 1: sign_state + verify_state happy path round-trips.
def test_state_round_trip(signing_key):
    state = sign_state(
        nonce="nonce-abc",
        auth0_sub="auth0|user1",
        account_email="user@example.com",
        signing_key=signing_key,
    )
    ctx = verify_state(state, signing_key)
    assert ctx.nonce == "nonce-abc"
    assert ctx.auth0_sub == "auth0|user1"
    assert ctx.account_email == "user@example.com"
    assert ctx.sub_fingerprint == compute_sub_fingerprint(
        "auth0|user1", "user@example.com", signing_key
    )


# Case 2: tampered signature is rejected.
def test_state_signature_tamper_rejected(signing_key):
    state = sign_state(
        nonce="nonce-abc",
        auth0_sub="auth0|user1",
        account_email="user@example.com",
        signing_key=signing_key,
    )
    # Flip a character in the signature segment.
    payload, sig = state.rsplit(".", 1)
    # Flip the FIRST char (carries 6 fully signature-bearing bits). The last
    # char of a base64url-encoded 32-byte HMAC-SHA256 digest only carries 2
    # signature bits (the bottom 4 bits are decode-padding), so flipping the
    # last char keeps the same decoded final byte ~1/16 of runs and the
    # tamper goes undetected. Flipping the first char is deterministic.
    flipped = ("A" if sig[0] != "A" else "B") + sig[1:]
    bad = f"{payload}.{flipped}"
    with pytest.raises(StateVerificationError):
        verify_state(bad, signing_key)


# Case 3: state signed with a different key is rejected.
def test_state_wrong_key_rejected(signing_key):
    state = sign_state(
        nonce="n",
        auth0_sub="s",
        account_email="e@e.com",
        signing_key=signing_key,
    )
    other = Fernet.generate_key().decode("ascii")
    with pytest.raises(StateVerificationError):
        verify_state(state, other)


# Case 4: expired iat is rejected, future iat (beyond skew) is rejected.
def test_state_iat_window(signing_key):
    too_old = sign_state(
        nonce="n",
        auth0_sub="s",
        account_email="e@e.com",
        signing_key=signing_key,
        iat=int(time.time()) - oauth_state.STATE_TTL_SECONDS - 5,
    )
    with pytest.raises(StateVerificationError, match="expired"):
        verify_state(too_old, signing_key)

    too_new = sign_state(
        nonce="n",
        auth0_sub="s",
        account_email="e@e.com",
        signing_key=signing_key,
        iat=int(time.time()) + oauth_state.STATE_CLOCK_SKEW_BEHIND_SECONDS + 60,
    )
    with pytest.raises(StateVerificationError, match="future"):
        verify_state(too_new, signing_key)


# Case 5: build_authorization_url contains required params.
def test_build_authorization_url():
    url = build_authorization_url(
        client_id="client-xyz",
        redirect_uri="https://mcp-gmail.test/oauth2callback",
        scopes=["https://www.googleapis.com/auth/gmail.readonly", "openid", "email"],
        state="state-abc",
    )
    assert url.startswith(AUTHORIZE_URL)
    # Required Google params for offline + refresh-token issuance.
    assert "access_type=offline" in url
    assert "prompt=consent" in url
    assert "include_granted_scopes=true" in url
    assert "client_id=client-xyz" in url
    assert "state=state-abc" in url
    # Scopes joined with space, URL-encoded as +
    assert "scope=" in url


# Case 6: exchange_code parses a successful Google response.
@pytest.mark.asyncio
async def test_exchange_code_success():
    fake_response = {
        "access_token": "ya29.fake-access",
        "refresh_token": "1//rt-fake",
        "scope": "https://www.googleapis.com/auth/gmail.readonly openid email",
        "expires_in": 3600,
        "token_type": "Bearer",
        "id_token": "header.payload.sig",
    }
    with respx.mock(assert_all_called=True) as router:
        router.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=fake_response))
        result = await exchange_code(
            client_id="cid",
            client_secret="csec",
            code="auth-code",
            redirect_uri="https://mcp-gmail.test/oauth2callback",
        )
    assert result.access_token == "ya29.fake-access"
    assert result.refresh_token == "1//rt-fake"
    assert "gmail.readonly" in result.scope
    assert result.expires_at_epoch > time.time()
    assert result.id_token == "header.payload.sig"


# Case 7: refresh_access_token + fetch_userinfo + revoke_refresh_token roundtrips.
@pytest.mark.asyncio
async def test_refresh_userinfo_revoke_round_trips():
    refresh_payload = {
        "access_token": "ya29.new-access",
        "expires_in": 3600,
        "scope": "https://www.googleapis.com/auth/gmail.readonly",
        "token_type": "Bearer",
    }
    userinfo_payload = {
        "sub": "google-sub-123",
        "email": "User@Example.com",
        "email_verified": True,
    }
    with respx.mock(assert_all_called=True) as router:
        router.post(TOKEN_URL).mock(return_value=httpx.Response(200, json=refresh_payload))
        router.get(USERINFO_URL).mock(return_value=httpx.Response(200, json=userinfo_payload))
        router.post(REVOKE_URL).mock(return_value=httpx.Response(200))

        refreshed = await refresh_access_token(
            client_id="cid", client_secret="csec", refresh_token="1//rt-fake"
        )
        assert refreshed.access_token == "ya29.new-access"
        assert refreshed.refresh_token is None  # refresh path may omit it

        info = await fetch_userinfo(refreshed.access_token)
        assert info.sub == "google-sub-123"
        assert info.email == "user@example.com"  # lowercased

        revoked = await revoke_refresh_token("1//rt-fake")
        assert revoked is True


# Case 8: error responses raise GoogleOAuthError, not silent failures.
@pytest.mark.asyncio
async def test_token_endpoint_400_raises():
    with respx.mock(assert_all_called=True) as router:
        router.post(TOKEN_URL).mock(
            return_value=httpx.Response(400, json={"error": "invalid_grant"})
        )
        with pytest.raises(GoogleOAuthError) as excinfo:
            await refresh_access_token(
                client_id="cid", client_secret="csec", refresh_token="1//bad"
            )
    assert excinfo.value.status == 400


def test_compute_sub_fingerprint_email_case_insensitive(signing_key):
    """Fingerprint must collapse email case so re-link with mixed-case matches."""
    a = compute_sub_fingerprint("auth0|x", "User@Example.com", signing_key)
    b = compute_sub_fingerprint("auth0|x", "user@example.com", signing_key)
    assert a == b


def test_state_with_email_case_mismatch_still_verifies(signing_key):
    """sign_state lowercases the email so verify_state succeeds either way."""
    state = sign_state(
        nonce="n",
        auth0_sub="s",
        account_email="MixedCase@Example.com",
        signing_key=signing_key,
    )
    ctx = verify_state(state, signing_key)
    assert ctx.account_email == "mixedcase@example.com"
