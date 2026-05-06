"""JWT validation and WWW-Authenticate header building.

Targets: src/mcp_gmail/auth.py:validate_bearer_token
Targets: src/mcp_gmail/auth.py:build_www_authenticate

Exercises the bearer-token validation path end-to-end: signature
verification against a JWKS document, audience and issuer checks,
expiry / not-before windows, and the WWW-Authenticate response shape
returned to clients on rejection.
"""

from __future__ import annotations

import time

import httpx
import pytest
import respx

from mcp_gmail import auth as auth_module
from mcp_gmail.auth import AuthError, build_www_authenticate, validate_bearer_token

from .conftest import TEST_ISSUER, TEST_JWKS_URL, TEST_RESOURCE


@pytest.fixture(autouse=True)
def mock_jwks(jwks_document):
    with respx.mock(assert_all_called=False) as router:
        router.get(TEST_JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_document))
        yield router


async def test_valid_token_accepted(settings, signed_jwt):
    token = signed_jwt()
    claims = await validate_bearer_token(token, settings)
    assert claims["iss"] == TEST_ISSUER
    assert claims["aud"] == TEST_RESOURCE
    assert claims["sub"] == "user-abc"


async def test_empty_token_rejected(settings):
    with pytest.raises(AuthError) as excinfo:
        await validate_bearer_token("", settings)
    assert excinfo.value.reason == "invalid_token"


async def test_expired_token_rejected(settings, signed_jwt):
    now = int(time.time())
    token = signed_jwt({"iat": now - 7200, "exp": now - 60})
    with pytest.raises(AuthError) as excinfo:
        await validate_bearer_token(token, settings)
    assert excinfo.value.reason == "expired_token"


async def test_wrong_issuer_rejected(settings, signed_jwt):
    token = signed_jwt({"iss": "https://evil.example.com"})
    with pytest.raises(AuthError) as excinfo:
        await validate_bearer_token(token, settings)
    assert excinfo.value.reason == "invalid_issuer"


async def test_wrong_aud_rejected_by_default(settings, signed_jwt):
    token = signed_jwt({"aud": "dcr-minted-client-id-xyz"})
    with pytest.raises(AuthError) as excinfo:
        await validate_bearer_token(token, settings)
    assert excinfo.value.reason == "invalid_aud"


async def test_wrong_aud_accepted_when_tolerance_explicitly_on(monkeypatch, signed_jwt):
    """tolerance accepts only allowlisted client_ids."""
    monkeypatch.setenv("MCP_ACCEPT_CLIENT_ID_AUD", "true")
    monkeypatch.setenv("MCP_ACCEPTED_CLIENT_IDS", "dcr-minted-client-id-xyz")
    from mcp_gmail import config as config_module

    settings = config_module.load()
    token = signed_jwt({"aud": "dcr-minted-client-id-xyz"})
    claims = await validate_bearer_token(token, settings)
    assert claims["aud"] == "dcr-minted-client-id-xyz"


async def test_wrong_aud_rejected_even_with_tolerance_when_not_allowlisted(monkeypatch, signed_jwt):
    """a client_id not in the allowlist is rejected
    even when tolerance is on. Conservative interpretation per
    the conservative interpretation."""
    monkeypatch.setenv("MCP_ACCEPT_CLIENT_ID_AUD", "true")
    monkeypatch.setenv("MCP_ACCEPTED_CLIENT_IDS", "approved-client-id-only")
    from mcp_gmail import config as config_module

    settings = config_module.load()
    token = signed_jwt({"aud": "rogue-dcr-client-id"})
    with pytest.raises(AuthError) as excinfo:
        await validate_bearer_token(token, settings)
    assert excinfo.value.reason == "invalid_aud"


async def test_aud_list_with_one_unrecognized_entry_rejected_under_tolerance(
    monkeypatch, signed_jwt
):
    """conservative interpretation: an aud LIST with
    one allowlisted client_id and one unrecognized value is rejected.
    The original behavior accepted any aud list with at least one valid
    entry; the conservative interpretation tightens this when tolerance is on."""
    monkeypatch.setenv("MCP_ACCEPT_CLIENT_ID_AUD", "true")
    monkeypatch.setenv("MCP_ACCEPTED_CLIENT_IDS", "client-good")
    from mcp_gmail import config as config_module

    settings = config_module.load()
    token = signed_jwt({"aud": ["client-good", "client-rogue"]})
    with pytest.raises(AuthError) as excinfo:
        await validate_bearer_token(token, settings)
    assert excinfo.value.reason == "invalid_aud"


async def test_aud_list_with_resource_url_and_allowlisted_entry_accepted(monkeypatch, signed_jwt):
    """under tolerance, an aud list mixing the
    resource URL and an allowlisted client_id is accepted."""
    monkeypatch.setenv("MCP_ACCEPT_CLIENT_ID_AUD", "true")
    monkeypatch.setenv("MCP_ACCEPTED_CLIENT_IDS", "approved-client-id")
    from mcp_gmail import config as config_module

    settings = config_module.load()
    token = signed_jwt({"aud": [TEST_RESOURCE, "approved-client-id"]})
    claims = await validate_bearer_token(token, settings)
    assert TEST_RESOURCE in claims["aud"]


async def test_aud_list_under_tolerance_off_with_extra_entries_still_accepted(settings, signed_jwt):
    """Original behavior preserved when tolerance is OFF: an aud list
    with the resource URL plus extra entries still validates. The
    conservative every-entry check is gated on tolerance ON."""
    token = signed_jwt({"aud": [TEST_RESOURCE, "harmless-extra"]})
    claims = await validate_bearer_token(token, settings)
    assert TEST_RESOURCE in claims["aud"]


async def test_missing_aud_always_rejected(settings, signed_jwt, rsa_keypair):
    import jwt

    now = int(time.time())
    token = jwt.encode(
        {"iss": TEST_ISSUER, "sub": "x", "iat": now, "exp": now + 60},
        rsa_keypair["private_pem"],
        algorithm="RS256",
        headers={"kid": "test-kid-1", "alg": "RS256"},
    )
    with pytest.raises(AuthError) as excinfo:
        await validate_bearer_token(token, settings)
    assert excinfo.value.reason == "invalid_aud"


async def test_aud_list_accepted(settings, signed_jwt):
    token = signed_jwt({"aud": ["some-other", TEST_RESOURCE]})
    claims = await validate_bearer_token(token, settings)
    assert TEST_RESOURCE in claims["aud"]


async def test_bad_signature_rejected(settings, signed_jwt):
    token = signed_jwt()
    sig_start = token.rindex(".") + 1
    mid = sig_start + (len(token) - sig_start) // 2
    tampered = token[:mid] + ("A" if token[mid] != "A" else "B") + token[mid + 1 :]
    with pytest.raises(AuthError) as excinfo:
        await validate_bearer_token(tampered, settings)
    assert excinfo.value.reason == "invalid_token"


async def test_tampered_payload_rejected(settings, signed_jwt):
    """Guard against a refactor that ever decodes the payload without re-checking the signature."""
    import base64
    import json

    token = signed_jwt()
    header_b64, payload_b64, signature_b64 = token.split(".")

    def _b64url_decode(segment: str) -> bytes:
        padding = "=" * (-len(segment) % 4)
        return base64.urlsafe_b64decode(segment + padding)

    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

    payload = json.loads(_b64url_decode(payload_b64))
    payload["sub"] = "attacker"
    tampered_payload_json = json.dumps(payload, separators=(",", ":")).encode("ascii")
    tampered_payload_b64 = _b64url_encode(tampered_payload_json)
    tampered = f"{header_b64}.{tampered_payload_b64}.{signature_b64}"

    with pytest.raises(AuthError) as excinfo:
        await validate_bearer_token(tampered, settings)
    assert excinfo.value.reason == "invalid_token"


async def test_scope_required_and_missing(monkeypatch, signed_jwt):
    monkeypatch.setenv("MCP_EXPECTED_SCOPES", "gmail.read gmail.send")
    from mcp_gmail import config as config_module

    settings = config_module.load()
    token = signed_jwt({"scope": "gmail.read"})
    with pytest.raises(AuthError) as excinfo:
        await validate_bearer_token(token, settings)
    assert excinfo.value.reason == "insufficient_scope"


async def test_scope_satisfied(monkeypatch, signed_jwt):
    monkeypatch.setenv("MCP_EXPECTED_SCOPES", "gmail.read")
    from mcp_gmail import config as config_module

    settings = config_module.load()
    token = signed_jwt({"scope": "gmail.read gmail.send"})
    claims = await validate_bearer_token(token, settings)
    assert "scope" in claims


async def test_aud_with_trailing_slash_accepted(monkeypatch, signed_jwt):
    monkeypatch.setenv("MCP_RESOURCE_URL", "https://mcp-gmail.test.local/")
    monkeypatch.setenv("MCP_ACCEPT_CLIENT_ID_AUD", "false")
    from mcp_gmail import config as config_module

    settings_with_slash = config_module.load()
    token = signed_jwt({"aud": "https://mcp-gmail.test.local/"})
    claims = await validate_bearer_token(token, settings_with_slash)
    assert claims["aud"] == "https://mcp-gmail.test.local/"


def test_www_authenticate_format(settings):
    header = build_www_authenticate(settings, "expired_token")
    assert 'Bearer realm="https://mcp-gmail.test.local"' in header
    expected_rm = (
        'resource_metadata="https://mcp-gmail.test.local/.well-known/oauth-protected-resource"'
    )
    assert expected_rm in header
    assert 'error="expired_token"' in header


def test_www_authenticate_no_double_slash():
    """Trailing-slash resource URL must not yield a double slash before .well-known."""
    from mcp_gmail.config import Settings

    settings_with_slash = Settings(
        oauth_issuer_url="https://issuer.test.local/",
        oauth_jwks_url=TEST_JWKS_URL,
        mcp_resource_url="https://mcp-gmail.test.local/",
        mcp_expected_scopes=(),
        mcp_accept_client_id_aud=True,
        # non-empty allowlist when tolerance is on.
        mcp_accepted_client_ids=("test-client-id",),
        jwks_cache_ttl_seconds=300,
        http_timeout_seconds=5,
        database_url="sqlite+pysqlite:///:memory:",
        encryption_key="dummy-encryption-key-for-test",
        state_signing_key="dummy-state-key-for-test",
        log_level="INFO",
        port=8000,
        google_oauth_client_id="dummy-client-id",
        google_oauth_client_secret="dummy-client-secret",
        google_oauth_redirect_url="https://mcp-gmail.test.local/oauth2callback",
        gmail_oauth_scopes=("openid", "email"),
    )
    header = build_www_authenticate(settings_with_slash, "invalid_token")
    assert "//.well-known" not in header


def test_www_authenticate_no_reason(settings):
    header = build_www_authenticate(settings)
    assert "error=" not in header


async def test_jwks_cache_reused(settings, signed_jwt):
    t1 = signed_jwt()
    await validate_bearer_token(t1, settings)
    t2 = signed_jwt({"sub": "another-user"})
    await validate_bearer_token(t2, settings)


def test_jwks_cache_reset_helper():
    auth_module._cache.keys_by_kid = {"some-kid": object()}
    auth_module._cache.fetched_at = 123.0
    auth_module._cache.last_refresh_attempt = 99.0
    auth_module._cache.negative_cache["leftover"] = 0.0
    auth_module._jwks_refresh_lock = object()  # type: ignore[assignment]
    auth_module.reset_cache_for_tests()
    assert auth_module._cache.keys_by_kid == {}
    assert auth_module._cache.fetched_at == 0.0
    assert auth_module._cache.last_refresh_attempt == 0.0
    assert auth_module._cache.negative_cache == {}
    assert auth_module._jwks_refresh_lock is None


# ---- regression net: JWKS throttle + negative cache ----------


async def test_jwks_throttle_collapses_concurrent_unknown_kid_attempts(
    settings, signed_jwt, rsa_keypair, mock_jwks
):
    """Critical regression: 5 concurrent malformed-JWT requests with the
    same unknown kid produce <=1 JWKS HTTP call within the throttle window.

    The previous behavior would have triggered up to 5 HTTP fetches as each
    request tried to refresh on a kid miss. With the 30s throttle + lock,
    the second-through-fifth requests find last_refresh_attempt fresh
    enough that they skip the refresh and fall through to the negative
    cache. The mock_jwks fixture's respx router records every call.
    """
    import asyncio

    import jwt as pyjwt

    auth_module.reset_cache_for_tests()

    # Build a JWT with a kid that the JWKS document does not contain.
    now = int(__import__("time").time())
    bad_token = pyjwt.encode(
        {
            "iss": "https://issuer.test.local",
            "sub": "x",
            "aud": "https://mcp-gmail.test.local",
            "iat": now,
            "exp": now + 60,
        },
        rsa_keypair["private_pem"],
        algorithm="RS256",
        headers={"kid": "totally-unknown-kid", "alg": "RS256"},
    )

    async def _attempt():
        try:
            await auth_module.validate_bearer_token(bad_token, settings)
        except auth_module.AuthError:
            pass

    # Snapshot call count, fire 5 concurrent attempts, check we did not
    # blow past one fetch.
    pre = mock_jwks.calls.call_count
    await asyncio.gather(*[_attempt() for _ in range(5)])
    post = mock_jwks.calls.call_count
    # The first attempt drives one cold-cache refresh; the second-fifth
    # find the cache populated and the kid in the negative cache, so no
    # additional refreshes fire. Allow a tolerance of <=2 to absorb the
    # race where two concurrent first-attempts both end up inside the
    # cold-cache branch before either has set last_refresh_attempt.
    assert (post - pre) <= 2


async def test_jwks_negative_cache_short_circuits_known_unknown_kid(
    settings, signed_jwt, rsa_keypair, mock_jwks
):
    """Once a kid lands in the negative cache, subsequent requests for the
    same kid never call the JWKS endpoint (until TTL expiry)."""
    import jwt as pyjwt

    auth_module.reset_cache_for_tests()
    now = int(__import__("time").time())
    bad_token = pyjwt.encode(
        {
            "iss": "https://issuer.test.local",
            "sub": "x",
            "aud": "https://mcp-gmail.test.local",
            "iat": now,
            "exp": now + 60,
        },
        rsa_keypair["private_pem"],
        algorithm="RS256",
        headers={"kid": "negcache-kid", "alg": "RS256"},
    )

    # First call populates the negative cache.
    with pytest.raises(auth_module.AuthError):
        await auth_module.validate_bearer_token(bad_token, settings)
    pre = mock_jwks.calls.call_count

    # Second call for the same kid must short-circuit without JWKS call.
    with pytest.raises(auth_module.AuthError):
        await auth_module.validate_bearer_token(bad_token, settings)
    post = mock_jwks.calls.call_count
    assert post == pre  # no additional fetch
