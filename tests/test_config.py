"""Config loading.

Targets: mcp-gmail/src/mcp_gmail/config.py:load
Targets: mcp-gmail/src/mcp_gmail/config.py:Settings.authorization_servers
"""

from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from mcp_gmail import config as config_module


def test_load_happy_path(settings):
    assert settings.oauth_issuer_url == "https://issuer.test.local"
    assert settings.mcp_resource_url == "https://mcp-gmail.test.local"
    assert settings.jwks_cache_ttl_seconds == 300
    assert settings.mcp_accept_client_id_aud is False
    assert settings.mcp_expected_scopes == ()
    assert settings.authorization_servers == ("https://issuer.test.local",)
    assert settings.encryption_key
    assert settings.state_signing_key
    # Two-key model: must be different.
    assert settings.encryption_key != settings.state_signing_key


def test_load_missing_required_raises(monkeypatch):
    monkeypatch.delenv("OAUTH_ISSUER_URL", raising=False)
    with pytest.raises(RuntimeError, match="OAUTH_ISSUER_URL"):
        config_module.load()


def test_load_missing_database_url_raises(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        config_module.load()


def test_load_missing_encryption_key_raises(monkeypatch):
    monkeypatch.delenv("ENCRYPTION_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ENCRYPTION_KEY"):
        config_module.load()


def test_load_missing_state_signing_key_raises(monkeypatch):
    monkeypatch.delenv("STATE_SIGNING_KEY", raising=False)
    with pytest.raises(RuntimeError, match="STATE_SIGNING_KEY"):
        config_module.load()


def test_load_rejects_identical_keys(monkeypatch):
    """ENCRYPTION_KEY and STATE_SIGNING_KEY must be different values.

    A defense-in-depth check at the config layer. Cross-contaminating
    the two trust domains (token-at-rest encryption and OAuth state
    signing) widens the blast radius of either key being leaked.
    """
    same = Fernet.generate_key().decode("ascii")
    monkeypatch.setenv("ENCRYPTION_KEY", same)
    monkeypatch.setenv("STATE_SIGNING_KEY", same)
    with pytest.raises(RuntimeError, match="must be different"):
        config_module.load()


def test_bad_integer_raises(monkeypatch):
    monkeypatch.setenv("JWKS_CACHE_TTL_SECONDS", "not-a-number")
    with pytest.raises(RuntimeError, match="JWKS_CACHE_TTL_SECONDS"):
        config_module.load()


def test_expected_scopes_split(monkeypatch):
    monkeypatch.setenv("MCP_EXPECTED_SCOPES", "read  write    gmail.send")
    settings = config_module.load()
    assert settings.mcp_expected_scopes == ("read", "write", "gmail.send")


def test_accept_client_id_aud_false(monkeypatch):
    monkeypatch.setenv("MCP_ACCEPT_CLIENT_ID_AUD", "false")
    settings = config_module.load()
    assert settings.mcp_accept_client_id_aud is False


def test_accept_client_id_aud_yes(monkeypatch):
    """tolerance flag toggles, but the allowlist
    must also be supplied or load() refuses to start."""
    monkeypatch.setenv("MCP_ACCEPT_CLIENT_ID_AUD", "yes")
    monkeypatch.setenv("MCP_ACCEPTED_CLIENT_IDS", "client-id-1, client-id-2")
    settings = config_module.load()
    assert settings.mcp_accept_client_id_aud is True
    assert settings.mcp_accepted_client_ids == ("client-id-1", "client-id-2")


def test_accept_client_id_aud_true_without_allowlist_raises(monkeypatch):
    """MCP_ACCEPT_CLIENT_ID_AUD=true + empty
    MCP_ACCEPTED_CLIENT_IDS must fail at config load. Misconfiguration
    surfaces at boot, not at the first /mcp call."""
    monkeypatch.setenv("MCP_ACCEPT_CLIENT_ID_AUD", "true")
    monkeypatch.delenv("MCP_ACCEPTED_CLIENT_IDS", raising=False)
    with pytest.raises(RuntimeError, match="MCP_ACCEPTED_CLIENT_IDS"):
        config_module.load()


def test_accepted_client_ids_default_empty_when_tolerance_off(monkeypatch):
    """Default state: tolerance off, allowlist empty. No error."""
    monkeypatch.setenv("MCP_ACCEPT_CLIENT_ID_AUD", "false")
    monkeypatch.delenv("MCP_ACCEPTED_CLIENT_IDS", raising=False)
    settings = config_module.load()
    assert settings.mcp_accept_client_id_aud is False
    assert settings.mcp_accepted_client_ids == ()


def test_accepted_client_ids_strips_whitespace(monkeypatch):
    """Comma-separated list tolerates whitespace around entries."""
    monkeypatch.setenv("MCP_ACCEPT_CLIENT_ID_AUD", "true")
    monkeypatch.setenv("MCP_ACCEPTED_CLIENT_IDS", "  a , b ,  c   ")
    settings = config_module.load()
    assert settings.mcp_accepted_client_ids == ("a", "b", "c")


def test_accepted_client_ids_drops_empty_entries(monkeypatch):
    """Trailing or doubled commas should not produce empty allowlist entries."""
    monkeypatch.setenv("MCP_ACCEPT_CLIENT_ID_AUD", "true")
    monkeypatch.setenv("MCP_ACCEPTED_CLIENT_IDS", "a,,b,")
    settings = config_module.load()
    assert settings.mcp_accepted_client_ids == ("a", "b")


def test_accepted_client_ids_only_whitespace_treated_as_empty(monkeypatch):
    """A whitespace-only allowlist value is treated as empty and triggers
    the misconfiguration error when tolerance is on."""
    monkeypatch.setenv("MCP_ACCEPT_CLIENT_ID_AUD", "true")
    monkeypatch.setenv("MCP_ACCEPTED_CLIENT_IDS", "   ,  , ")
    with pytest.raises(RuntimeError, match="MCP_ACCEPTED_CLIENT_IDS"):
        config_module.load()


def test_load_preserves_resource_and_issuer_trailing_slash(monkeypatch):
    """MCP_RESOURCE_URL and OAUTH_ISSUER_URL must be preserved exactly as configured."""
    monkeypatch.setenv("OAUTH_ISSUER_URL", "https://issuer.test.local/")
    monkeypatch.setenv("MCP_RESOURCE_URL", "https://mcp-gmail.test.local/")
    settings = config_module.load()
    assert settings.oauth_issuer_url == "https://issuer.test.local/"
    assert settings.mcp_resource_url == "https://mcp-gmail.test.local/"


# -- Fernet shape validation ------------------------------------------------


def test_load_rejects_misshapen_encryption_key(monkeypatch):
    monkeypatch.setenv("ENCRYPTION_KEY", "not-32-bytes-after-base64-decode")
    with pytest.raises(RuntimeError, match="ENCRYPTION_KEY"):
        config_module.load()


def test_load_rejects_misshapen_state_signing_key(monkeypatch):
    """STATE_SIGNING_KEY also requires the Fernet shape (uniform operator UX).

    Even though HMAC-SHA256 accepts arbitrary byte strings, we constrain
    the shape so operators run one generator command, paste two
    distinct outputs, and never wonder which key format is expected
    where.
    """
    monkeypatch.setenv("STATE_SIGNING_KEY", "abcdef")
    with pytest.raises(RuntimeError, match="STATE_SIGNING_KEY"):
        config_module.load()


def test_load_rejects_non_base64_encryption_key(monkeypatch):
    """Non-base64 garbage in ENCRYPTION_KEY surfaces a load-time error."""
    monkeypatch.setenv("ENCRYPTION_KEY", "@@@not-base64@@@!!!")
    with pytest.raises(RuntimeError, match="ENCRYPTION_KEY"):
        config_module.load()


# -- Google OAuth fields ----------------------------------------------------


def test_load_google_oauth_fields_happy_path(settings):
    assert settings.google_oauth_client_id.endswith(".googleusercontent.com")
    assert settings.google_oauth_client_secret == "test-client-secret"
    assert settings.google_oauth_redirect_url.endswith("/oauth2callback")
    assert "openid" in settings.gmail_oauth_scopes
    assert "https://www.googleapis.com/auth/gmail.readonly" in settings.gmail_oauth_scopes


def test_load_missing_google_client_id_raises(monkeypatch):
    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_ID", raising=False)
    with pytest.raises(RuntimeError, match="GOOGLE_OAUTH_CLIENT_ID"):
        config_module.load()


def test_load_missing_google_client_secret_raises(monkeypatch):
    monkeypatch.delenv("GOOGLE_OAUTH_CLIENT_SECRET", raising=False)
    with pytest.raises(RuntimeError, match="GOOGLE_OAUTH_CLIENT_SECRET"):
        config_module.load()


def test_load_missing_google_redirect_url_raises(monkeypatch):
    monkeypatch.delenv("GOOGLE_OAUTH_REDIRECT_URL", raising=False)
    with pytest.raises(RuntimeError, match="GOOGLE_OAUTH_REDIRECT_URL"):
        config_module.load()


def test_load_gmail_scopes_default_when_unset(monkeypatch):
    monkeypatch.delenv("GMAIL_OAUTH_SCOPES", raising=False)
    settings = config_module.load()
    assert "openid" in settings.gmail_oauth_scopes
    assert "email" in settings.gmail_oauth_scopes


def test_load_gmail_scopes_empty_string_uses_default(monkeypatch):
    """Empty GMAIL_OAUTH_SCOPES falls back to the built-in default."""
    monkeypatch.setenv("GMAIL_OAUTH_SCOPES", "")
    settings = config_module.load()
    assert "openid" in settings.gmail_oauth_scopes


def test_load_gmail_scopes_whitespace_only_raises(monkeypatch):
    """Whitespace-only is treated as no scopes after the split; reject."""
    monkeypatch.setenv("GMAIL_OAUTH_SCOPES", "   ")
    with pytest.raises(RuntimeError, match="GMAIL_OAUTH_SCOPES"):
        config_module.load()


# ---- production scope requirement -----------------------------


def test_load_production_with_no_scopes_raises(monkeypatch):
    """In production, MCP_EXPECTED_SCOPES empty must fail-close at load."""
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    monkeypatch.setenv("MCP_EXPECTED_SCOPES", "")
    monkeypatch.delenv("MCP_REQUIRE_SCOPES_OVERRIDE", raising=False)
    with pytest.raises(RuntimeError, match="MCP_EXPECTED_SCOPES is empty in production"):
        config_module.load()


def test_load_production_override_unblocks(monkeypatch):
    """MCP_REQUIRE_SCOPES_OVERRIDE=false acknowledges the empty-scopes risk."""
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    monkeypatch.setenv("MCP_EXPECTED_SCOPES", "")
    monkeypatch.setenv("MCP_REQUIRE_SCOPES_OVERRIDE", "false")
    settings = config_module.load()
    assert settings.mcp_expected_scopes == ()


def test_load_production_with_scopes_ok(monkeypatch):
    """Non-empty MCP_EXPECTED_SCOPES in production is fine without override."""
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    monkeypatch.setenv("MCP_EXPECTED_SCOPES", "gmail.read gmail.send")
    monkeypatch.delenv("MCP_REQUIRE_SCOPES_OVERRIDE", raising=False)
    settings = config_module.load()
    assert "gmail.read" in settings.mcp_expected_scopes


def test_load_non_production_no_scope_check(monkeypatch):
    """Outside production, empty scopes is fine (existing behavior)."""
    monkeypatch.delenv("RAILWAY_ENVIRONMENT_NAME", raising=False)
    monkeypatch.setenv("MCP_EXPECTED_SCOPES", "")
    settings = config_module.load()
    assert settings.mcp_expected_scopes == ()


def test_settings_is_production_property(monkeypatch):
    """is_production reads RAILWAY_ENVIRONMENT_NAME with case-insensitive match."""
    # Need non-empty scopes (or override) to satisfy the Item 3
    # production check; the property under test is is_production
    # itself, not the scope guardrail.
    monkeypatch.setenv("MCP_EXPECTED_SCOPES", "gmail.read")
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "Production")
    settings = config_module.load()
    assert settings.is_production is True
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "staging")
    settings2 = config_module.load()
    assert settings2.is_production is False
