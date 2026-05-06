"""allowlist + allow_any settings.

Targets: mcp-gmail/src/mcp_gmail/config.py:load (allowlist parsing)
Targets: mcp-gmail/src/mcp_gmail/config.py:Settings.requires_confirm_page
Targets: mcp-gmail/src/mcp_gmail/config.py:Settings.is_auth0_sub_allowed
"""

from __future__ import annotations

import pytest

from mcp_gmail import config as config_module


# ---------------------------------------------------------------------------
# Allowlist parsing
# ---------------------------------------------------------------------------


def test_allowlist_parses_comma_separated(monkeypatch):
    monkeypatch.setenv("MCP_ALLOWED_AUTH0_SUBS", "auth0|a,auth0|b,auth0|c")
    settings = config_module.load()
    assert settings.allowed_auth0_subs == ("auth0|a", "auth0|b", "auth0|c")


def test_allowlist_strips_whitespace(monkeypatch):
    monkeypatch.setenv("MCP_ALLOWED_AUTH0_SUBS", "  auth0|a , auth0|b ,  auth0|c  ")
    settings = config_module.load()
    assert settings.allowed_auth0_subs == ("auth0|a", "auth0|b", "auth0|c")


def test_allowlist_drops_empty_entries(monkeypatch):
    monkeypatch.setenv("MCP_ALLOWED_AUTH0_SUBS", "auth0|a,,auth0|b,")
    settings = config_module.load()
    assert settings.allowed_auth0_subs == ("auth0|a", "auth0|b")


def test_allowlist_default_empty(monkeypatch):
    monkeypatch.delenv("MCP_ALLOWED_AUTH0_SUBS", raising=False)
    monkeypatch.delenv("RAILWAY_ENVIRONMENT_NAME", raising=False)
    settings = config_module.load()
    assert settings.allowed_auth0_subs == ()


# ---------------------------------------------------------------------------
# Production fail-closed guardrail
# ---------------------------------------------------------------------------


def test_load_production_with_empty_allowlist_fails_closed(monkeypatch):
    """In production, MCP_ALLOWED_AUTH0_SUBS empty must fail-close at load."""
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    monkeypatch.setenv("MCP_EXPECTED_SCOPES", "gmail.read")  # satisfy production scope-check
    monkeypatch.setenv("MCP_ALLOWED_AUTH0_SUBS", "")
    monkeypatch.setenv("MCP_ALLOW_ANY_AUTH0_SUB", "false")
    with pytest.raises(RuntimeError, match="MCP_ALLOWED_AUTH0_SUBS is empty in production"):
        config_module.load()


def test_load_production_with_allowlist_set_ok(monkeypatch):
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    monkeypatch.setenv("MCP_EXPECTED_SCOPES", "gmail.read")
    monkeypatch.setenv("MCP_ALLOWED_AUTH0_SUBS", "auth0|sample-user")
    monkeypatch.setenv("MCP_ALLOW_ANY_AUTH0_SUB", "false")
    settings = config_module.load()
    assert settings.allowed_auth0_subs == ("auth0|sample-user",)


def test_allowlist_empty_with_allow_any_in_production(monkeypatch):
    """production AND allowlist empty AND allow_any=true.

    Design decision: allow_any=true is the explicit emergency
    multi-user opt-in. When set in production, an empty allowlist
    is the intended state (the operator wants to bypass the
    allowlist entirely). Config load succeeds.

    Truth table for this combination:
      env=production, allowlist=[], allow_any=true => load OK,
      requires_confirm_page=true (allow_any forces it), and every
      bearer with a valid sub is allowed by `is_auth0_sub_allowed`.
    """
    monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
    monkeypatch.setenv("MCP_EXPECTED_SCOPES", "gmail.read")
    monkeypatch.setenv("MCP_ALLOWED_AUTH0_SUBS", "")
    monkeypatch.setenv("MCP_ALLOW_ANY_AUTH0_SUB", "true")
    settings = config_module.load()
    assert settings.allowed_auth0_subs == ()
    assert settings.allow_any_auth0_sub is True
    assert settings.requires_confirm_page is True
    assert settings.is_auth0_sub_allowed("auth0|anyone") is True


def test_load_non_production_empty_allowlist_ok(monkeypatch):
    """Outside production, empty allowlist is fine (development default)."""
    monkeypatch.delenv("RAILWAY_ENVIRONMENT_NAME", raising=False)
    monkeypatch.setenv("MCP_ALLOWED_AUTH0_SUBS", "")
    monkeypatch.setenv("MCP_ALLOW_ANY_AUTH0_SUB", "false")
    settings = config_module.load()
    assert settings.allowed_auth0_subs == ()


# ---------------------------------------------------------------------------
# is_auth0_sub_allowed
# ---------------------------------------------------------------------------


def test_is_auth0_sub_allowed_membership(monkeypatch):
    monkeypatch.setenv("MCP_ALLOWED_AUTH0_SUBS", "auth0|a,auth0|b")
    monkeypatch.setenv("MCP_ALLOW_ANY_AUTH0_SUB", "false")
    settings = config_module.load()
    assert settings.is_auth0_sub_allowed("auth0|a") is True
    assert settings.is_auth0_sub_allowed("auth0|b") is True
    assert settings.is_auth0_sub_allowed("auth0|c") is False


def test_is_auth0_sub_allowed_rejects_empty_under_allow_any(monkeypatch):
    """A None or empty sub is always rejected even under allow_any."""
    monkeypatch.setenv("MCP_ALLOWED_AUTH0_SUBS", "")
    monkeypatch.setenv("MCP_ALLOW_ANY_AUTH0_SUB", "true")
    settings = config_module.load()
    assert settings.is_auth0_sub_allowed("") is False
    assert settings.is_auth0_sub_allowed(None) is False
    # Non-empty passes when allow_any is set.
    assert settings.is_auth0_sub_allowed("auth0|anything") is True


# ---------------------------------------------------------------------------
# requires_confirm_page truth-table matrix
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "allowlist,allow_any,is_prod,expected",
    [
        # Truth table for `requires_confirm_page = allow_any OR len(allowlist) > 1`.
        # is_prod is captured because some combinations are blocked at load
        # (production + empty + allow_any=false fails; not exercised here).
        # length 0
        ("", False, False, False),  # dev-mode wide-open, no allowlist (load OK)
        ("", True, False, True),  # allow_any opt-in, dev
        ("", True, True, True),  # allow_any opt-in, prod
        # length 1
        ("auth0|a", False, False, False),  # single-user mode, dev
        ("auth0|a", False, True, False),  # single-user mode, prod (current default)
        ("auth0|a", True, False, True),  # allow_any forces True even with 1 sub
        # length 2
        ("auth0|a,auth0|b", False, False, True),  # multi-user mode triggers confirm
        ("auth0|a,auth0|b", True, False, True),  # both layers true
        ("auth0|a,auth0|b", False, True, True),  # multi-user prod
        # length 3
        ("auth0|a,auth0|b,auth0|c", False, False, True),
    ],
)
def test_requires_confirm_page_matrix(monkeypatch, allowlist, allow_any, is_prod, expected):
    """every relevant (allowlist length, allow_any, env) combo.

    Truth table:
      requires_confirm_page == True iff
        allow_any_auth0_sub OR len(allowed_auth0_subs) > 1.
      is_production has no direct effect on the boolean (it gates
      load-time validity but not the runtime property).
    """
    if is_prod:
        monkeypatch.setenv("RAILWAY_ENVIRONMENT_NAME", "production")
        monkeypatch.setenv("MCP_EXPECTED_SCOPES", "gmail.read")
    else:
        monkeypatch.delenv("RAILWAY_ENVIRONMENT_NAME", raising=False)
    monkeypatch.setenv("MCP_ALLOWED_AUTH0_SUBS", allowlist)
    monkeypatch.setenv("MCP_ALLOW_ANY_AUTH0_SUB", "true" if allow_any else "false")
    settings = config_module.load()
    assert settings.requires_confirm_page is expected
