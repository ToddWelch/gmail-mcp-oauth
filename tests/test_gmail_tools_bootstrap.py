"""Tests for the connect_gmail_account bootstrap tool.

Targets: mcp-gmail/src/mcp_gmail/gmail_tools/bootstrap.py
Targets: mcp-gmail/src/mcp_gmail/gmail_tools/dispatch.py (bootstrap branch)
Targets: mcp-gmail/src/mcp_gmail/gmail_tools/tool_definitions_bootstrap.py

The bootstrap tool is the ONE tool that runs before a token row exists.
Test coverage:
- Manifest entry shape (name, schema, required field)
- Dispatcher short-circuits the token-bound flow for this tool name
- create_nonce is NOT called when account_email is malformed (regression
  guard for the bootstrap-tool revision)
- audit() emits without authorization_url, state, or nonce
- Email is normalized to lowercase before nonce creation
- The returned authorization_url is a valid Google consent URL shape
"""

from __future__ import annotations

import logging
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mcp_gmail import config as config_module
from mcp_gmail import db as db_module
from mcp_gmail.db import Base
from mcp_gmail.gmail_tools import TOOL_DEFINITIONS
from mcp_gmail.gmail_tools.bootstrap import (
    handle_connect_gmail_account,
    is_bootstrap_tool,
)
from mcp_gmail.gmail_tools.dispatch import dispatch_tool_call
from mcp_gmail.gmail_tools.errors import ToolErrorCode


@pytest.fixture(autouse=True)
def init_engine_for_bootstrap():
    """Bootstrap the module-level engine + factory used by session_scope."""
    db_module.reset_for_tests()
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(engine)
    db_module._engine = engine  # type: ignore[attr-defined]
    db_module._SessionFactory = sessionmaker(  # type: ignore[attr-defined]
        bind=engine, autoflush=False, expire_on_commit=False
    )
    yield
    db_module.reset_for_tests()


# ---------------------------------------------------------------------------
# Manifest + registry
# ---------------------------------------------------------------------------


def test_connect_gmail_account_in_tool_definitions():
    """The bootstrap tool ships in the public TOOL_DEFINITIONS list."""
    names = [t["name"] for t in TOOL_DEFINITIONS]
    assert "connect_gmail_account" in names


def test_total_tool_count_is_thirty_two():
    """The fanout helpers bump the tool surface to 32 (30 + 2)."""
    assert len(TOOL_DEFINITIONS) == 32


def test_connect_gmail_account_schema_requires_account_email():
    """The JSON Schema requires account_email and disallows extras."""
    entry = next(t for t in TOOL_DEFINITIONS if t["name"] == "connect_gmail_account")
    schema = entry["inputSchema"]
    assert schema["type"] == "object"
    assert "account_email" in schema["properties"]
    assert schema["required"] == ["account_email"]
    assert schema["additionalProperties"] is False


def test_is_bootstrap_tool_recognizes_connect_gmail_account():
    """The bootstrap-tool registry returns True only for the exact name."""
    assert is_bootstrap_tool("connect_gmail_account") is True
    assert is_bootstrap_tool("send_email") is False
    assert is_bootstrap_tool("read_email") is False
    assert is_bootstrap_tool("") is False


# ---------------------------------------------------------------------------
# Handler: happy path + email-shape validation (regression guard)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connect_returns_authorization_url():
    """Happy path: the handler returns an authorization_url shaped like
    Google's consent endpoint with state, scopes, and login_hint set."""
    settings = config_module.load()
    result = await handle_connect_gmail_account(
        auth0_sub="user-abc",
        arguments={"account_email": "linkme@example.com"},
        settings=settings,
    )
    assert "authorization_url" in result
    parsed = urlparse(result["authorization_url"])
    assert parsed.scheme == "https"
    assert "google.com" in parsed.netloc or "googleapis.com" in parsed.netloc
    qs = parse_qs(parsed.query)
    assert "state" in qs
    assert "scope" in qs
    assert qs.get("login_hint") == ["linkme@example.com"]


@pytest.mark.asyncio
async def test_connect_rejects_email_without_at_symbol():
    """Regression guard for the bootstrap-revision item 1.

    A malformed email (no '@') must return bad_request_error AND
    create_nonce must NOT be called. This is a hard contract:
    previously the handler delegated to state_store.create_nonce
    which would happily write a nonce row before any email validation,
    creating an unbounded write surface."""
    from mcp_gmail.gmail_tools import bootstrap as bootstrap_mod

    settings = config_module.load()
    with patch.object(bootstrap_mod, "create_nonce", wraps=bootstrap_mod.create_nonce) as spy:
        result = await handle_connect_gmail_account(
            auth0_sub="user-abc",
            arguments={"account_email": "not-an-email"},
            settings=settings,
        )
    assert result["code"] == ToolErrorCode.BAD_REQUEST
    assert "email" in result["message"].lower()
    assert spy.call_count == 0, "create_nonce must NOT be called when account_email lacks '@'"


@pytest.mark.asyncio
async def test_connect_rejects_empty_email():
    """Empty account_email returns bad_request without minting a nonce."""
    from mcp_gmail.gmail_tools import bootstrap as bootstrap_mod

    settings = config_module.load()
    with patch.object(bootstrap_mod, "create_nonce", wraps=bootstrap_mod.create_nonce) as spy:
        result = await handle_connect_gmail_account(
            auth0_sub="user-abc",
            arguments={"account_email": ""},
            settings=settings,
        )
    assert result["code"] == ToolErrorCode.BAD_REQUEST
    assert spy.call_count == 0


@pytest.mark.asyncio
async def test_connect_rejects_email_too_long():
    """Email longer than 320 chars returns bad_request (RFC 5321 cap)."""
    settings = config_module.load()
    long_local = "a" * 320
    result = await handle_connect_gmail_account(
        auth0_sub="user-abc",
        arguments={"account_email": f"{long_local}@example.com"},
        settings=settings,
    )
    assert result["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_connect_lowercases_and_strips_email():
    """Emails are normalized: stripped + lowercased before login_hint."""
    settings = config_module.load()
    result = await handle_connect_gmail_account(
        auth0_sub="user-abc",
        arguments={"account_email": "  Mixed.Case@Example.COM  "},
        settings=settings,
    )
    assert "authorization_url" in result
    parsed = urlparse(result["authorization_url"])
    qs = parse_qs(parsed.query)
    assert qs.get("login_hint") == ["mixed.case@example.com"]


# ---------------------------------------------------------------------------
# Dispatcher: short-circuit + audit hygiene
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatcher_short_circuits_bootstrap_no_token_lookup():
    """The dispatcher does NOT call get_token / get_access_token for the
    bootstrap tool. With no token row seeded, a token-bound tool would
    return needs_reauth; the bootstrap tool returns success."""
    settings = config_module.load()
    result = await dispatch_tool_call(
        tool_name="connect_gmail_account",
        arguments={"account_email": "linkme@example.com"},
        claims={"sub": "user-abc"},
        settings=settings,
    )
    assert "authorization_url" in result
    # Confirm the success path: no error code on the result dict.
    assert result.get("code") is None


@pytest.mark.asyncio
async def test_dispatcher_bootstrap_audit_does_not_log_url_or_state(caplog):
    """Audit-log discipline (audit-allowlist spirit, bootstrap-tool constraint).

    The dispatcher's audit() call for the bootstrap tool MUST NOT emit
    authorization_url, state, or nonce. The keyword-only signature of
    audit() makes this structurally true (no such kwargs exist), but
    we assert on the log content as a regression guard so a future
    refactor that changes audit's signature gets caught here too."""
    settings = config_module.load()
    with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
        await dispatch_tool_call(
            tool_name="connect_gmail_account",
            arguments={"account_email": "linkme@example.com"},
            claims={"sub": "user-abc"},
            settings=settings,
        )
    audit_records = [r for r in caplog.records if r.name == "mcp_gmail.gmail_tools.audit_log"]
    assert audit_records, "expected at least one audit record"
    full_log = " ".join(r.getMessage() for r in audit_records)
    assert "tool=connect_gmail_account" in full_log
    assert "https://accounts.google.com" not in full_log
    assert "state=" not in full_log
    assert "nonce=" not in full_log
    assert "authorization_url" not in full_log


@pytest.mark.asyncio
async def test_dispatcher_rejects_missing_sub_for_bootstrap():
    """No auth0_sub claim -> needs_reauth, even for the bootstrap tool.
    Defense in depth: a future test path that bypasses auth must not
    mint nonce rows under a null auth0_sub."""
    settings = config_module.load()
    result = await dispatch_tool_call(
        tool_name="connect_gmail_account",
        arguments={"account_email": "linkme@example.com"},
        claims={},
        settings=settings,
    )
    assert result["code"] == ToolErrorCode.NEEDS_REAUTH


@pytest.mark.asyncio
async def test_dispatcher_bootstrap_email_validation_audit_outcome_error(caplog):
    """Regression guard: when bootstrap returns bad_request, the
    dispatcher's audit emits outcome=error with error_code=BAD_REQUEST."""
    settings = config_module.load()
    with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
        result = await dispatch_tool_call(
            tool_name="connect_gmail_account",
            arguments={"account_email": "no-at-sign"},
            claims={"sub": "user-abc"},
            settings=settings,
        )
    assert result["code"] == ToolErrorCode.BAD_REQUEST
    audit_records = [r for r in caplog.records if r.name == "mcp_gmail.gmail_tools.audit_log"]
    full_log = " ".join(r.getMessage() for r in audit_records)
    assert "outcome=error" in full_log
    assert f"error_code={ToolErrorCode.BAD_REQUEST}" in full_log
