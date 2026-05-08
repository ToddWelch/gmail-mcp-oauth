"""Tests for gmail_tools.dispatch.dispatch_tool_call.

Covers cross-user isolation and session boundaries.
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import patch

import httpx
import pytest
import respx

from mcp_gmail import config as config_module
from mcp_gmail import db as db_module
from mcp_gmail import token_manager
from mcp_gmail.crypto import encrypt
from mcp_gmail.db import Base
from mcp_gmail.gmail_tools.dispatch import dispatch_tool_call
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE
from mcp_gmail.token_store import GmailOAuthToken


READONLY = "https://www.googleapis.com/auth/gmail.readonly"
MODIFY = "https://www.googleapis.com/auth/gmail.modify"


@pytest.fixture(autouse=True)
def init_engine_for_dispatch():
    """Bootstrap the module-level engine + factory used by session_scope."""
    db_module.reset_for_tests()
    token_manager.reset_cache_for_tests()
    engine = db_module.init_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield
    db_module.reset_for_tests()
    token_manager.reset_cache_for_tests()


def _seed_token(
    *,
    auth0_sub: str,
    account_email: str,
    scope: str,
    revoked: bool = False,
):
    """Insert a token row and return the encryption key used."""
    settings = config_module.load()
    enc_token = encrypt("fake-refresh-token", settings.encryption_key)
    now = datetime.now(timezone.utc)
    with db_module.session_scope() as session:
        row = GmailOAuthToken(
            auth0_sub=auth0_sub,
            account_email=account_email.lower(),
            encrypted_refresh_token=enc_token,
            scope=scope,
            created_at=now,
            updated_at=now,
            revoked_at=now if revoked else None,
        )
        session.add(row)
    return settings


def _stub_token_manager_with(access_token: str):
    """Patch get_access_token at the dispatcher's import site."""

    async def fake(**_kwargs):
        return access_token

    from mcp_gmail.gmail_tools import dispatch as dispatch_mod

    return patch.object(dispatch_mod, "get_access_token", side_effect=fake)


def _stub_token_manager_raises(exc: Exception):
    async def fake(**_kwargs):
        raise exc

    from mcp_gmail.gmail_tools import dispatch as dispatch_mod

    return patch.object(dispatch_mod, "get_access_token", side_effect=fake)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dispatch_returns_needs_reauth_when_no_token_row():
    settings = config_module.load()
    result = await dispatch_tool_call(
        tool_name="read_email",
        arguments={"account_email": "noone@example.com", "message_id": "M1"},
        claims={"sub": "user-a"},
        settings=settings,
    )
    assert result["code"] == ToolErrorCode.NEEDS_REAUTH


@pytest.mark.asyncio
async def test_dispatch_returns_needs_reauth_when_row_revoked():
    _seed_token(
        auth0_sub="user-a",
        account_email="x@example.com",
        scope=READONLY,
        revoked=True,
    )
    settings = config_module.load()
    result = await dispatch_tool_call(
        tool_name="read_email",
        arguments={"account_email": "x@example.com", "message_id": "M1"},
        claims={"sub": "user-a"},
        settings=settings,
    )
    assert result["code"] == ToolErrorCode.NEEDS_REAUTH


@pytest.mark.asyncio
async def test_dispatch_scope_check_fires_BEFORE_gmail_call():
    """scope-check + session-boundary: scope_insufficient surfaces with no Gmail HTTP call."""
    settings = _seed_token(
        auth0_sub="user-a",
        account_email="x@example.com",
        scope=READONLY,
    )
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        # Any Gmail call would route through this mock; we assert it
        # was never called.
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        result = await dispatch_tool_call(
            tool_name="modify_thread",  # requires gmail.modify
            arguments={"account_email": "x@example.com", "thread_id": "t1"},
            claims={"sub": "user-a"},
            settings=settings,
        )
        assert any_route.called is False, "Gmail API was called despite scope_insufficient"

    assert result["code"] == ToolErrorCode.SCOPE_INSUFFICIENT
    error_data = result["data"]["error_data"]
    assert MODIFY in error_data["required_scopes"]
    assert error_data["granted_scope"] == READONLY
    assert "reconnect_hint" in error_data


@pytest.mark.asyncio
async def test_dispatch_returns_needs_reauth_on_token_unavailable():
    settings = _seed_token(
        auth0_sub="user-a",
        account_email="x@example.com",
        scope=READONLY,
    )
    err = token_manager.TokenUnavailableError("revoked at Google")
    with _stub_token_manager_raises(err):
        result = await dispatch_tool_call(
            tool_name="read_email",
            arguments={"account_email": "x@example.com", "message_id": "M1"},
            claims={"sub": "user-a"},
            settings=settings,
        )
    assert result["code"] == ToolErrorCode.NEEDS_REAUTH


@pytest.mark.asyncio
async def test_dispatch_happy_path_returns_gmail_response():
    settings = _seed_token(
        auth0_sub="user-a",
        account_email="x@example.com",
        scope=READONLY,
    )
    with _stub_token_manager_with("access-tok"):
        with respx.mock(base_url=GMAIL_API_BASE) as router:
            router.get("/users/me/messages/M1").mock(
                return_value=httpx.Response(200, json={"id": "M1", "snippet": "hi"})
            )
            result = await dispatch_tool_call(
                tool_name="read_email",
                arguments={"account_email": "x@example.com", "message_id": "M1"},
                claims={"sub": "user-a"},
                settings=settings,
            )
    assert result == {"id": "M1", "snippet": "hi"}


@pytest.mark.asyncio
async def test_dispatch_marks_used_on_success():
    settings = _seed_token(
        auth0_sub="user-a",
        account_email="x@example.com",
        scope=READONLY,
    )
    with _stub_token_manager_with("access-tok"):
        with respx.mock(base_url=GMAIL_API_BASE) as router:
            router.get("/users/me/labels").mock(
                return_value=httpx.Response(200, json={"labels": []})
            )
            await dispatch_tool_call(
                tool_name="list_email_labels",
                arguments={"account_email": "x@example.com"},
                claims={"sub": "user-a"},
                settings=settings,
            )
    # last_used_at should be populated now.
    with db_module.session_scope() as session:
        row = (
            session.query(GmailOAuthToken)
            .filter_by(auth0_sub="user-a", account_email="x@example.com")
            .one()
        )
        assert row.last_used_at is not None


@pytest.mark.asyncio
async def test_dispatch_cross_user_isolation_m5():
    """Cross-user isolation: user-b cannot reach user-a's account_email row.

    Token rows are looked up by (auth0_sub, account_email). A request
    with user-b's claims and user-a's account_email returns no row, so
    the dispatcher surfaces needs_reauth. Property is enforced
    structurally; this is a regression test.
    """
    settings = _seed_token(
        auth0_sub="user-a",
        account_email="x@example.com",
        scope=READONLY,
    )
    result = await dispatch_tool_call(
        tool_name="read_email",
        arguments={"account_email": "x@example.com", "message_id": "M1"},
        claims={"sub": "user-b"},  # different user
        settings=settings,
    )
    assert result["code"] == ToolErrorCode.NEEDS_REAUTH


@pytest.mark.asyncio
async def test_dispatch_rejects_missing_account_email():
    settings = config_module.load()
    result = await dispatch_tool_call(
        tool_name="read_email",
        arguments={"message_id": "M1"},
        claims={"sub": "user-a"},
        settings=settings,
    )
    assert result["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_dispatch_rejects_missing_sub_claim():
    settings = config_module.load()
    result = await dispatch_tool_call(
        tool_name="read_email",
        arguments={"account_email": "x@example.com", "message_id": "M1"},
        claims={},
        settings=settings,
    )
    assert result["code"] == ToolErrorCode.NEEDS_REAUTH


@pytest.mark.asyncio
async def test_dispatch_returns_not_found_on_404_from_gmail():
    settings = _seed_token(
        auth0_sub="user-a",
        account_email="x@example.com",
        scope=READONLY,
    )
    with _stub_token_manager_with("access-tok"):
        with respx.mock(base_url=GMAIL_API_BASE) as router:
            router.get("/users/me/messages/missing").mock(
                return_value=httpx.Response(404, json={"error": "not found"})
            )
            result = await dispatch_tool_call(
                tool_name="read_email",
                arguments={"account_email": "x@example.com", "message_id": "missing"},
                claims={"sub": "user-a"},
                settings=settings,
            )
    assert result["code"] == ToolErrorCode.NOT_FOUND


@pytest.mark.asyncio
async def test_dispatch_returns_rate_limited_on_429():
    settings = _seed_token(
        auth0_sub="user-a",
        account_email="x@example.com",
        scope=READONLY,
    )
    with _stub_token_manager_with("access-tok"):
        with respx.mock(base_url=GMAIL_API_BASE) as router:
            router.get("/users/me/messages").mock(
                return_value=httpx.Response(429, json={}, headers={"Retry-After": "5"})
            )
            result = await dispatch_tool_call(
                tool_name="search_emails",
                arguments={"account_email": "x@example.com"},
                claims={"sub": "user-a"},
                settings=settings,
            )
    assert result["code"] == ToolErrorCode.RATE_LIMITED
    assert result["data"]["error_data"]["retry_after_seconds"] == 5


@pytest.mark.asyncio
async def test_dispatch_returns_upstream_error_on_500():
    settings = _seed_token(
        auth0_sub="user-a",
        account_email="x@example.com",
        scope=READONLY,
    )
    with _stub_token_manager_with("access-tok"):
        with respx.mock(base_url=GMAIL_API_BASE) as router:
            router.get("/users/me/labels").mock(return_value=httpx.Response(500, text="boom"))
            result = await dispatch_tool_call(
                tool_name="list_email_labels",
                arguments={"account_email": "x@example.com"},
                claims={"sub": "user-a"},
                settings=settings,
            )
    assert result["code"] == ToolErrorCode.UPSTREAM_ERROR


@pytest.mark.asyncio
async def test_dispatch_send_email_happy_path_with_send_scope():
    """send_email dispatch end-to-end with gmail.send scope."""
    SEND = "https://www.googleapis.com/auth/gmail.send"
    settings = _seed_token(
        auth0_sub="user-a",
        account_email="x@example.com",
        scope=SEND,
    )
    with _stub_token_manager_with("access-tok"):
        with respx.mock(base_url=GMAIL_API_BASE) as router:
            router.post("/users/me/messages/send").mock(
                return_value=httpx.Response(200, json={"id": "sent-1", "threadId": "t1"})
            )
            result = await dispatch_tool_call(
                tool_name="send_email",
                arguments={
                    "account_email": "x@example.com",
                    "sender": "x@example.com",
                    "to": ["y@example.com"],
                    "subject": "hi",
                    "body_text": "body",
                },
                claims={"sub": "user-a"},
                settings=settings,
            )
    assert result == {"id": "sent-1", "threadId": "t1"}


@pytest.mark.asyncio
async def test_dispatch_send_email_scope_insufficient_with_readonly():
    """send_email surfaces scope_insufficient when only readonly is granted."""
    SEND = "https://www.googleapis.com/auth/gmail.send"
    settings = _seed_token(
        auth0_sub="user-a",
        account_email="x@example.com",
        scope=READONLY,
    )
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        result = await dispatch_tool_call(
            tool_name="send_email",
            arguments={
                "account_email": "x@example.com",
                "sender": "x@example.com",
                "to": ["y@example.com"],
                "subject": "s",
                "body_text": "b",
            },
            claims={"sub": "user-a"},
            settings=settings,
        )
        assert any_route.called is False
    assert result["code"] == ToolErrorCode.SCOPE_INSUFFICIENT
    assert SEND in result["data"]["error_data"]["required_scopes"]


@pytest.mark.asyncio
async def test_dispatch_account_email_lowercased():
    """Email is normalized to lowercase to match the DB CHECK."""
    _seed_token(
        auth0_sub="user-a",
        account_email="x@example.com",
        scope=READONLY,
    )
    settings = config_module.load()
    with _stub_token_manager_with("access-tok"):
        with respx.mock(base_url=GMAIL_API_BASE) as router:
            router.get("/users/me/labels").mock(
                return_value=httpx.Response(200, json={"labels": []})
            )
            result = await dispatch_tool_call(
                tool_name="list_email_labels",
                arguments={"account_email": "X@Example.COM"},
                claims={"sub": "user-a"},
                settings=settings,
            )
    assert result == {"labels": []}


@pytest.mark.asyncio
async def test_reply_all_audit_records_message_id(caplog):
    """reply_all input field is `message_id`, so the
    dispatcher's audit harvest at `_str_or_none("message_id")` records
    the source-message ID. Renaming to `original_message_id` would
    silently drop the audit binding and is forbidden.

    The Gmail-ID shape is enforced by audit_log.audit() (16-128 chars in
    the URL-safe base64 alphabet); a malformed ID promotes the audit
    line to WARN level. This test passes a valid-shape ID so the line
    lands at INFO and the message_id pair appears verbatim.
    """
    import logging

    SEND = "https://www.googleapis.com/auth/gmail.send"
    settings = _seed_token(
        auth0_sub="user-a",
        account_email="x@example.com",
        scope=f"{SEND} {READONLY}",
    )
    valid_msg_id = "abc123def456ghi7"  # 16 chars, valid Gmail ID shape
    with _stub_token_manager_with("access-tok"):
        with respx.mock(base_url=GMAIL_API_BASE) as router:
            router.get(f"/users/me/messages/{valid_msg_id}").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "id": valid_msg_id,
                        "threadId": "T",
                        "payload": {
                            "headers": [
                                {"name": "From", "value": "alice@example.com"},
                                {"name": "To", "value": "x@example.com"},
                                {"name": "Subject", "value": "Hi"},
                                {"name": "Message-ID", "value": "<M1@example.com>"},
                            ]
                        },
                    },
                )
            )
            router.get("/users/me/profile").mock(
                return_value=httpx.Response(200, json={"emailAddress": "x@example.com"})
            )
            router.post("/users/me/messages/send").mock(
                return_value=httpx.Response(200, json={"id": "sent-1", "threadId": "T"})
            )
            with caplog.at_level(logging.INFO, logger="mcp_gmail.gmail_tools.audit_log"):
                result = await dispatch_tool_call(
                    tool_name="reply_all",
                    arguments={
                        "account_email": "x@example.com",
                        "message_id": valid_msg_id,
                        "body_text": "thanks",
                    },
                    claims={"sub": "user-a"},
                    settings=settings,
                )

    assert result == {"id": "sent-1", "threadId": "T"}
    # The audit() call in dispatch.py is the ONE that runs after the
    # tool returns. Find that record (filter to the audit logger) and
    # confirm it carries the source message_id.
    audit_records = [r for r in caplog.records if r.name == "mcp_gmail.gmail_tools.audit_log"]
    assert audit_records, "expected at least one audit record"
    final_audit = audit_records[-1].getMessage()
    assert "tool=reply_all" in final_audit
    assert f"message_id={valid_msg_id}" in final_audit, (
        f"audit record should bind reply_all's source message_id; got: {final_audit}"
    )
