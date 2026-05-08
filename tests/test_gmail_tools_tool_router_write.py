"""Smoke tests for tool_router.route_tool dispatching the 14 write tools.

Each branch in tool_router_write.py is exercised once via route_tool to
verify the dispatch table and argument-binding glue produce a Gmail
call (or a typed error for input-validation paths). The deeper per-
tool semantics are covered in the dedicated test files (test_gmail_tools_send.py,
test_gmail_tools_drafts.py, test_gmail_tools_messages_write.py,
test_gmail_tools_labels_write.py, test_gmail_tools_filters_write.py).
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient
from mcp_gmail.gmail_tools.tool_router import route_tool


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


# ---------------------------------------------------------------------------
# Dispatch coverage: one happy path per write tool
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_route_send_email(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/messages/send").mock(
            return_value=httpx.Response(200, json={"id": "x"})
        )
        r = await route_tool(
            tool_name="send_email",
            arguments={
                "sender": "me@x.com",
                "to": ["y@x.com"],
                "subject": "s",
                "body_text": "b",
            },
            client=client,
            auth0_sub="u",
            account_email="me@x.com",
        )
    assert r["id"] == "x"


@pytest.mark.asyncio
async def test_route_create_draft(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts").mock(return_value=httpx.Response(200, json={"id": "d1"}))
        r = await route_tool(
            tool_name="create_draft",
            arguments={
                "sender": "me@x.com",
                "to": ["y@x.com"],
                "subject": "s",
                "body_text": "b",
            },
            client=client,
        )
    assert r["id"] == "d1"


@pytest.mark.asyncio
async def test_route_update_draft(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.put("/users/me/drafts/d1").mock(return_value=httpx.Response(200, json={"id": "d1"}))
        r = await route_tool(
            tool_name="update_draft",
            arguments={
                "draft_id": "d1",
                "sender": "me@x.com",
                "to": ["y@x.com"],
                "subject": "s",
                "body_text": "b",
            },
            client=client,
        )
    assert r["id"] == "d1"


@pytest.mark.asyncio
async def test_route_list_drafts(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/drafts").mock(return_value=httpx.Response(200, json={"drafts": []}))
        r = await route_tool(tool_name="list_drafts", arguments={}, client=client)
    assert r == {"drafts": []}


@pytest.mark.asyncio
async def test_route_send_draft(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts/send").mock(
            return_value=httpx.Response(200, json={"id": "x"})
        )
        r = await route_tool(tool_name="send_draft", arguments={"draft_id": "d1"}, client=client)
    assert r["id"] == "x"


@pytest.mark.asyncio
async def test_route_delete_draft(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.delete("/users/me/drafts/d1").mock(return_value=httpx.Response(204))
        r = await route_tool(tool_name="delete_draft", arguments={"draft_id": "d1"}, client=client)
    assert r == {}


@pytest.mark.asyncio
async def test_route_create_label(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/labels").mock(return_value=httpx.Response(200, json={"id": "L1"}))
        r = await route_tool(tool_name="create_label", arguments={"name": "X"}, client=client)
    assert r["id"] == "L1"


@pytest.mark.asyncio
async def test_route_update_label(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.put("/users/me/labels/L1").mock(return_value=httpx.Response(200, json={"id": "L1"}))
        r = await route_tool(
            tool_name="update_label",
            arguments={"label_id": "L1", "name": "Y"},
            client=client,
        )
    assert r["id"] == "L1"


@pytest.mark.asyncio
async def test_route_delete_label(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.delete("/users/me/labels/L1").mock(return_value=httpx.Response(204))
        r = await route_tool(tool_name="delete_label", arguments={"label_id": "L1"}, client=client)
    assert r == {}


@pytest.mark.asyncio
async def test_route_modify_email_labels(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/messages/M1/modify").mock(
            return_value=httpx.Response(200, json={"id": "M1"})
        )
        r = await route_tool(
            tool_name="modify_email_labels",
            arguments={"message_id": "M1", "add_label_ids": ["INBOX"]},
            client=client,
        )
    assert r["id"] == "M1"


@pytest.mark.asyncio
async def test_route_create_filter(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/settings/filters").mock(
            return_value=httpx.Response(200, json={"id": "F1"})
        )
        r = await route_tool(
            tool_name="create_filter",
            arguments={"criteria": {"from": "x"}, "action": {"addLabelIds": ["L1"]}},
            client=client,
        )
    assert r["id"] == "F1"


@pytest.mark.asyncio
async def test_route_delete_filter(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.delete("/users/me/settings/filters/F1").mock(return_value=httpx.Response(204))
        r = await route_tool(
            tool_name="delete_filter", arguments={"filter_id": "F1"}, client=client
        )
    assert r == {}


@pytest.mark.asyncio
async def test_route_delete_email(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/messages/M1/trash").mock(
            return_value=httpx.Response(200, json={"id": "M1"})
        )
        r = await route_tool(
            tool_name="delete_email", arguments={"message_id": "M1"}, client=client
        )
    assert r["id"] == "M1"


@pytest.mark.asyncio
async def test_route_batch_delete_emails(client):
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(204)

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/messages/batchModify").mock(side_effect=handler)
        r = await route_tool(
            tool_name="batch_delete_emails",
            arguments={"message_ids": ["M1", "M2"]},
            client=client,
        )
    assert r == {}
    assert captured["body"]["addLabelIds"] == ["TRASH"]


# ---------------------------------------------------------------------------
# Argument validation paths
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_route_unknown_tool_returns_unknown_error(client):
    """When the write router returns _NOT_HANDLED, route_tool surfaces unknown_error."""
    r = await route_tool(
        tool_name="not_a_real_tool",
        arguments={"account_email": "x@x.com"},
        client=client,
    )
    assert r["code"] == ToolErrorCode.UNKNOWN


@pytest.mark.asyncio
async def test_route_send_email_missing_required_arg_returns_bad_request(client):
    r = await route_tool(
        tool_name="send_email",
        arguments={},
        client=client,
        auth0_sub="u",
        account_email="me@x.com",
    )
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_route_batch_delete_emails_empty_list_returns_bad_request(client):
    r = await route_tool(
        tool_name="batch_delete_emails",
        arguments={"message_ids": []},
        client=client,
    )
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_route_create_filter_non_dict_criteria_returns_bad_request(client):
    r = await route_tool(
        tool_name="create_filter",
        arguments={"criteria": "not-a-dict", "action": {"addLabelIds": ["L1"]}},
        client=client,
    )
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_route_create_draft_with_attachment(client):
    """Exercise the attachment-decoder path in tool_router_write."""
    data_b64 = base64.urlsafe_b64encode(b"hello").decode("ascii")
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts").mock(return_value=httpx.Response(200, json={"id": "d1"}))
        r = await route_tool(
            tool_name="create_draft",
            arguments={
                "sender": "me@x.com",
                "to": ["y@x.com"],
                "subject": "s",
                "body_text": "b",
                "attachments": [
                    {"filename": "f.txt", "mime_type": "text/plain", "data_base64url": data_b64}
                ],
            },
            client=client,
        )
    assert r["id"] == "d1"


@pytest.mark.asyncio
async def test_route_create_draft_malformed_attachment_returns_bad_request(client):
    r = await route_tool(
        tool_name="create_draft",
        arguments={
            "sender": "me@x.com",
            "to": ["y@x.com"],
            "subject": "s",
            "body_text": "b",
            "attachments": "not-a-list",
        },
        client=client,
    )
    assert r["code"] == ToolErrorCode.BAD_REQUEST


# ---------------------------------------------------------------------------
# Cleanup-tool dispatch coverage (one happy path per new tool)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_route_reply_all(client):
    """Smoke: reply_all dispatches and posts to messages/send."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/ORIG").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "ORIG",
                    "threadId": "T",
                    "payload": {
                        "headers": [
                            {"name": "From", "value": "alice@example.com"},
                            {"name": "To", "value": "me@x.com"},
                            {"name": "Subject", "value": "Hello"},
                            {"name": "Message-ID", "value": "<M1@example.com>"},
                        ]
                    },
                },
            )
        )
        router.get("/users/me/profile").mock(
            return_value=httpx.Response(200, json={"emailAddress": "me@x.com"})
        )
        router.post("/users/me/messages/send").mock(
            return_value=httpx.Response(200, json={"id": "sent-1"})
        )
        r = await route_tool(
            tool_name="reply_all",
            arguments={
                "message_id": "ORIG",
                "body_text": "thanks",
            },
            client=client,
            auth0_sub="u",
            account_email="me@x.com",
        )
    assert r["id"] == "sent-1"


@pytest.mark.asyncio
async def test_route_batch_modify_emails(client):
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(204)

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/messages/batchModify").mock(side_effect=handler)
        r = await route_tool(
            tool_name="batch_modify_emails",
            arguments={
                "message_ids": ["M1", "M2"],
                "add_label_ids": ["IMPORTANT"],
            },
            client=client,
        )
    assert r == {}
    assert captured["body"]["addLabelIds"] == ["IMPORTANT"]
    # Confirm we are NOT defaulting to TRASH; this differs from
    # batch_delete_emails by design.
    assert "TRASH" not in (captured["body"].get("addLabelIds") or [])


@pytest.mark.asyncio
async def test_route_get_or_create_label(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/labels").mock(return_value=httpx.Response(200, json={"labels": []}))
        router.post("/users/me/labels").mock(
            return_value=httpx.Response(200, json={"id": "Lnew", "name": "Y"})
        )
        r = await route_tool(
            tool_name="get_or_create_label",
            arguments={"name": "Y"},
            client=client,
        )
    assert r["id"] == "Lnew"


@pytest.mark.asyncio
async def test_route_create_filter_from_template(client):
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "F1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/settings/filters").mock(side_effect=handler)
        r = await route_tool(
            tool_name="create_filter_from_template",
            arguments={
                "template": "auto_archive_sender",
                "sender_email": "spam@example.com",
            },
            client=client,
        )
    assert r["id"] == "F1"
    assert captured["body"]["criteria"]["from"] == "spam@example.com"


@pytest.mark.asyncio
async def test_route_create_filter_from_template_empty_query_returns_bad_request(client):
    """B2 round-trip via dispatcher: empty query rejected, no Gmail call."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={}))
        r = await route_tool(
            tool_name="create_filter_from_template",
            arguments={
                "template": "auto_label_from_keyword",
                "query": "",
                "label_id": "L1",
            },
            client=client,
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


# ---------------------------------------------------------------------------
# thread_id round trip through tool_router for create_draft / update_draft
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_route_create_draft_with_thread_id_sets_threadid_on_message(client):
    """tool_router_write happy path: arguments['thread_id'] reaches the
    Gmail request body at message.threadId."""
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "d1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts").mock(side_effect=handler)
        r = await route_tool(
            tool_name="create_draft",
            arguments={
                "sender": "me@x.com",
                "to": ["y@x.com"],
                "subject": "s",
                "body_text": "b",
                "thread_id": "T-router-create",
            },
            client=client,
        )
    assert r["id"] == "d1"
    assert captured["body"]["message"]["threadId"] == "T-router-create"


@pytest.mark.asyncio
async def test_route_update_draft_with_thread_id_sets_threadid_on_message(client):
    """tool_router_write happy path mirror for update_draft."""
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "d1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.put("/users/me/drafts/d1").mock(side_effect=handler)
        r = await route_tool(
            tool_name="update_draft",
            arguments={
                "draft_id": "d1",
                "sender": "me@x.com",
                "to": ["y@x.com"],
                "subject": "s",
                "body_text": "b",
                "thread_id": "T-router-update",
            },
            client=client,
        )
    assert r["id"] == "d1"
    assert captured["body"]["message"]["threadId"] == "T-router-update"


@pytest.mark.asyncio
async def test_route_create_draft_invalid_thread_id_typed_bad_request(client):
    """Round trip via the dispatcher: a malformed thread_id surfaces as a
    typed bad_request_error (not an unhandled ValueError). The route
    layer's ValueError-to-bad_request_error translation is the user-
    facing failure path defense-in-depth shipping for thread_id."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={"id": "should-not-happen"}))
        r = await route_tool(
            tool_name="create_draft",
            arguments={
                "sender": "me@x.com",
                "to": ["y@x.com"],
                "subject": "s",
                "body_text": "b",
                # CRLF injection probe (header-smuggling shape).
                "thread_id": "T\r\nX-Injected: 1",
            },
            client=client,
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST
