"""Tests for the write-side message tools (delete_email, batch_delete_emails, modify_email_labels).

Covers the TRASH-semantics design:
- delete_email maps to users.messages.trash (recoverable, gmail.modify)
- batch_delete_emails maps to users.messages.batchModify with
  addLabelIds=['TRASH'] (recoverable, gmail.modify), NOT batchDelete
"""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import messages_write
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


# ---------------------------------------------------------------------------
# delete_email
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_email_calls_trash_endpoint(client):
    """delete_email maps to users.messages.trash, NOT users.messages.delete."""
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        return httpx.Response(200, json={"id": "m1", "labelIds": ["TRASH"]})

    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.post("/users/me/messages/m1/trash").mock(side_effect=handler)
        # Make sure DELETE on /users/me/messages/m1 is NOT called.
        delete_route = router.delete("/users/me/messages/m1").mock(return_value=httpx.Response(204))
        result = await messages_write.delete_email(client=client, message_id="m1")
    assert captured["method"] == "POST"
    assert captured["path"].endswith("/messages/m1/trash")
    assert delete_route.called is False
    assert "TRASH" in result["labelIds"]


@pytest.mark.asyncio
async def test_delete_email_404_returns_not_found(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/messages/missing/trash").mock(
            return_value=httpx.Response(404, json={})
        )
        r = await messages_write.delete_email(client=client, message_id="missing")
    assert r["code"] == ToolErrorCode.NOT_FOUND


# ---------------------------------------------------------------------------
# batch_delete_emails
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_delete_emails_uses_batchModify_with_TRASH_label(client):
    """TRASH-semantics design: implemented via batchModify, NOT batchDelete."""
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(204)

    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.post("/users/me/messages/batchModify").mock(side_effect=handler)
        # The permanent batchDelete endpoint must NOT be called.
        permanent_route = router.post("/users/me/messages/batchDelete").mock(
            return_value=httpx.Response(204)
        )
        await messages_write.batch_delete_emails(
            client=client,
            message_ids=["m1", "m2", "m3"],
        )
    assert captured["method"] == "POST"
    assert captured["path"].endswith("/messages/batchModify")
    assert permanent_route.called is False
    body = captured["body"]
    assert isinstance(body, dict)
    assert body["ids"] == ["m1", "m2", "m3"]
    assert body["addLabelIds"] == ["TRASH"]
    # Removing TRASH would be wrong; the call should ONLY add TRASH.
    assert "removeLabelIds" not in body


@pytest.mark.asyncio
async def test_batch_delete_emails_rejects_empty_list(client):
    """Empty message_ids is bad_request, no Gmail call."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(204))
        r = await messages_write.batch_delete_emails(client=client, message_ids=[])
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_batch_delete_emails_rejects_over_1000_ids(client):
    """Gmail's batchModify cap is 1000; we fail fast above that."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(204))
        ids = [f"m{i}" for i in range(1001)]
        r = await messages_write.batch_delete_emails(client=client, message_ids=ids)
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_batch_delete_emails_at_cap_passes(client):
    """Exactly 1000 IDs is allowed."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/messages/batchModify").mock(return_value=httpx.Response(204))
        ids = [f"m{i}" for i in range(1000)]
        r = await messages_write.batch_delete_emails(client=client, message_ids=ids)
    assert r == {}


# ---------------------------------------------------------------------------
# modify_email_labels
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_modify_email_labels_sends_add_and_remove(client):
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "m1", "labelIds": ["INBOX"]})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/messages/m1/modify").mock(side_effect=handler)
        await messages_write.modify_email_labels(
            client=client,
            message_id="m1",
            add_label_ids=["INBOX"],
            remove_label_ids=["UNREAD"],
        )
    assert captured["body"]["addLabelIds"] == ["INBOX"]
    assert captured["body"]["removeLabelIds"] == ["UNREAD"]


@pytest.mark.asyncio
async def test_modify_email_labels_no_lists_still_calls_gmail(client):
    """Empty lists do not short-circuit; the audit line is the value."""
    called = {"hit": False}

    def handler(request: httpx.Request) -> httpx.Response:
        called["hit"] = True
        return httpx.Response(200, json={"id": "m1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/messages/m1/modify").mock(side_effect=handler)
        await messages_write.modify_email_labels(client=client, message_id="m1")
    assert called["hit"] is True


@pytest.mark.asyncio
async def test_modify_email_labels_404(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/messages/missing/modify").mock(
            return_value=httpx.Response(404, json={})
        )
        r = await messages_write.modify_email_labels(client=client, message_id="missing")
    assert r["code"] == ToolErrorCode.NOT_FOUND


# ---------------------------------------------------------------------------
# batch_modify_emails
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_batch_modify_emails_sends_caller_label_sets(client):
    """batch_modify_emails posts add+remove label sets verbatim, no TRASH default."""
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(204)

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/messages/batchModify").mock(side_effect=handler)
        await messages_write.batch_modify_emails(
            client=client,
            message_ids=["m1", "m2"],
            add_label_ids=["IMPORTANT"],
            remove_label_ids=["UNREAD"],
        )
    body = captured["body"]
    assert body["ids"] == ["m1", "m2"]
    assert body["addLabelIds"] == ["IMPORTANT"]
    assert body["removeLabelIds"] == ["UNREAD"]


@pytest.mark.asyncio
async def test_batch_modify_emails_rejects_empty_list(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(204))
        r = await messages_write.batch_modify_emails(
            client=client,
            message_ids=[],
            add_label_ids=["X"],
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_batch_modify_emails_rejects_over_1000_ids(client):
    """N5: reuses _BATCH_MODIFY_MAX_IDS = 1000 cap from the module."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(204))
        ids = [f"m{i}" for i in range(1001)]
        r = await messages_write.batch_modify_emails(
            client=client,
            message_ids=ids,
            add_label_ids=["X"],
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_batch_modify_emails_at_cap_passes(client):
    """Exactly 1000 IDs is allowed."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/messages/batchModify").mock(return_value=httpx.Response(204))
        ids = [f"m{i}" for i in range(1000)]
        r = await messages_write.batch_modify_emails(
            client=client,
            message_ids=ids,
            add_label_ids=["X"],
        )
    assert r == {}


@pytest.mark.asyncio
async def test_batch_modify_emails_rejects_both_empty(client):
    """both add_label_ids and remove_label_ids absent
    is a no-op; reject as bad_request BEFORE any Gmail call. Mirrors
    filters_write's empty-dict policy. Differs from modify_email_labels
    (single-message) which still calls Gmail on a no-op; the bulk tool
    is stricter because blast radius scales with the 1000-id cap.
    """
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(204))
        r = await messages_write.batch_modify_emails(
            client=client,
            message_ids=["m1"],
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_batch_modify_emails_rejects_both_empty_lists_passed(client):
    """Explicit empty lists also count as both-empty -> bad_request."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(204))
        r = await messages_write.batch_modify_emails(
            client=client,
            message_ids=["m1"],
            add_label_ids=[],
            remove_label_ids=[],
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_batch_modify_emails_only_remove_set_is_allowed(client):
    """Asymmetric: caller can pass only remove_label_ids and skip Gmail call gating."""
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(204)

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/messages/batchModify").mock(side_effect=handler)
        r = await messages_write.batch_modify_emails(
            client=client,
            message_ids=["m1"],
            remove_label_ids=["UNREAD"],
        )
    assert r == {}
    assert captured["body"]["removeLabelIds"] == ["UNREAD"]
    assert "addLabelIds" not in captured["body"]
