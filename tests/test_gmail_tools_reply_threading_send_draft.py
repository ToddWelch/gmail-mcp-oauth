"""send_draft checks what the draft actually holds, before and after it goes out.

Draft shapes and thread ids here match what real Gmail returned on 2026-11-06:
a new draft's threadId equals its message id, and drafts.send returns the
draft's own threadId unchanged.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import drafts
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient

from ._threading_fixtures import (
    SCOPES_COMPOSE_ONLY,
    SCOPES_FULL_ACCESS,
    TARGET_RFC_ID,
    TARGET_THREAD,
    error_reason,
    message_metadata,
    mount_draft,
    mount_fresh_draft,
    mount_lookup,
)


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


def _send_draft(client, **overrides):
    args = {"client": client, "draft_id": "d1", "granted_scope": SCOPES_FULL_ACCESS}
    args.update(overrides)
    return drafts.send_draft(**args)


def _mount_drafts_send(router, *, thread_id: str = TARGET_THREAD):
    return router.post("/users/me/drafts/send").mock(
        return_value=httpx.Response(200, json={"id": "sent1", "threadId": thread_id})
    )


@pytest.mark.asyncio
async def test_send_draft_sends_a_reply_already_in_its_thread(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_draft(router, subject="Re: Items", in_reply_to=TARGET_RFC_ID)
        mount_lookup(router, message_metadata())
        send_route = _mount_drafts_send(router)
        result = await _send_draft(client)

    assert send_route.call_count == 1
    assert result["threadId"] == TARGET_THREAD


@pytest.mark.asyncio
async def test_send_draft_refuses_in_reply_to_pointing_at_a_different_thread(client):
    """The incident shape held in a draft: headers set, own thread brand new."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_draft(
            router, thread_id="draftsownthread1", subject="Re: Items", in_reply_to=TARGET_RFC_ID
        )
        mount_lookup(router, message_metadata())
        send_route = _mount_drafts_send(router, thread_id="draftsownthread1")
        result = await _send_draft(client)

    assert send_route.call_count == 0
    assert result["code"] == ToolErrorCode.THREADING_REFUSED
    assert error_reason(result) == "thread_conflict"


@pytest.mark.asyncio
async def test_send_draft_refuses_a_re_subject_with_no_in_reply_to(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_draft(router, subject="Re: Items")
        send_route = _mount_drafts_send(router)
        result = await _send_draft(client)

    assert send_route.call_count == 0
    assert error_reason(result) == "no_reply_target"


@pytest.mark.asyncio
async def test_send_draft_refuses_references_with_no_in_reply_to(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_draft(router, subject="Items", references=TARGET_RFC_ID)
        send_route = _mount_drafts_send(router)
        result = await _send_draft(client)

    assert send_route.call_count == 0
    assert error_reason(result) == "no_reply_target"


@pytest.mark.asyncio
async def test_send_draft_refuses_when_the_target_is_not_found(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_draft(router, subject="Re: Items", in_reply_to=TARGET_RFC_ID)
        mount_lookup(router)
        send_route = _mount_drafts_send(router)
        result = await _send_draft(client)

    assert send_route.call_count == 0
    assert error_reason(result) == "reply_target_not_found"


@pytest.mark.asyncio
async def test_send_draft_refuses_a_subject_mismatch(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_draft(router, subject="Re: Different", in_reply_to=TARGET_RFC_ID)
        mount_lookup(router, message_metadata())
        send_route = _mount_drafts_send(router)
        result = await _send_draft(client)

    assert send_route.call_count == 0
    assert error_reason(result) == "subject_mismatch"


@pytest.mark.asyncio
async def test_send_draft_compose_only_sends_a_plain_draft(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_fresh_draft(router)
        send_route = _mount_drafts_send(router, thread_id="freshdraftthread")
        result = await _send_draft(client, granted_scope=SCOPES_COMPOSE_ONLY)

    assert send_route.call_count == 1
    assert result["threadId"] == "freshdraftthread"


@pytest.mark.asyncio
async def test_send_draft_compose_only_refuses_a_reply_draft(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_draft(router, subject="Re: Items", in_reply_to=TARGET_RFC_ID)
        send_route = _mount_drafts_send(router)
        result = await _send_draft(client, granted_scope=SCOPES_COMPOSE_ONLY)

    assert send_route.call_count == 0
    assert result["code"] == ToolErrorCode.SCOPE_INSUFFICIENT


@pytest.mark.asyncio
async def test_send_draft_read_404_is_not_found_and_sends_nothing(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.get("/users/me/drafts/d1").mock(return_value=httpx.Response(404, json={}))
        send_route = _mount_drafts_send(router)
        result = await _send_draft(client)

    assert send_route.call_count == 0
    assert result["code"] == ToolErrorCode.NOT_FOUND


@pytest.mark.asyncio
async def test_send_draft_failed_read_refuses(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.get("/users/me/drafts/d1").mock(return_value=httpx.Response(503, json={}))
        send_route = _mount_drafts_send(router)
        result = await _send_draft(client)

    assert send_route.call_count == 0
    assert result["code"] == ToolErrorCode.THREADING_REFUSED
    assert error_reason(result) == "lookup_failed"
    assert result["data"]["error_data"]["status"] == 503


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stored",
    [
        {"id": "d1"},
        {"id": "d1", "message": {"id": "m", "threadId": "t"}},
        {"id": "d1", "message": {"id": "m", "threadId": "t", "payload": {"headers": []}}},
        {
            "id": "d1",
            "message": {"id": "m", "payload": {"headers": [{"name": "Subject", "value": "x"}]}},
        },
    ],
)
async def test_send_draft_refuses_a_draft_read_with_no_headers_or_thread(client, stored):
    """Absent headers must never read as 'this is not a reply'."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.get("/users/me/drafts/d1").mock(return_value=httpx.Response(200, json=stored))
        send_route = _mount_drafts_send(router)
        result = await _send_draft(client)

    assert send_route.call_count == 0
    assert error_reason(result) == "lookup_failed"


@pytest.mark.asyncio
async def test_send_draft_asks_gmail_for_metadata(client):
    """Contract: format=metadata is what returns headers. Last verified live 2026-11-06."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        read = mount_draft(router)
        _mount_drafts_send(router)
        await _send_draft(client)

    assert dict(read.calls[0].request.url.params) == {"format": "metadata"}


@pytest.mark.asyncio
async def test_send_draft_mismatch_is_an_error_and_runs_no_post_send_action(client):
    """Archiving the wrong thread on top of a split reply would compound it."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_draft(router, subject="Re: Items", in_reply_to=TARGET_RFC_ID)
        mount_lookup(router, message_metadata())
        _mount_drafts_send(router, thread_id="threadwrongwrong")
        modify = router.post("/users/me/threads/threadwrongwrong/modify").mock(
            return_value=httpx.Response(200, json={})
        )
        result = await _send_draft(client, archive_thread=True)

    assert modify.call_count == 0
    assert result["code"] == ToolErrorCode.THREAD_MISMATCH
    assert result["data"]["error_data"]["expected_thread_id"] == TARGET_THREAD
    assert result["data"]["error_data"]["sent_message_id"] == "sent1"
