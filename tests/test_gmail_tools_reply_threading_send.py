"""send_email and reply_all: a reply lands in its conversation.

Regression for the 2026-11-06 incident: a reply carrying correct In-Reply-To,
References and Subject went out as a new conversation, because the POST to
users.messages.send carried only `raw`. Older tests mocked a threadId in the
response, so they passed without one ever being sent; these assert on the
request body. Refusals are in test_gmail_tools_reply_threading_refusals.py.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import reply, send
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient
from mcp_gmail.gmail_tools.idempotency import IdempotencyCache

from ._threading_fixtures import (
    SCOPES_FULL_ACCESS,
    SCOPES_SEND_AND_READ,
    SCOPES_SEND_ONLY,
    TARGET_GMAIL_ID,
    TARGET_RFC_ID,
    TARGET_SUBJECT,
    TARGET_THREAD,
    decode_raw,
    error_reason,
    message_metadata,
    mount_lookup,
    mount_send,
    posted_body,
)


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


async def _send_reply(client, **overrides):
    args = {
        "client": client,
        "auth0_sub": "user-a",
        "account_email": "me@example.com",
        "sender": "me@example.com",
        "to": ["you@example.com"],
        "subject": f"Re: {TARGET_SUBJECT}",
        "body_text": "thanks",
        "reply_to_message_id": TARGET_RFC_ID,
        "granted_scope": SCOPES_FULL_ACCESS,
        "cache": IdempotencyCache(),
    }
    args.update(overrides)
    return await send.send_email(**args)


def _source(thread_id: str | None = TARGET_THREAD) -> dict:
    message = {
        "id": TARGET_GMAIL_ID,
        "payload": {
            "headers": [
                {"name": "From", "value": "you@example.com"},
                {"name": "To", "value": "me@example.com"},
                {"name": "Subject", "value": TARGET_SUBJECT},
                {"name": "Message-Id", "value": TARGET_RFC_ID},
            ]
        },
    }
    if thread_id is not None:
        message["threadId"] = thread_id
    return message


def _mount_source(router, source: dict) -> None:
    router.get(f"/users/me/messages/{TARGET_GMAIL_ID}").mock(
        return_value=httpx.Response(200, json=source)
    )
    router.get("/users/me/profile").mock(
        return_value=httpx.Response(200, json={"emailAddress": "me@example.com"})
    )


async def _reply_all(client, **overrides):
    args = {
        "client": client,
        "auth0_sub": "user-a",
        "account_email": "me@example.com",
        "message_id": TARGET_GMAIL_ID,
        "body_text": "thanks",
        "cache": IdempotencyCache(),
    }
    args.update(overrides)
    return await reply.reply_all(**args)


# ---------------------------------------------------------------------------
# The regression: the POST itself carries threadId
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_email_reply_posts_the_resolved_thread_id(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = mount_send(router)
        result = await _send_reply(client)

    body = posted_body(send_route)
    # Exact field set pins the accepted contract. Proved live by the post-deploy
    # proof recorded on PR #33.
    assert set(body) == {"raw", "threadId"}
    assert body["threadId"] == TARGET_THREAD
    assert result["threadId"] == TARGET_THREAD
    parsed = decode_raw(body)
    assert parsed["In-Reply-To"] == TARGET_RFC_ID
    assert parsed["References"] == TARGET_RFC_ID


@pytest.mark.asyncio
async def test_reply_all_posts_the_source_thread_id(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        _mount_source(router, _source())
        send_route = mount_send(router)
        result = await _reply_all(client)

    body = posted_body(send_route)
    assert set(body) == {"raw", "threadId"}
    assert body["threadId"] == TARGET_THREAD
    assert result["threadId"] == TARGET_THREAD


@pytest.mark.asyncio
async def test_lookup_uses_the_confirmed_search_form(client):
    """Exact query shape. Verified live 2026-11-06: rfc822msgid matches the whole id
    only (a partial id returns nothing). The Spam and Trash flag is sent per Gmail's
    docs; a target actually in Spam or Trash has not been exercised live."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        search = mount_lookup(router, message_metadata())
        mount_send(router)
        await _send_reply(client)
        metadata_read = next(
            call.request for call in router.calls if call.request.url.path.endswith(TARGET_GMAIL_ID)
        )

    params = dict(search.calls[0].request.url.params)
    assert params == {
        "q": 'rfc822msgid:"parent-1@mail.example.com"',
        "includeSpamTrash": "true",
        "maxResults": "10",
    }
    # Real Gmail returns only the headers asked for; the mock returns them regardless,
    # so without this a dropped Subject would refuse every reply only in production.
    assert metadata_read.url.params.get_list("metadataHeaders") == ["Message-ID", "Subject"]
    assert metadata_read.url.params["format"] == "metadata"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "form",
    ["<parent-1@mail.example.com>", "parent-1@mail.example.com", "  <parent-1@mail.example.com>  "],
)
async def test_every_accepted_id_form_emits_a_clean_header(client, form):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = mount_send(router)
        await _send_reply(client, reply_to_message_id=form)

    assert decode_raw(posted_body(send_route))["In-Reply-To"] == TARGET_RFC_ID


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "subject",
    ["Items", "Re: Items", "RE:  items", "re: fwd: ITEMS", "Fwd: Re:   Items ", "Re[2]: Items"],
)
async def test_subject_normalization_accepts_the_same_conversation(client, subject):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = mount_send(router)
        result = await _send_reply(client, subject=subject)

    assert "code" not in result
    assert posted_body(send_route)["threadId"] == TARGET_THREAD


@pytest.mark.asyncio
async def test_duplicate_copies_in_one_thread_still_resolve(client):
    copy_a = message_metadata(gmail_id="gmailcopyaaaaaaa")
    copy_b = message_metadata(gmail_id="gmailcopybbbbbbb")
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, copy_a, copy_b)
        send_route = mount_send(router)
        await _send_reply(client)

    assert posted_body(send_route)["threadId"] == TARGET_THREAD


# ---------------------------------------------------------------------------
# Item 6: post-send comparison
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_email_reports_a_post_send_thread_mismatch_as_an_error(client, caplog):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        mount_send(router, thread_id="threadwrongwrong", sent_id="sentwrongthread1")
        with caplog.at_level("ERROR"):
            result = await _send_reply(client)

    assert result["code"] == ToolErrorCode.THREAD_MISMATCH
    data = result["data"]["error_data"]
    assert data["expected_thread_id"] == TARGET_THREAD
    assert data["actual_thread_id"] == "threadwrongwrong"
    assert data["sent_message_id"] == "sentwrongthread1"
    assert "was sent" in result["message"].lower()
    logged = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    assert any(TARGET_THREAD in m and "threadwrongwrong" in m for m in logged)


@pytest.mark.asyncio
async def test_send_email_treats_a_missing_returned_thread_as_a_mismatch(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        router.post("/users/me/messages/send").mock(
            return_value=httpx.Response(200, json={"id": "sent000000000001"})
        )
        result = await _send_reply(client)

    assert result["code"] == ToolErrorCode.THREAD_MISMATCH
    assert result["data"]["error_data"]["actual_thread_id"] is None


@pytest.mark.asyncio
async def test_reply_all_reports_a_post_send_thread_mismatch_as_an_error(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        _mount_source(router, _source())
        mount_send(router, thread_id="threadwrongwrong")
        result = await _reply_all(client)

    assert result["code"] == ToolErrorCode.THREAD_MISMATCH
    assert result["data"]["error_data"]["expected_thread_id"] == TARGET_THREAD
    assert result["data"]["error_data"]["actual_thread_id"] == "threadwrongwrong"


@pytest.mark.asyncio
async def test_reply_all_with_no_source_message_id_still_lands_by_thread_id(client):
    """Nothing to put in In-Reply-To, but threadId alone joins (live 2026-11-06)."""
    source = _source()
    source["payload"]["headers"] = [
        h for h in source["payload"]["headers"] if h["name"] != "Message-Id"
    ]
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        _mount_source(router, source)
        send_route = mount_send(router)
        result = await _reply_all(client)

    body = posted_body(send_route)
    assert body["threadId"] == TARGET_THREAD
    assert decode_raw(body)["In-Reply-To"] is None
    assert result["threadId"] == TARGET_THREAD


@pytest.mark.asyncio
async def test_reply_all_refuses_when_the_source_has_no_thread_id(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        _mount_source(router, _source(thread_id=None))
        send_route = mount_send(router)
        result = await _reply_all(client)

    assert send_route.call_count == 0
    assert result["code"] == ToolErrorCode.THREADING_REFUSED
    assert error_reason(result) == "lookup_failed"


# ---------------------------------------------------------------------------
# Item 7: scopes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_plain_new_email_needs_no_read_access(client):
    """No search, no threadId, send-only token: the pre-fix behavior, byte for byte."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        search = mount_lookup(router)
        send_route = mount_send(router, thread_id="brandnewthread01")
        result = await _send_reply(
            client,
            subject="Items",
            reply_to_message_id=None,
            granted_scope=SCOPES_SEND_ONLY,
        )

    assert search.call_count == 0
    assert set(posted_body(send_route)) == {"raw"}
    assert result["threadId"] == "brandnewthread01"


@pytest.mark.asyncio
async def test_a_reply_without_read_access_refuses_loudly(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        search = mount_lookup(router)
        send_route = mount_send(router)
        result = await _send_reply(client, granted_scope=SCOPES_SEND_ONLY)

    assert send_route.call_count == 0
    assert search.call_count == 0
    assert result["code"] == ToolErrorCode.SCOPE_INSUFFICIENT
    data = result["data"]["error_data"]
    assert data["reason"] == "read_scope_missing"
    assert "gmail.readonly" in data["required_scopes"][0]
    assert "Nothing was sent" in result["message"]


@pytest.mark.asyncio
async def test_send_plus_read_scope_is_enough_for_a_reply(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = mount_send(router)
        await _send_reply(client, granted_scope=SCOPES_SEND_AND_READ)

    assert posted_body(send_route)["threadId"] == TARGET_THREAD


@pytest.mark.asyncio
async def test_handler_default_scope_fails_closed_for_a_reply(client):
    """A caller that forgets to pass the scope gets a refusal, never a send."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        send_route = mount_send(router)
        result = await send.send_email(
            client=client,
            auth0_sub="user-a",
            account_email="me@example.com",
            sender="me@example.com",
            to=["you@example.com"],
            subject="Re: Items",
            body_text="b",
            reply_to_message_id=TARGET_RFC_ID,
            cache=IdempotencyCache(),
        )

    assert send_route.call_count == 0
    assert result["code"] == ToolErrorCode.SCOPE_INSUFFICIENT
