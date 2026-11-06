"""Item 8 for reply_all: a replay never resends and never skips the checks.

send_email's replay tests are in test_gmail_tools_reply_threading_replay.py.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import reply
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient
from mcp_gmail.gmail_tools.idempotency import IdempotencyCache

from ._threading_fixtures import (
    TARGET_GMAIL_ID,
    TARGET_RFC_ID,
    TARGET_THREAD,
    error_reason,
    mount_send,
    slow_send,
)


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


def _mount_source(router, *, thread_id: str = TARGET_THREAD) -> None:
    router.get(f"/users/me/messages/{TARGET_GMAIL_ID}").mock(
        return_value=httpx.Response(
            200,
            json={
                "id": TARGET_GMAIL_ID,
                "threadId": thread_id,
                "payload": {
                    "headers": [
                        {"name": "From", "value": "you@example.com"},
                        {"name": "To", "value": "me@example.com"},
                        {"name": "Subject", "value": "Items"},
                        {"name": "Message-Id", "value": TARGET_RFC_ID},
                    ]
                },
            },
        )
    )
    router.get("/users/me/profile").mock(
        return_value=httpx.Response(200, json={"emailAddress": "me@example.com"})
    )


def _reply_all(client, cache, **overrides):
    args = {
        "client": client,
        "auth0_sub": "user-a",
        "account_email": "me@example.com",
        "message_id": TARGET_GMAIL_ID,
        "body_text": "thanks",
        "idempotency_key": "key-1",
        "cache": cache,
    }
    args.update(overrides)
    return reply.reply_all(**args)


@pytest.mark.asyncio
async def test_reply_all_replay_does_not_resend(client):
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        _mount_source(router)
        send_route = mount_send(router)
        first = await _reply_all(client, cache)
        second = await _reply_all(client, cache)

    assert second == first
    assert send_route.call_count == 1


@pytest.mark.asyncio
async def test_reply_all_mismatch_replays_as_the_same_error_without_resending(client):
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        _mount_source(router)
        send_route = mount_send(router, thread_id="threadwrongwrong")
        first = await _reply_all(client, cache)
        second = await _reply_all(client, cache)

    assert first["code"] == ToolErrorCode.THREAD_MISMATCH
    assert second == first
    assert send_route.call_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [{"message_id": "anothermessage01"}, {"body_text": "a different body"}],
)
async def test_reply_all_key_reused_for_a_different_message_is_refused(client, overrides):
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        _mount_source(router)
        send_route = mount_send(router)
        await _reply_all(client, cache)
        result = await _reply_all(client, cache, **overrides)

    assert send_route.call_count == 1
    assert error_reason(result) == "idempotency_key_reused"


@pytest.mark.asyncio
async def test_concurrent_reply_all_replays_send_exactly_once(client):
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        _mount_source(router)
        send_route = router.post("/users/me/messages/send").mock(side_effect=slow_send)
        await asyncio.gather(*(_reply_all(client, cache) for _ in range(5)))

    assert send_route.call_count == 1


@pytest.mark.asyncio
async def test_reply_all_unconfirmed_send_replays_as_an_error_and_never_resends(client):
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        _mount_source(router)
        send_route = router.post("/users/me/messages/send").mock(
            return_value=httpx.Response(503, json={})
        )
        first = await _reply_all(client, cache)
        second = await _reply_all(client, cache)

    assert send_route.call_count == 1
    assert first["code"] == ToolErrorCode.SEND_OUTCOME_UNKNOWN
    assert second == first
