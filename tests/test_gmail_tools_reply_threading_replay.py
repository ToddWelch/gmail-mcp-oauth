"""Item 8: a replay inside the idempotency window never resends, and never
returns a result that skipped the threading checks."""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import send
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailApiError, GmailClient
from mcp_gmail.gmail_tools.idempotency import IdempotencyCache
from mcp_gmail.gmail_tools.reply_outcomes import attachment_identity

from ._threading_fixtures import (
    SCOPES_FULL_ACCESS,
    TARGET_RFC_ID,
    TARGET_THREAD,
    error_reason,
    message_metadata,
    mount_lookup,
    mount_send,
    slow_send,
)


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


def _send(client, cache, **overrides):
    args = {
        "client": client,
        "auth0_sub": "user-a",
        "account_email": "me@example.com",
        "sender": "me@example.com",
        "to": ["you@example.com"],
        "subject": "Re: Items",
        "body_text": "thanks",
        "reply_to_message_id": TARGET_RFC_ID,
        "granted_scope": SCOPES_FULL_ACCESS,
        "idempotency_key": "key-1",
        "cache": cache,
    }
    args.update(overrides)
    return send.send_email(**args)


@pytest.mark.asyncio
async def test_a_replay_returns_the_first_result_with_no_gmail_calls(client):
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        search = mount_lookup(router, message_metadata())
        send_route = mount_send(router)
        first = await _send(client, cache)
        second = await _send(client, cache)

    assert second == first
    assert send_route.call_count == 1
    assert search.call_count == 1, "a replay must not repeat the lookup either"


@pytest.mark.asyncio
async def test_a_replay_with_bracket_differences_is_still_the_same_call(client):
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = mount_send(router)
        first = await _send(client, cache)
        second = await _send(client, cache, reply_to_message_id="parent-1@mail.example.com")

    assert second == first
    assert send_route.call_count == 1


@pytest.mark.asyncio
async def test_a_post_send_mismatch_replays_as_the_same_error_without_resending(client):
    """The mail already went out once. A retry must not send it a second time."""
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = mount_send(router, thread_id="threadwrongwrong")
        first = await _send(client, cache)
        second = await _send(client, cache)

    assert first["code"] == ToolErrorCode.THREAD_MISMATCH
    assert second == first
    assert send_route.call_count == 1


@pytest.mark.asyncio
async def test_reusing_a_plain_email_key_for_a_reply_is_refused(client):
    """Otherwise the reply reports success with an unthreaded message's id."""
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        send_route = mount_send(router, thread_id="brandnewthread01")
        await _send(client, cache, subject="Items", reply_to_message_id=None)
        replay = await _send(client, cache)

    assert send_route.call_count == 1
    assert replay["code"] == ToolErrorCode.THREADING_REFUSED
    assert error_reason(replay) == "idempotency_key_reused"


@pytest.mark.asyncio
async def test_reusing_a_key_for_a_different_subject_is_refused(client):
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = mount_send(router)
        await _send(client, cache)
        replay = await _send(client, cache, subject="Re: Different")

    assert send_route.call_count == 1
    assert error_reason(replay) == "idempotency_key_reused"


@pytest.mark.asyncio
async def test_an_entry_with_no_fingerprint_is_not_trusted(client):
    """Fail closed: anything that did not come through the checked path refuses."""
    cache = IdempotencyCache()
    cache.set(("user-a", "me@example.com", "key-1"), {"id": "x", "threadId": "y"})
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        send_route = mount_send(router)
        result = await _send(client, cache)

    assert send_route.call_count == 0
    assert error_reason(result) == "idempotency_key_reused"


@pytest.mark.asyncio
async def test_a_refused_attempt_is_not_cached_so_a_corrected_retry_sends_once(client):
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = mount_send(router)
        refused = await _send(client, cache, subject="Re: Wrong")
        assert send_route.call_count == 0
        corrected = await _send(client, cache, subject="Re: Items")

    assert error_reason(refused) == "subject_mismatch"
    assert corrected["threadId"] == TARGET_THREAD
    assert send_route.call_count == 1


@pytest.mark.asyncio
async def test_concurrent_replays_send_exactly_once(client):
    """A client retrying while the first call is mid-send must not double send."""
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = router.post("/users/me/messages/send").mock(side_effect=slow_send)
        results = await asyncio.gather(*(_send(client, cache) for _ in range(5)))

    assert send_route.call_count == 1
    assert all(r == results[0] for r in results)
    assert cache._locks == {}, "idle key locks must be released"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"to": ["someone-else@example.com"]},
        {"cc": ["someone-else@example.com"]},
        {"bcc": ["someone-else@example.com"]},
        {"reply_to_references": ["<another-parent@mail.example.com>"]},
        {
            "attachments": [
                {"filename": "a.txt", "mime_type": "text/plain", "data_base64url": "YQ"},
            ]
        },
        {"body_text": "a different body"},
        {"body_html": "<p>a different body</p>"},
        {"sender": "alias@example.com"},
    ],
)
async def test_reusing_a_key_for_different_content_is_refused(client, overrides):
    """Otherwise the new recipient or body is reported as sent when nothing went out."""
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = mount_send(router)
        await _send(client, cache)
        replay = await _send(client, cache, **overrides)

    assert send_route.call_count == 1
    assert error_reason(replay) == "idempotency_key_reused"


@pytest.mark.asyncio
async def test_different_keys_do_not_wait_on_each_other(client):
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = mount_send(router)
        await asyncio.gather(
            _send(client, cache, idempotency_key="a"),
            _send(client, cache, idempotency_key="b"),
        )

    assert send_route.call_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [0, 500, 503])
async def test_an_unconfirmed_send_replays_as_an_error_and_never_resends(client, status):
    """Gmail may have accepted it, so a retry could mail a real person twice."""
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = router.post("/users/me/messages/send")
        if status == 0:
            send_route.mock(side_effect=httpx.ReadTimeout("no answer"))
        else:
            send_route.mock(return_value=httpx.Response(status, json={}))
        first = await _send(client, cache)
        second = await _send(client, cache)

    assert send_route.call_count == 1
    assert first["code"] == ToolErrorCode.SEND_OUTCOME_UNKNOWN
    assert first["data"]["error_data"]["status"] == status
    assert "Sent" in first["message"]
    assert second == first
    assert cache._locks == {}


@pytest.mark.asyncio
async def test_a_2xx_with_an_unreadable_body_replays_as_an_error_and_never_resends(client):
    """The status says Gmail accepted it, so this is the likeliest duplicate of all."""
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = router.post("/users/me/messages/send").mock(
            return_value=httpx.Response(200, text="<html>not json</html>")
        )
        first = await _send(client, cache)
        second = await _send(client, cache)

    assert send_route.call_count == 1
    assert first["code"] == ToolErrorCode.SEND_OUTCOME_UNKNOWN
    assert second == first


@pytest.mark.asyncio
async def test_a_new_key_after_an_unconfirmed_send_sends_again_by_choice(client):
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = router.post("/users/me/messages/send").mock(
            side_effect=[
                httpx.Response(500, json={}),
                httpx.Response(200, json={"id": "sent2", "threadId": TARGET_THREAD}),
            ]
        )
        await _send(client, cache)
        retried = await _send(client, cache, idempotency_key="key-2")

    assert send_route.call_count == 2
    assert retried["id"] == "sent2"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 403, 429])
async def test_a_definite_refusal_from_gmail_stays_retryable(client, status):
    """Gmail said no, so nothing went out and the same key can try again."""
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        mount_lookup(router, message_metadata())
        send_route = router.post("/users/me/messages/send").mock(
            side_effect=[
                httpx.Response(status, json={}),
                httpx.Response(200, json={"id": "sent2", "threadId": TARGET_THREAD}),
            ]
        )
        with pytest.raises(GmailApiError):
            await _send(client, cache)
        assert cache._locks == {}
        retried = await _send(client, cache)

    assert send_route.call_count == 2
    assert retried["id"] == "sent2"


@pytest.mark.asyncio
async def test_a_retry_with_a_fresh_upload_handle_is_still_a_replay():
    """Upload tokens are one-time, so a retry legitimately carries a new one."""
    first = attachment_identity([{"source": "upload", "upload_token": "tokenaaaaaaaaaaa"}])
    retry = attachment_identity([{"source": "upload", "upload_token": "tokenbbbbbbbbbbb"}])
    other = attachment_identity(
        [{"source": "upload", "upload_token": "tokenbbbbbbbbbbb", "filename": "other.pdf"}]
    )

    assert first == retry
    assert first != other
    assert attachment_identity(None) is None
