"""Idempotency cache tests: cross-tool collision and TTL replay.

Targets:
- src/mcp_gmail/gmail_tools/idempotency.py (TTL expiry path)
- src/mcp_gmail/gmail_tools/send.py (send_email cache flow)
- src/mcp_gmail/gmail_tools/reply.py (reply_all cache flow)

These two scenarios surfaced during MCP-client end-to-end smoke
testing and are not covered by the contract suite in
test_gmail_tools_idempotency.py:

1. Replay-after-TTL: an idempotency entry that has expired must be a
   genuine cache miss; the next send must produce a fresh Gmail POST,
   never a stale cached value (a "zombie"). The existing
   test_expired_entry_returns_none asserts the cache primitive does
   the right thing in isolation; this new test exercises the full
   send_email -> cache path.

2. Cross-tool key collision: send_email and reply_all share the
   default_cache singleton and the same key shape
   (auth0_sub, account_email, idempotency_key). The second tool used to
   return the first tool's cached result, reporting success for a reply
   that never went out or met the threading checks. It is now refused,
   with ZERO Gmail calls from the second tool.

We use a fresh IdempotencyCache() per test (NOT the module-level
default_cache) so tests do not leak state into each other. For test
#1 we use ttl_seconds=0.05 (50ms) and time.sleep past the TTL; we
deliberately do not monkeypatch default_cache._ttl since it would be
a fragile reach into module internals.
"""

from __future__ import annotations

import time

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import reply, send
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient
from mcp_gmail.gmail_tools.idempotency import IdempotencyCache


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


# ---------------------------------------------------------------------------
# Scenario 1: replay after TTL expiry produces a fresh Gmail POST
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_email_replay_after_ttl_expiry_makes_fresh_post(client):
    """After the cache TTL expires, the second send_email call must
    produce a brand-new Gmail POST, NOT return the prior cached value.

    Pattern: instantiate a short-TTL cache, send once (POST 1), sleep
    past the TTL, send again (POST 2). The respx route returns
    distinct payloads on each call so we can assert the second send
    gets the FRESH payload (not the cached first one).
    """
    cache = IdempotencyCache(ttl_seconds=0.05)
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        send_route = router.post("/users/me/messages/send").mock(
            side_effect=[
                httpx.Response(200, json={"id": "first", "threadId": "t1"}),
                httpx.Response(200, json={"id": "second", "threadId": "t2"}),
            ]
        )
        first = await send.send_email(
            client=client,
            auth0_sub="u",
            account_email="me@example.com",
            sender="me@example.com",
            to=["you@example.com"],
            subject="s",
            body_text="b",
            idempotency_key="abc",
            cache=cache,
        )
        # Sleep past the 50ms TTL. 100ms gives a generous margin for
        # CI clocks (the existing test_expired_entry_returns_none in
        # test_gmail_tools_idempotency.py uses the same pattern with
        # 20ms sleep against a 10ms TTL; we double the margin).
        time.sleep(0.10)
        second = await send.send_email(
            client=client,
            auth0_sub="u",
            account_email="me@example.com",
            sender="me@example.com",
            to=["you@example.com"],
            subject="s",
            body_text="b",
            idempotency_key="abc",
            cache=cache,
        )
    assert send_route.call_count == 2, (
        f"expected two POSTs (cache miss after TTL), got {send_route.call_count}"
    )
    assert first == {"id": "first", "threadId": "t1"}
    assert second == {"id": "second", "threadId": "t2"}, (
        "second send returned the FIRST cached value; TTL expiry did not produce a fresh Gmail POST"
    )


# ---------------------------------------------------------------------------
# Scenario 2: cross-tool key collision (send_email -> reply_all)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_email_and_reply_all_collide_on_shared_idempotency_key(client):
    """When send_email and reply_all run with the same
    (auth0_sub, account_email, idempotency_key), the SECOND tool is
    refused and makes no Gmail call at all.

    It used to return the FIRST tool's cached result, which told the caller
    a reply had gone out when it had not, past every threading check.
    """
    cache = IdempotencyCache()

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        send_route = router.post("/users/me/messages/send").mock(
            return_value=httpx.Response(200, json={"id": "from-send", "threadId": "t1"})
        )
        # reply_all's source-message and profile GETs are deliberately not
        # mounted: if it read Gmail at all, respx would fail on the unmatched
        # request. The replay check is the first thing it does.

        first = await send.send_email(
            client=client,
            auth0_sub="user-a",
            account_email="me@example.com",
            sender="me@example.com",
            to=["you@example.com"],
            subject="s",
            body_text="b",
            idempotency_key="shared-key",
            cache=cache,
        )
        assert send_route.call_count == 1, "first send_email should hit Gmail once"
        assert first == {"id": "from-send", "threadId": "t1"}

        # Now call reply_all with the SAME idempotency_key from the SAME actor.
        replied = await reply.reply_all(
            client=client,
            auth0_sub="user-a",
            account_email="me@example.com",
            message_id="orig-123-shaped-like-a-real-id",
            body_text="my reply",
            idempotency_key="shared-key",
            cache=cache,
        )

    assert send_route.call_count == 1, "reply_all must not POST on a reused key"
    assert replied["code"] == ToolErrorCode.THREADING_REFUSED
    assert replied["data"]["error_data"]["reason"] == "idempotency_key_reused"
