"""Tests for send_email.

Covers the four foot-gun mitigations the design calls out:
- Idempotency cache (cache hit returns cached value WITHOUT calling Gmail)
- 25 MiB attachment cap (oversize -> bad_request, no Gmail call)
- Recipient validation (malformed -> bad_request, no Gmail call)
- Audit log discipline (NO subject / body / recipients / filenames in caplog)
- Exactly one POST per call: cache miss path = exactly 1 POST,
  cache hit path = exactly 0 POSTs.
"""

from __future__ import annotations

import logging

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import send
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient
from mcp_gmail.gmail_tools.idempotency import IdempotencyCache


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_email_happy_path_makes_exactly_one_post(client):
    """Cache miss path: exactly one POST to users.messages.send."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        send_route = router.post("/users/me/messages/send").mock(
            return_value=httpx.Response(200, json={"id": "sent-1", "threadId": "t1"})
        )
        r = await send.send_email(
            client=client,
            auth0_sub="u",
            account_email="me@example.com",
            sender="me@example.com",
            to=["you@example.com"],
            subject="hello",
            body_text="hi",
        )
    assert send_route.call_count == 1
    assert r == {"id": "sent-1", "threadId": "t1"}


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_email_cache_hit_makes_zero_posts(client):
    """Same idempotency_key from same actor: cache hit, NO Gmail call."""
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        send_route = router.post("/users/me/messages/send").mock(
            return_value=httpx.Response(200, json={"id": "sent-1", "threadId": "t1"})
        )
        r1 = await send.send_email(
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
        r2 = await send.send_email(
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
    assert send_route.call_count == 1, "second call should hit cache"
    assert r1 == r2


@pytest.mark.asyncio
async def test_send_email_idempotency_key_partitioned_by_actor(client):
    """Decision 2: cache key includes (sub, email, idem_key)."""
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        send_route = router.post("/users/me/messages/send").mock(
            side_effect=[
                httpx.Response(200, json={"id": "from-a"}),
                httpx.Response(200, json={"id": "from-b"}),
            ]
        )
        r_a = await send.send_email(
            client=client,
            auth0_sub="user-a",
            account_email="x@example.com",
            sender="x@example.com",
            to=["y@example.com"],
            subject="s",
            body_text="b",
            idempotency_key="shared",
            cache=cache,
        )
        r_b = await send.send_email(
            client=client,
            auth0_sub="user-b",
            account_email="x@example.com",
            sender="x@example.com",
            to=["y@example.com"],
            subject="s",
            body_text="b",
            idempotency_key="shared",
            cache=cache,
        )
    assert send_route.call_count == 2
    assert r_a["id"] == "from-a"
    assert r_b["id"] == "from-b"


@pytest.mark.asyncio
async def test_send_email_empty_idempotency_key_rejected(client):
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={"id": "x"}))
        r = await send.send_email(
            client=client,
            auth0_sub="u",
            account_email="e",
            sender="me@x.com",
            to=["y@x.com"],
            subject="s",
            body_text="b",
            idempotency_key="",
            cache=cache,
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


# ---------------------------------------------------------------------------
# Attachment cap (25 MiB encoded)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_email_oversize_returns_bad_request_no_gmail_call(client):
    """Oversize attachment must NOT reach Gmail."""
    import base64

    from mcp_gmail.gmail_tools.message_format import MAX_ENCODED_BYTES

    raw = b"x" * int(MAX_ENCODED_BYTES * 0.78)
    data_b64 = base64.urlsafe_b64encode(raw).decode("ascii")
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        send_route = router.post("/users/me/messages/send")
        send_route.mock(return_value=httpx.Response(200, json={"id": "x"}))
        r = await send.send_email(
            client=client,
            auth0_sub="u",
            account_email="me@x.com",
            sender="me@x.com",
            to=["y@x.com"],
            subject="s",
            body_text="b",
            attachments=[
                {
                    "filename": "big.bin",
                    "mime_type": "application/octet-stream",
                    "data_base64url": data_b64,
                }
            ],
        )
        assert send_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_send_email_malformed_attachment_data_rejected(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={"id": "x"}))
        r = await send.send_email(
            client=client,
            auth0_sub="u",
            account_email="me@x.com",
            sender="me@x.com",
            to=["y@x.com"],
            subject="s",
            body_text="b",
            attachments=[
                {
                    "filename": "f",
                    "mime_type": "application/octet-stream",
                    "data_base64url": "@@@not_base64@@@",
                }
            ],
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


# ---------------------------------------------------------------------------
# Recipient validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_email_rejects_non_email_recipient(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={"id": "x"}))
        r = await send.send_email(
            client=client,
            auth0_sub="u",
            account_email="me@x.com",
            sender="me@x.com",
            to=["not-an-email"],
            subject="s",
            body_text="b",
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_send_email_rejects_non_email_in_cc(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={"id": "x"}))
        r = await send.send_email(
            client=client,
            auth0_sub="u",
            account_email="me@x.com",
            sender="me@x.com",
            to=["y@x.com"],
            cc=["bogus"],
            subject="s",
            body_text="b",
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


# ---------------------------------------------------------------------------
# Audit log discipline
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_email_does_not_log_subject_or_body_or_recipients(client, caplog):
    """Send-tool internals never log PII fields. The audit() helper at
    the dispatch boundary uses a structurally-restricted signature; the
    send function itself should not emit any record containing the
    sensitive payload."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/messages/send").mock(
            return_value=httpx.Response(200, json={"id": "x"})
        )
        with caplog.at_level(logging.DEBUG):
            await send.send_email(
                client=client,
                auth0_sub="u",
                account_email="me@x.com",
                sender="me@x.com",
                to=["yy@example.com"],
                subject="CONFIDENTIAL: contract",
                body_text="this body is sensitive",
            )

    for rec in caplog.records:
        msg = rec.getMessage()
        assert "CONFIDENTIAL" not in msg
        assert "contract" not in msg
        assert "this body is sensitive" not in msg
        # Recipient leak guard: deliberately check the localpart so a
        # benign substring match of "y@example.com" or similar in
        # framework debug output doesn't false-positive.
        assert "yy@example.com" not in msg
