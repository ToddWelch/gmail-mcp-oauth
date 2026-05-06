"""Tests for reply_all.

Coversfoot-gun mitigations:
- Empty expanded recipient list -> bad_request_error.
- getProfile failure -> upstream_error (NOT silent fallback).
- Self filtered out of To+Cc.
- Recipient set capped at 100.
- Idempotency cache shared with send_email (same key partition).
"""

from __future__ import annotations

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import reply
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient
from mcp_gmail.gmail_tools.idempotency import IdempotencyCache


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


def _original_message(*, headers: list[tuple[str, str]]) -> dict:
    """Build a Gmail format=metadata message payload with the given headers."""
    return {
        "id": "ORIG",
        "threadId": "THREAD",
        "payload": {
            "headers": [{"name": n, "value": v} for n, v in headers],
        },
    }


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reply_all_replies_to_from_and_ccs_to_plus_cc_minus_self(client):
    """Original From -> reply To. Original To+Cc minus self -> reply Cc."""
    sent_bodies: list[dict] = []

    def get_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_original_message(
                headers=[
                    ("From", "alice@example.com"),
                    ("To", "me@example.com, bob@example.com"),
                    ("Cc", "carol@example.com"),
                    ("Subject", "Hello"),
                    ("Message-ID", "<msg-1@example.com>"),
                ]
            ),
        )

    def profile_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"emailAddress": "me@example.com"})

    def send_handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        sent_bodies.append(_json.loads(request.read().decode()))
        return httpx.Response(200, json={"id": "sent-1", "threadId": "THREAD"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/ORIG").mock(side_effect=get_handler)
        router.get("/users/me/profile").mock(side_effect=profile_handler)
        router.post("/users/me/messages/send").mock(side_effect=send_handler)
        r = await reply.reply_all(
            client=client,
            auth0_sub="u",
            account_email="me@example.com",
            message_id="ORIG",
            body_text="thanks for the note",
        )

    assert r == {"id": "sent-1", "threadId": "THREAD"}
    # Decode the raw RFC 5322 to verify recipients (To + Cc).
    import base64

    raw_b64 = sent_bodies[0]["raw"]
    padded = raw_b64 + "=" * (-len(raw_b64) % 4)
    rfc5322 = base64.urlsafe_b64decode(padded).decode("ascii", errors="replace")
    # Reply To is the original From.
    assert "To: alice@example.com" in rfc5322
    # Reply Cc has bob and carol but NOT me.
    assert "bob@example.com" in rfc5322
    assert "carol@example.com" in rfc5322
    # Self filtered out of Cc.
    assert "Cc: " in rfc5322
    cc_line = next(line for line in rfc5322.splitlines() if line.startswith("Cc:"))
    assert "me@example.com" not in cc_line
    # Threading headers.
    assert "In-Reply-To: <msg-1@example.com>" in rfc5322
    assert "References: <msg-1@example.com>" in rfc5322
    # Subject prefixed.
    assert "Subject: Re: Hello" in rfc5322


@pytest.mark.asyncio
async def test_reply_all_does_not_double_prefix_re(client):
    """If original Subject starts with Re:, don't add another."""
    sent_bodies: list[dict] = []

    def get_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_original_message(
                headers=[
                    ("From", "alice@example.com"),
                    ("To", "me@example.com"),
                    ("Subject", "Re: previous chat"),
                    ("Message-ID", "<msg-1@example.com>"),
                ]
            ),
        )

    def profile_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"emailAddress": "me@example.com"})

    def send_handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        sent_bodies.append(_json.loads(request.read().decode()))
        return httpx.Response(200, json={"id": "sent-1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/ORIG").mock(side_effect=get_handler)
        router.get("/users/me/profile").mock(side_effect=profile_handler)
        router.post("/users/me/messages/send").mock(side_effect=send_handler)
        await reply.reply_all(
            client=client,
            auth0_sub="u",
            account_email="me@example.com",
            message_id="ORIG",
            body_text="hi",
        )

    import base64

    raw_b64 = sent_bodies[0]["raw"]
    padded = raw_b64 + "=" * (-len(raw_b64) % 4)
    rfc5322 = base64.urlsafe_b64decode(padded).decode("ascii", errors="replace")
    assert "Subject: Re: previous chat" in rfc5322
    assert "Re: Re:" not in rfc5322


# ---------------------------------------------------------------------------
# Empty recipient list -> bad_request (N1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reply_all_empty_recipients_returns_bad_request(client):
    """Original where the only recipient is self: no recipients to reply to."""

    def get_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_original_message(
                headers=[
                    # Original was sent by self to nobody else
                    ("From", "me@example.com"),
                    ("To", "me@example.com"),
                    ("Subject", "self note"),
                ]
            ),
        )

    def profile_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"emailAddress": "me@example.com"})

    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.get("/users/me/messages/ORIG").mock(side_effect=get_handler)
        router.get("/users/me/profile").mock(side_effect=profile_handler)
        send_route = router.post("/users/me/messages/send")
        send_route.mock(return_value=httpx.Response(200, json={"id": "x"}))
        r = await reply.reply_all(
            client=client,
            auth0_sub="u",
            account_email="me@example.com",
            message_id="ORIG",
            body_text="hi",
        )
        # The send endpoint must NOT have been called.
        assert send_route.called is False

    assert r["code"] == ToolErrorCode.BAD_REQUEST
    assert "no recipients" in r["message"].lower()


# ---------------------------------------------------------------------------
# getProfile failure -> upstream_error (N1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reply_all_getprofile_failure_returns_upstream_error(client):
    """getProfile 5xx -> upstream_error, NOT silent send to everyone."""

    def get_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_original_message(
                headers=[
                    ("From", "alice@example.com"),
                    ("To", "me@example.com, bob@example.com"),
                    ("Subject", "Hello"),
                    ("Message-ID", "<msg-1@example.com>"),
                ]
            ),
        )

    def profile_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="profile unavailable")

    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.get("/users/me/messages/ORIG").mock(side_effect=get_handler)
        router.get("/users/me/profile").mock(side_effect=profile_handler)
        send_route = router.post("/users/me/messages/send")
        send_route.mock(return_value=httpx.Response(200, json={"id": "x"}))
        r = await reply.reply_all(
            client=client,
            auth0_sub="u",
            account_email="me@example.com",
            message_id="ORIG",
            body_text="hi",
        )
        # Send must NOT have happened on getProfile failure.
        assert send_route.called is False

    assert r["code"] == ToolErrorCode.UPSTREAM_ERROR


# ---------------------------------------------------------------------------
# Recipient cap (N1)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reply_all_caps_expanded_recipient_set_at_100(client):
    """Original with 200 To recipients: reply Cc capped at 100 - len(reply_to)."""
    sent_bodies: list[dict] = []

    big_to = ", ".join(f"u{i}@example.com" for i in range(200))

    def get_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=_original_message(
                headers=[
                    ("From", "alice@example.com"),
                    ("To", big_to),
                    ("Subject", "Mass mailing"),
                    ("Message-ID", "<msg-1@example.com>"),
                ]
            ),
        )

    def profile_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"emailAddress": "me@example.com"})

    def send_handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        sent_bodies.append(_json.loads(request.read().decode()))
        return httpx.Response(200, json={"id": "sent-1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/ORIG").mock(side_effect=get_handler)
        router.get("/users/me/profile").mock(side_effect=profile_handler)
        router.post("/users/me/messages/send").mock(side_effect=send_handler)
        await reply.reply_all(
            client=client,
            auth0_sub="u",
            account_email="me@example.com",
            message_id="ORIG",
            body_text="enough",
        )

    import base64

    raw_b64 = sent_bodies[0]["raw"]
    padded = raw_b64 + "=" * (-len(raw_b64) % 4)
    rfc5322 = base64.urlsafe_b64decode(padded).decode("ascii", errors="replace")
    # Reply To is alice (1), so Cc cap is 100 - 1 = 99.
    cc_line_idx = rfc5322.find("\nCc:")
    assert cc_line_idx >= 0
    # We can't easily count without re-parsing; the easier invariant is
    # that no more than 100 user@... addresses in u### form appear.
    addrs = [f"u{i}@example.com" for i in range(200) if f"u{i}@example.com" in rfc5322]
    # The expanded set (To + Cc) cannot exceed 100; our To has 1, so
    # Cc is at most 99.
    assert len(addrs) <= 99


# ---------------------------------------------------------------------------
# Idempotency cache (N2: shared with send_email key partition)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_reply_all_idempotency_cache_hit_skips_gmail(client):
    """Same idempotency_key from same actor: cache hit, NO Gmail calls."""
    cache = IdempotencyCache()
    # Pre-populate the cache.
    cache.set(
        ("u", "me@example.com", "abc"),
        {"id": "cached-1", "threadId": "T"},
    )
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={"id": "x"}))
        r = await reply.reply_all(
            client=client,
            auth0_sub="u",
            account_email="me@example.com",
            message_id="ORIG",
            body_text="hi",
            idempotency_key="abc",
            cache=cache,
        )
        assert any_route.called is False
    assert r == {"id": "cached-1", "threadId": "T"}
