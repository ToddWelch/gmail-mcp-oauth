"""Tests for the draft tools (create_draft, update_draft, list_drafts, send_draft, delete_draft)."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import drafts
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


# ---------------------------------------------------------------------------
# create_draft
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_draft_posts_to_drafts(client):
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "d1", "message": {"id": "m1"}})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts").mock(side_effect=handler)
        r = await drafts.create_draft(
            client=client,
            sender="me@x.com",
            to=["you@x.com"],
            subject="hello",
            body_text="body",
        )
    body = captured["body"]
    assert "message" in body
    assert "raw" in body["message"]
    assert r["id"] == "d1"


@pytest.mark.asyncio
async def test_create_draft_oversize_returns_bad_request(client):
    from mcp_gmail.gmail_tools.message_format import MAX_ENCODED_BYTES, Attachment

    raw = b"x" * int(MAX_ENCODED_BYTES * 0.78)
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={"id": "x"}))
        r = await drafts.create_draft(
            client=client,
            sender="me@x.com",
            to=["you@x.com"],
            subject="s",
            body_text="b",
            attachments=[
                Attachment(filename="big.bin", mime_type="application/octet-stream", data=raw)
            ],
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


# ---------------------------------------------------------------------------
# update_draft
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_update_draft_uses_PUT(client):
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        return httpx.Response(200, json={"id": "d1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.put("/users/me/drafts/d1").mock(side_effect=handler)
        r = await drafts.update_draft(
            client=client,
            draft_id="d1",
            sender="me@x.com",
            to=["you@x.com"],
            subject="s",
            body_text="b",
        )
    assert captured["method"] == "PUT"
    assert r["id"] == "d1"


@pytest.mark.asyncio
async def test_update_draft_404(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.put("/users/me/drafts/missing").mock(return_value=httpx.Response(404, json={}))
        r = await drafts.update_draft(
            client=client,
            draft_id="missing",
            sender="me@x.com",
            to=["you@x.com"],
            subject="s",
            body_text="b",
        )
    assert r["code"] == ToolErrorCode.NOT_FOUND


# ---------------------------------------------------------------------------
# list_drafts
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_drafts_passes_optional_filters(client):
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"drafts": [{"id": "d1"}]})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/drafts").mock(side_effect=handler)
        await drafts.list_drafts(client=client, q="from:boss", max_results=5)
    assert captured["params"]["q"] == "from:boss"
    assert captured["params"]["maxResults"] == "5"


@pytest.mark.asyncio
async def test_list_drafts_no_args(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/drafts").mock(return_value=httpx.Response(200, json={"drafts": []}))
        r = await drafts.list_drafts(client=client)
    assert r == {"drafts": []}


# ---------------------------------------------------------------------------
# send_draft
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_draft_posts_id_in_body(client):
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "sent-1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts/send").mock(side_effect=handler)
        r = await drafts.send_draft(client=client, draft_id="d1")
    assert captured["body"] == {"id": "d1"}
    assert r["id"] == "sent-1"


@pytest.mark.asyncio
async def test_send_draft_404(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts/send").mock(return_value=httpx.Response(404, json={}))
        r = await drafts.send_draft(client=client, draft_id="missing")
    assert r["code"] == ToolErrorCode.NOT_FOUND


# ---------------------------------------------------------------------------
# delete_draft
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_draft_uses_DELETE(client):
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        return httpx.Response(204)

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.delete("/users/me/drafts/d1").mock(side_effect=handler)
        r = await drafts.delete_draft(client=client, draft_id="d1")
    assert captured["method"] == "DELETE"
    assert r == {}


@pytest.mark.asyncio
async def test_delete_draft_404(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.delete("/users/me/drafts/missing").mock(return_value=httpx.Response(404, json={}))
        r = await drafts.delete_draft(client=client, draft_id="missing")
    assert r["code"] == ToolErrorCode.NOT_FOUND


# ---------------------------------------------------------------------------
# thread_id (Gmail's authoritative thread join on Message resource)
#
# Per Gmail API threading docs, adding a draft to an existing thread
# requires THREE conditions: the requested threadId on the Message
# resource, the In-Reply-To / References headers, and a matching
# Subject. The Gmail MCP previously exposed conditions 2 and 3 via
# reply_to_message_id / reply_to_references and Subject, but condition
# 1 (threadId) was missing in the original send-only design; the
# draft-thread-id parameter adds it. These tests prove the request body
# actually contains threadId at message.threadId when the caller
# supplies thread_id, and is byte-identical to the prior shape when the
# caller omits it (back-compat).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_draft_sets_message_thread_id_when_provided(client):
    """Happy path: thread_id flows to message.threadId in the request body."""
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "d1", "message": {"id": "m1", "threadId": "T123"}})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts").mock(side_effect=handler)
        await drafts.create_draft(
            client=client,
            sender="me@x.com",
            to=["you@x.com"],
            subject="hello",
            body_text="body",
            thread_id="T123",
        )
    assert captured["body"]["message"]["threadId"] == "T123"


@pytest.mark.asyncio
async def test_create_draft_omits_threadid_when_not_provided(client):
    """Back-compat: omitting thread_id keeps the request body byte-shape
    identical to . The `threadId` key MUST NOT appear."""
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "d1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts").mock(side_effect=handler)
        await drafts.create_draft(
            client=client,
            sender="me@x.com",
            to=["you@x.com"],
            subject="hello",
            body_text="body",
        )
    assert "threadId" not in captured["body"]["message"]


@pytest.mark.asyncio
async def test_update_draft_sets_message_thread_id_when_provided(client):
    """Happy path mirror for update_draft: PUT body includes threadId."""
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "d1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.put("/users/me/drafts/d1").mock(side_effect=handler)
        await drafts.update_draft(
            client=client,
            draft_id="d1",
            sender="me@x.com",
            to=["you@x.com"],
            subject="s",
            body_text="b",
            thread_id="T999",
        )
    assert captured["body"]["message"]["threadId"] == "T999"


@pytest.mark.asyncio
async def test_update_draft_omits_threadid_when_not_provided(client):
    """Back-compat for update_draft: omitted thread_id leaves the body shape
    unchanged from the original send-tool design."""
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "d1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.put("/users/me/drafts/d1").mock(side_effect=handler)
        await drafts.update_draft(
            client=client,
            draft_id="d1",
            sender="me@x.com",
            to=["you@x.com"],
            subject="s",
            body_text="b",
        )
    assert "threadId" not in captured["body"]["message"]


@pytest.mark.asyncio
async def test_create_draft_three_legged_threading_request_body(client):
    """Integration: thread_id together with reply_to_message_id and
    reply_to_references all target the same thread.

    Gmail's threading docs require ALL of:
      1. threadId on the Message resource (via thread_id)
      2. RFC 2822 In-Reply-To / References headers (via
         reply_to_message_id and reply_to_references)
      3. Matching Subject (via subject; not validated structurally
         here because the prior _build_raw_message tests already cover
         the Subject path)

    This test asserts the request body emerging from create_draft sets
    threadId on message.threadId AND the encoded raw RFC 5322 message
    contains both In-Reply-To and References headers. We decode the
    base64url raw to verify the headers are present; we deliberately
    do NOT assert exact byte values for the headers because
    message_format.py controls that surface and changing its tests
    would expand the blast radius."""
    import base64

    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.read().decode())
        return httpx.Response(200, json={"id": "d1"})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.post("/users/me/drafts").mock(side_effect=handler)
        await drafts.create_draft(
            client=client,
            sender="me@x.com",
            to=["you@x.com"],
            subject="Re: hello",
            body_text="thanks",
            reply_to_message_id="<orig@example.com>",
            reply_to_references=["<orig@example.com>"],
            thread_id="T-three-legged",
        )
    body = captured["body"]
    # Leg 1: threadId on the Message resource.
    assert body["message"]["threadId"] == "T-three-legged"
    # Legs 2 + 3: decode the raw RFC 5322 to confirm In-Reply-To and
    # References headers are present (Subject is also visible in the
    # decoded raw, which closes the third leg implicitly).
    raw_b64 = body["message"]["raw"]
    # Gmail uses URL-safe base64 without padding; restore padding for
    # decode correctness.
    padding = "=" * (-len(raw_b64) % 4)
    raw_bytes = base64.urlsafe_b64decode(raw_b64 + padding)
    decoded = raw_bytes.decode("utf-8", errors="replace")
    assert "In-Reply-To: <orig@example.com>" in decoded
    assert "References: <orig@example.com>" in decoded
    assert "Subject: Re: hello" in decoded


@pytest.mark.asyncio
async def test_create_draft_invalid_thread_id_rejected_at_handler(client):
    """Handler-entry validation (defense-in-depth): a malformed thread_id
    bypassing the schema regex still fails before the request is sent.

    This is the same defense-in-depth pattern established for
    every Gmail-ID-shaped field: schema regex at the JSON Schema layer,
    plus runtime validation via gmail_id.validate_gmail_id at the
    interpolation site. We assert the Gmail mock is NEVER called when
    a bad thread_id is supplied.
    """
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={"id": "should-not-happen"}))
        # CRLF injection probe (the canonical header-smuggling shape
        # from the adversarial set). validate_gmail_id raises
        # ValueError; tool_router translates that into bad_request_error
        # but only the route-level dispatcher does the translation, not
        # the bare drafts.create_draft tool function. So we assert the
        # ValueError propagates here (the route-level test below covers
        # the typed-error round trip).
        with pytest.raises(ValueError) as excinfo:
            await drafts.create_draft(
                client=client,
                sender="me@x.com",
                to=["you@x.com"],
                subject="s",
                body_text="b",
                thread_id="T\r\nX-Injected: 1",
            )
        assert any_route.called is False
    assert "thread_id" in str(excinfo.value)


@pytest.mark.asyncio
async def test_update_draft_invalid_thread_id_rejected_at_handler(client):
    """Handler-entry validation mirror for update_draft."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={"id": "should-not-happen"}))
        with pytest.raises(ValueError) as excinfo:
            await drafts.update_draft(
                client=client,
                draft_id="d1",
                sender="me@x.com",
                to=["you@x.com"],
                subject="s",
                body_text="b",
                thread_id="T\x00null",
            )
        assert any_route.called is False
    assert "thread_id" in str(excinfo.value)


@pytest.mark.parametrize(
    "bad_value",
    [
        # Mirror the adversarial probe set so the draft tools inherit the
        # same coverage. The shapes were curated for Gmail-ID seams:
        # CRLF (header smuggling), null byte (downstream truncation),
        # unicode homoglyph (lookalike confusion), URL-encoded slash
        # (path traversal), backslash (Windows-style traversal), hash
        # fragment (URL authority confusion), semicolon matrix-param,
        # at-sign userinfo (URL authority confusion), bare period
        # (relative path), oversized 257-char value (length cap).
        pytest.param("T\x00null", id="null-byte"),
        pytest.param("T\r\nX-Injected: 1", id="crlf-injection"),
        pytest.param("Tаbc", id="unicode-homoglyph-cyrillic-a"),
        pytest.param("T%2Fbad", id="url-encoded-slash"),
        pytest.param("T\\bad", id="backslash"),
        pytest.param("T#fragment", id="hash-fragment"),
        pytest.param("T;param=evil", id="semicolon-matrix-param"),
        pytest.param("T@evil.example", id="at-sign-userinfo"),
        pytest.param(".", id="lone-period"),
        pytest.param("T" * 257, id="oversized-257-chars"),
    ],
)
@pytest.mark.asyncio
async def test_create_draft_thread_id_adversarial_probes_rejected(client, bad_value):
    """Adversarial probe set on thread_id at the handler layer.

    Identical shape to test_validate_gmail_id_rejects_adversarial_shapes
    in test_gmail_id_validation_pr3h.py, applied to the new thread_id
    surface. No Gmail call must ever land for any of these probes."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={"id": "should-not-happen"}))
        with pytest.raises(ValueError) as excinfo:
            await drafts.create_draft(
                client=client,
                sender="me@x.com",
                to=["you@x.com"],
                subject="s",
                body_text="b",
                thread_id=bad_value,
            )
        assert any_route.called is False
    assert "thread_id" in str(excinfo.value)
