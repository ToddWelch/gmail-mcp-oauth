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


@pytest.mark.asyncio
async def test_send_email_rejects_control_char_recipient_specific_error(client):
    """A recipient with a SINGLE @ but a CR/LF (e.g. header injection) passes the
    syntactic _looks_like_email check yet is caught by proactive per-field
    validation: a SPECIFIC field-named bad_request, and NO Gmail call."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={"id": "x"}))
        r = await send.send_email(
            client=client,
            auth0_sub="u",
            account_email="me@x.com",
            sender="me@x.com",
            to=["ok@x.com", "a@b.com\r\nX-Injected: y"],
            subject="s",
            body_text="b",
        )
        assert any_route.called is False  # build validation fired -> NO send
    assert r["code"] == ToolErrorCode.BAD_REQUEST
    assert r["message"] == "to[1] contains control characters"


@pytest.mark.asyncio
async def test_send_email_rejects_control_char_subject_specific_error(client):
    """A CR/LF in the subject yields the specific 'subject' bad_request, no send."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route()
        any_route.mock(return_value=httpx.Response(200, json={"id": "x"}))
        r = await send.send_email(
            client=client,
            auth0_sub="u",
            account_email="me@x.com",
            sender="me@x.com",
            to=["y@x.com"],
            subject="Hello\r\nX-Injected: y",
            body_text="b",
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST
    assert r["message"] == "subject contains control characters"


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


# ---------------------------------------------------------------------------
# body_html -> multipart/alternative on the wire (end-to-end through send)
# ---------------------------------------------------------------------------


def _decode_sent_message(send_route):
    """Parse the EmailMessage Gmail actually received from a send POST.

    Gmail's users.messages.send body is {"raw": base64url(rfc5322_bytes)}.
    Decode the last request's raw field back into an EmailMessage so tests
    can assert the exact MIME structure the recipient's client will see.
    """
    import base64
    import json
    from email import message_from_bytes
    from email.policy import default as default_policy

    body = json.loads(send_route.calls.last.request.content)
    raw = body["raw"]
    padded = raw + "=" * (-len(raw) % 4)
    rfc5322 = base64.urlsafe_b64decode(padded)
    return message_from_bytes(rfc5322, policy=default_policy)


_HTML_TABLE = "<table><tr><td>Q1</td><td>$5</td></tr></table>"


@pytest.mark.asyncio
async def test_send_email_body_html_sends_multipart_alternative_raw_html(client):
    """CORE PROOF at the send boundary: send_email with body_html POSTs a
    multipart/alternative whose text/plain part == body_text and whose
    text/html part carries the RAW (un-escaped) html. This is the exact
    fix: a <table> is delivered as real HTML, not literal tags."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        send_route = router.post("/users/me/messages/send").mock(
            return_value=httpx.Response(200, json={"id": "s1", "threadId": "t1"})
        )
        r = await send.send_email(
            client=client,
            auth0_sub="u",
            account_email="me@example.com",
            sender="me@example.com",
            to=["you@example.com"],
            subject="report",
            body_text="Q1: 5",
            body_html=_HTML_TABLE,
        )
    assert send_route.call_count == 1
    assert r == {"id": "s1", "threadId": "t1"}

    msg = _decode_sent_message(send_route)
    assert msg.get_content_type() == "multipart/alternative"
    parts = msg.get_payload()
    assert [p.get_content_type() for p in parts] == ["text/plain", "text/html"]
    assert parts[0].get_content().rstrip("\n") == "Q1: 5"

    html_payload = parts[1].get_content()
    assert "<table>" in html_payload
    assert "</table>" in html_payload
    assert html_payload.rstrip("\n") == _HTML_TABLE
    assert "&lt;table&gt;" not in html_payload


@pytest.mark.asyncio
async def test_send_email_without_body_html_is_single_text_plain(client):
    """No body_html: the wire message stays a single text/plain (unchanged)."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        send_route = router.post("/users/me/messages/send").mock(
            return_value=httpx.Response(200, json={"id": "s2"})
        )
        await send.send_email(
            client=client,
            auth0_sub="u",
            account_email="me@example.com",
            sender="me@example.com",
            to=["you@example.com"],
            subject="s",
            body_text="plain only",
        )
    msg = _decode_sent_message(send_route)
    assert not msg.is_multipart()
    assert msg.get_content_type() == "text/plain"
    assert msg.get_content().rstrip("\n") == "plain only"


@pytest.mark.asyncio
async def test_send_email_body_html_plus_attachment_is_mixed_alternative(client):
    """body_html + attachment: the wire message is multipart/mixed wrapping
    a multipart/alternative (plain + html) and the attachment."""
    import base64

    data_b64 = base64.urlsafe_b64encode(b"PDFDATA").decode("ascii")
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        send_route = router.post("/users/me/messages/send").mock(
            return_value=httpx.Response(200, json={"id": "s3"})
        )
        await send.send_email(
            client=client,
            auth0_sub="u",
            account_email="me@example.com",
            sender="me@example.com",
            to=["you@example.com"],
            subject="s",
            body_text="plain",
            body_html=_HTML_TABLE,
            attachments=[
                {
                    "filename": "r.pdf",
                    "mime_type": "application/pdf",
                    "data_base64url": data_b64,
                }
            ],
        )
    msg = _decode_sent_message(send_route)
    assert msg.get_content_type() == "multipart/mixed"
    atts = list(msg.iter_attachments())
    assert len(atts) == 1 and atts[0].get_filename() == "r.pdf"
    alt = next(p for p in msg.iter_parts() if p.get_content_type() == "multipart/alternative")
    assert {p.get_content_type() for p in alt.iter_parts()} == {
        "text/plain",
        "text/html",
    }


@pytest.mark.asyncio
async def test_send_email_body_html_oversize_bad_request_no_post(client):
    """An oversize text+html+attachment set raises OversizeMessage inside
    the build and returns bad_request BEFORE any Gmail POST (and before any
    slot consume). The html body counts toward the 25 MiB cap."""
    import base64

    from mcp_gmail.gmail_tools.message_format import MAX_ENCODED_BYTES

    big = b"x" * int(MAX_ENCODED_BYTES * 0.78)
    data_b64 = base64.urlsafe_b64encode(big).decode("ascii")
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        send_route = router.post("/users/me/messages/send")
        send_route.mock(return_value=httpx.Response(200, json={"id": "x"}))
        r = await send.send_email(
            client=client,
            auth0_sub="u",
            account_email="me@example.com",
            sender="me@example.com",
            to=["you@example.com"],
            subject="s",
            body_text="t",
            body_html="<p>" + ("h" * 1000) + "</p>",
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
async def test_send_email_body_html_preserves_idempotency_and_headers(client):
    """Invariants hold with an HTML body: header validation still rejects a
    control-char subject (no POST), and the idempotency cache still dedupes
    a body_html send to exactly one POST across two identical calls."""
    # Header validation still fires with body_html present.
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        route = router.post("/users/me/messages/send")
        route.mock(return_value=httpx.Response(200, json={"id": "x"}))
        r = await send.send_email(
            client=client,
            auth0_sub="u",
            account_email="me@example.com",
            sender="me@example.com",
            to=["you@example.com"],
            subject="bad\r\nX-Injected: y",
            body_text="t",
            body_html=_HTML_TABLE,
        )
        assert route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST

    # Idempotency: two identical body_html sends => exactly one POST.
    cache = IdempotencyCache()
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        send_route = router.post("/users/me/messages/send").mock(
            return_value=httpx.Response(200, json={"id": "s4", "threadId": "t4"})
        )
        kwargs = dict(
            client=client,
            auth0_sub="u",
            account_email="me@example.com",
            sender="me@example.com",
            to=["you@example.com"],
            subject="s",
            body_text="t",
            body_html=_HTML_TABLE,
            idempotency_key="k-html",
            cache=cache,
        )
        r1 = await send.send_email(**kwargs)
        r2 = await send.send_email(**kwargs)
    assert send_route.call_count == 1
    assert r1 == r2 == {"id": "s4", "threadId": "t4"}
