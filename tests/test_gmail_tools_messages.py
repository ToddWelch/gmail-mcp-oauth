"""Tests for the read-side message tools (read_email, search_emails,
download_attachment, download_email).

download_attachment now resolves one of three selection modes
(attachment_id | filename | part_index), enriches the output to
{filename, mime_type, size, data}, and lives in attachment_download.py
(re-exported via messages). These tests exercise it through the
`messages.download_attachment` re-export so the public reference the
router uses is what gets covered.
"""

from __future__ import annotations

import re
from unittest.mock import patch

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import messages
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailApiError, GmailClient


# Attachment IDs must satisfy the {16,2048} attachment pattern (real
# Gmail IDs are >=16 chars; get_attachment hard-validates them).
PDF_ID = "ATTACH_PDF_000001"
PNG_ID = "ATTACH_PNG_000002"
DUP_A_ID = "ATTACH_DUP_00000A"
DUP_B_ID = "ATTACH_DUP_00000B"
LONG_ID = "L" * 320  # ~320 chars: exceeds the old 128 cap, within {16,2048}


def _full_message_payload() -> dict:
    """A multipart message with three downloadable attachments in
    document order: report.pdf (0), nested logo.png (1), and a nested
    inline image with an attachmentId but NO filename (2). Also a text
    part with only body.data (no attachmentId) which is NOT enumerated."""
    return {
        "id": "M1",
        "payload": {
            "mimeType": "multipart/mixed",
            "filename": "",
            "body": {},
            "parts": [
                {"mimeType": "text/plain", "filename": "", "body": {"size": 10, "data": "aGk"}},
                {
                    "mimeType": "application/pdf",
                    "filename": "report.pdf",
                    "body": {"attachmentId": PDF_ID, "size": 1234},
                },
                {
                    "mimeType": "multipart/related",
                    "filename": "",
                    "body": {},
                    "parts": [
                        {
                            "mimeType": "image/png",
                            "filename": "logo.png",
                            "body": {"attachmentId": PNG_ID, "size": 555},
                        },
                        {
                            # inline image: attachmentId present, filename empty ->
                            # enumerated (reachable by part_index, filename is null)
                            "mimeType": "image/gif",
                            "filename": "",
                            "body": {"attachmentId": "INLINE_NOFILENAME_1", "size": 22},
                        },
                    ],
                },
            ],
        },
    }


def _deeply_nested_payload(levels: int) -> dict:
    """A payload nested `levels` deep via repeated single-child `parts`.
    With levels > _MAX_MIME_DEPTH the walker raises _MimeTooDeepError."""
    node: dict = {"mimeType": "text/plain", "filename": "", "body": {}}
    for _ in range(levels):
        node = {"mimeType": "multipart/mixed", "filename": "", "body": {}, "parts": [node]}
    return {"id": "M1", "payload": node}


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


@pytest.mark.asyncio
async def test_read_email_happy(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/M1").mock(
            return_value=httpx.Response(200, json={"id": "M1"})
        )
        r = await messages.read_email(client=client, message_id="M1")
        assert r == {"id": "M1"}


@pytest.mark.asyncio
async def test_read_email_404_returns_not_found(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/missing").mock(return_value=httpx.Response(404, json={}))
        r = await messages.read_email(client=client, message_id="missing")
        assert r["code"] == ToolErrorCode.NOT_FOUND


@pytest.mark.asyncio
async def test_read_email_invalid_format_rejected(client):
    r = await messages.read_email(client=client, message_id="M1", format="bogus")
    assert r["code"] == ToolErrorCode.BAD_REQUEST


def _b64url(text: str) -> str:
    import base64

    return base64.urlsafe_b64encode(text.encode("utf-8")).rstrip(b"=").decode("ascii")


@pytest.mark.asyncio
async def test_read_email_text_format_returns_lean_and_calls_full(client):
    """format='text' fetches Gmail with format='full' (Gmail has no
    'text' format) and returns the lean shape."""
    captured = {}
    plain = "Order total $42.00"

    def handler(request: httpx.Request) -> httpx.Response:
        captured["format"] = request.url.params.get("format")
        return httpx.Response(
            200,
            json={
                "id": "M1",
                "threadId": "T1",
                "labelIds": ["INBOX"],
                "snippet": "Order",
                "payload": {
                    "mimeType": "text/plain",
                    "headers": [{"name": "Subject", "value": "Order"}],
                    "body": {"data": _b64url(plain)},
                },
            },
        )

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/M1").mock(side_effect=handler)
        r = await messages.read_email(client=client, message_id="M1", format="text")

    assert captured["format"] == "full"  # Gmail is called with 'full'
    assert r["text"] == plain
    assert r["text_source"] == "text/plain"
    assert r["headers"] == {"Subject": "Order"}
    assert r["id"] == "M1"
    assert "payload" not in r  # the heavy payload is dropped


@pytest.mark.asyncio
async def test_read_email_text_format_drops_bloated_html(client):
    """The reported problem, at the tool boundary: a ~200KB text/html
    part next to a small text/plain yields a small lean response."""
    import json

    plain = "Small plain body."
    big_html = "<html><body>" + ("<div>row</div>" * 20000) + "</body></html>"
    assert len(big_html) > 200_000

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/M1").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "M1",
                    "threadId": "T1",
                    "snippet": "s",
                    "payload": {
                        "mimeType": "multipart/alternative",
                        "headers": [{"name": "Subject", "value": "S"}],
                        "parts": [
                            {
                                "mimeType": "text/plain",
                                "headers": [
                                    {"name": "Content-Type", "value": "text/plain; charset=utf-8"}
                                ],
                                "body": {"data": _b64url(plain)},
                            },
                            {
                                "mimeType": "text/html",
                                "headers": [
                                    {"name": "Content-Type", "value": "text/html; charset=utf-8"}
                                ],
                                "body": {"data": _b64url(big_html)},
                            },
                        ],
                    },
                },
            )
        )
        r = await messages.read_email(client=client, message_id="M1", format="text")

    assert r["text"] == plain
    assert r["text_source"] == "text/plain"
    serialized = json.dumps(r)
    assert len(serialized) < 4_000  # a few KB, not 200KB+
    assert "row" not in serialized


@pytest.mark.asyncio
async def test_search_emails_passes_query(client):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["params"] = dict(request.url.params)
        return httpx.Response(200, json={"messages": []})

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages").mock(side_effect=handler)
        await messages.search_emails(client=client, q="from:foo")
    assert captured["params"]["q"] == "from:foo"


@pytest.mark.asyncio
async def test_search_emails_no_args(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages").mock(
            return_value=httpx.Response(200, json={"messages": [{"id": "M1"}]})
        )
        r = await messages.search_emails(client=client)
        assert r["messages"][0]["id"] == "M1"


# ---------------------------------------------------------------------------
# search_emails include_previews (Feature B / #8)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_previews_off_is_byte_identical_no_extra_calls(client):
    """include_previews absent/False: the raw Gmail list page is returned
    unchanged and NO per-hit metadata GET is made (no N+1)."""
    listing = {
        "messages": [{"id": "M1", "threadId": "T1"}, {"id": "M2", "threadId": "T2"}],
        "nextPageToken": "np",
        "resultSizeEstimate": 2,
    }
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        list_route = router.get(path="/users/me/messages").mock(
            return_value=httpx.Response(200, json=listing)
        )
        # Any per-message GET would be a separate path; assert none fire.
        per_msg = router.get(re.compile(r"/users/me/messages/M\d+")).mock(
            return_value=httpx.Response(200, json={"id": "should-not-be-called"})
        )
        r_default = await messages.search_emails(client=client, q="x")
        r_false = await messages.search_emails(client=client, q="x", include_previews=False)

    assert r_default == listing  # byte-identical to Gmail's list page
    assert r_false == listing
    assert list_route.called is True
    assert per_msg.called is False  # zero extra Gmail calls when off


@pytest.mark.asyncio
async def test_search_previews_on_enriches_each_hit(client):
    """include_previews=True enriches each stub with
    {id, threadId, subject, from, date, snippet, labelIds} via one
    metadata GET per hit; envelope (nextPageToken/resultSizeEstimate)
    is preserved."""
    listing = {
        "messages": [{"id": "M1", "threadId": "T1"}, {"id": "M2", "threadId": "T2"}],
        "nextPageToken": "np",
        "resultSizeEstimate": 2,
    }

    def per_msg_handler(request: httpx.Request) -> httpx.Response:
        mid = request.url.path.rsplit("/", 1)[-1]
        assert request.url.params.get("format") == "metadata"
        return httpx.Response(
            200,
            json={
                "id": mid,
                "threadId": f"T{mid[-1]}",
                "labelIds": ["INBOX", "IMPORTANT"],
                "snippet": f"snippet-{mid}",
                "payload": {
                    "headers": [
                        {"name": "Subject", "value": f"Subj {mid}"},
                        {"name": "From", "value": f"{mid}@example.com"},
                        {"name": "Date", "value": "Mon, 13 Jul 2026 09:00:00 +0000"},
                    ]
                },
            },
        )

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get(path="/users/me/messages").mock(return_value=httpx.Response(200, json=listing))
        router.get(re.compile(r"/users/me/messages/M\d+")).mock(side_effect=per_msg_handler)
        r = await messages.search_emails(client=client, q="x", include_previews=True)

    assert r["nextPageToken"] == "np"
    assert r["resultSizeEstimate"] == 2
    previews = r["messages"]
    assert len(previews) == 2
    first = previews[0]
    assert first == {
        "id": "M1",
        "threadId": "T1",
        "subject": "Subj M1",
        "from": "M1@example.com",
        "date": "Mon, 13 Jul 2026 09:00:00 +0000",
        "snippet": "snippet-M1",
        "labelIds": ["INBOX", "IMPORTANT"],
    }


@pytest.mark.asyncio
async def test_search_previews_absent_header_is_null(client):
    """A hit missing the Date header yields date=None (absent -> null),
    not a KeyError; other preview fields still populate."""
    listing = {"messages": [{"id": "M1", "threadId": "T1"}]}

    def per_msg_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "M1",
                "threadId": "T1",
                "labelIds": [],
                "snippet": "s",
                "payload": {"headers": [{"name": "Subject", "value": "Only subject"}]},
            },
        )

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get(path="/users/me/messages").mock(return_value=httpx.Response(200, json=listing))
        router.get("/users/me/messages/M1").mock(side_effect=per_msg_handler)
        r = await messages.search_emails(client=client, q="x", include_previews=True)

    p = r["messages"][0]
    assert p["subject"] == "Only subject"
    assert p["from"] is None
    assert p["date"] is None
    assert p["labelIds"] == []


@pytest.mark.asyncio
async def test_search_previews_per_hit_failure_degrades_not_aborts(client):
    """A per-hit metadata GET that 404s degrades THAT entry to
    {id, threadId, error_status}; the other hits still enrich, and the
    page is not aborted."""
    listing = {
        "messages": [{"id": "M1", "threadId": "T1"}, {"id": "M2", "threadId": "T2"}],
    }

    def per_msg_handler(request: httpx.Request) -> httpx.Response:
        mid = request.url.path.rsplit("/", 1)[-1]
        if mid == "M2":
            return httpx.Response(404, json={})
        return httpx.Response(
            200,
            json={
                "id": mid,
                "threadId": "T1",
                "labelIds": ["INBOX"],
                "snippet": "ok",
                "payload": {"headers": [{"name": "Subject", "value": "Good"}]},
            },
        )

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get(path="/users/me/messages").mock(return_value=httpx.Response(200, json=listing))
        router.get(re.compile(r"/users/me/messages/M\d+")).mock(side_effect=per_msg_handler)
        r = await messages.search_emails(client=client, q="x", include_previews=True)

    good, bad = r["messages"]
    assert good["subject"] == "Good"
    assert bad == {"id": "M2", "threadId": "T2", "error_status": 404}


def test_search_emails_schema_has_optional_include_previews():
    """The tool schema advertises include_previews as an optional boolean;
    omitting it is valid (not in required)."""
    from mcp_gmail.gmail_tools import TOOL_DEFINITIONS

    tool_def = next(d for d in TOOL_DEFINITIONS if d["name"] == "search_emails")
    props = tool_def["inputSchema"]["properties"]
    assert props["include_previews"]["type"] == "boolean"
    assert "include_previews" not in tool_def["inputSchema"]["required"]


@pytest.mark.asyncio
async def test_search_previews_fanout_never_exceeds_concurrency_window(client):
    """With a large result page, the preview fan-out never has more than
    _PREVIEW_FANOUT_CONCURRENCY (10) metadata fetches in flight at once.
    An instrumented handler tracks concurrent in-flight calls and records
    the peak; the semaphore must hold it at or below the window even for
    a page far larger than the window (250 hits here)."""
    import asyncio

    from mcp_gmail.gmail_tools.messages import _PREVIEW_FANOUT_CONCURRENCY

    n = 250
    listing = {"messages": [{"id": f"M{i}", "threadId": f"T{i}"} for i in range(n)]}

    in_flight = 0
    peak = 0
    lock = asyncio.Lock()

    async def per_msg_handler(request: httpx.Request) -> httpx.Response:
        nonlocal in_flight, peak
        async with lock:
            in_flight += 1
            peak = max(peak, in_flight)
        # Yield so overlapping coroutines actually accumulate in flight;
        # without an await the counter would never exceed 1.
        await asyncio.sleep(0.001)
        async with lock:
            in_flight -= 1
        mid = request.url.path.rsplit("/", 1)[-1]
        return httpx.Response(
            200,
            json={
                "id": mid,
                "threadId": "T",
                "labelIds": [],
                "snippet": "s",
                "payload": {"headers": [{"name": "Subject", "value": "x"}]},
            },
        )

    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get(path="/users/me/messages").mock(return_value=httpx.Response(200, json=listing))
        router.get(re.compile(r"/users/me/messages/M\d+")).mock(side_effect=per_msg_handler)
        r = await messages.search_emails(client=client, q="x", include_previews=True)

    # All hits enriched, and the burst stayed within the window.
    assert len(r["messages"]) == n
    assert peak <= _PREVIEW_FANOUT_CONCURRENCY
    # Sanity: with 250 hits and a 10-wide window we should have actually
    # saturated the window (proves the semaphore is the binding limit,
    # not just a low natural concurrency).
    assert peak == _PREVIEW_FANOUT_CONCURRENCY


# ---------------------------------------------------------------------------
# download_attachment: attachment_id mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_download_attachment_by_id_enriched(client):
    """attachment_id mode returns the enriched {filename, mime_type, size, data}
    shape; metadata comes from the matched message part."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get(f"/users/me/messages/M1/attachments/{PDF_ID}").mock(
            return_value=httpx.Response(200, json={"size": 1234, "data": "cGRmYnl0ZXM"})
        )
        router.get("/users/me/messages/M1").mock(
            return_value=httpx.Response(200, json=_full_message_payload())
        )
        r = await messages.download_attachment(client=client, message_id="M1", attachment_id=PDF_ID)
    assert r == {
        "filename": "report.pdf",
        "mime_type": "application/pdf",
        "size": 1234,
        "data": "cGRmYnl0ZXM",
    }


@pytest.mark.asyncio
async def test_download_attachment_long_id_passes_all_gates(client):
    """A ~320-char attachment_id clears all three length gates (schema
    pattern, messages _ATTACHMENT_ID_PATTERN, gmail_id
    validate_attachment_id inside get_attachment) and returns bytes."""
    payload = {
        "id": "M1",
        "payload": {
            "mimeType": "multipart/mixed",
            "filename": "",
            "parts": [
                {
                    "mimeType": "application/octet-stream",
                    "filename": "big.bin",
                    "body": {"attachmentId": LONG_ID, "size": 9},
                }
            ],
        },
    }
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        att_route = router.get(f"/users/me/messages/M1/attachments/{LONG_ID}").mock(
            return_value=httpx.Response(200, json={"size": 9, "data": "YmlnYnl0ZXM"})
        )
        router.get("/users/me/messages/M1").mock(return_value=httpx.Response(200, json=payload))
        r = await messages.download_attachment(
            client=client, message_id="M1", attachment_id=LONG_ID
        )
    assert att_route.called is True
    assert r["filename"] == "big.bin"
    assert r["data"] == "YmlnYnl0ZXM"


@pytest.mark.asyncio
async def test_download_attachment_by_id_no_matching_part_degrades(client):
    """attachment_id mode: bytes ship even when no part matches the id
    (filename/mime_type degrade to null)."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get(f"/users/me/messages/M1/attachments/{LONG_ID}").mock(
            return_value=httpx.Response(200, json={"size": 3, "data": "YWJj"})
        )
        router.get("/users/me/messages/M1").mock(
            return_value=httpx.Response(200, json=_full_message_payload())
        )
        r = await messages.download_attachment(
            client=client, message_id="M1", attachment_id=LONG_ID
        )
    assert r == {"filename": None, "mime_type": None, "size": 3, "data": "YWJj"}


@pytest.mark.asyncio
async def test_download_attachment_by_id_enrichment_error_degrades(client):
    """AMEND-4(a): if the best-effort enrichment get_message errors
    (GmailApiError), the bytes still return with null metadata."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get(f"/users/me/messages/M1/attachments/{PDF_ID}").mock(
            return_value=httpx.Response(200, json={"size": 1234, "data": "cGRm"})
        )
        router.get("/users/me/messages/M1").mock(return_value=httpx.Response(500, json={}))
        r = await messages.download_attachment(client=client, message_id="M1", attachment_id=PDF_ID)
    assert r == {"filename": None, "mime_type": None, "size": 1234, "data": "cGRm"}


@pytest.mark.asyncio
async def test_download_attachment_by_id_enrichment_walker_raises_degrades(client):
    """FIX-3 (Codex finding 3): a NON-GmailApiError during enrichment
    (here the parts walker raises on a malformed/deeply-nested payload)
    must NOT drop the already-fetched bytes. The id-path enrichment
    catches broad Exception, so it degrades to null metadata and still
    returns the bytes."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get(f"/users/me/messages/M1/attachments/{PDF_ID}").mock(
            return_value=httpx.Response(200, json={"size": 7, "data": "Ynl0ZXM"})
        )
        router.get("/users/me/messages/M1").mock(
            return_value=httpx.Response(200, json=_full_message_payload())
        )
        with patch(
            "mcp_gmail.gmail_tools.attachment_download._enumerate_attachment_parts",
            side_effect=TypeError("malformed payload"),
        ):
            r = await messages.download_attachment(
                client=client, message_id="M1", attachment_id=PDF_ID
            )
    assert r == {"filename": None, "mime_type": None, "size": 7, "data": "Ynl0ZXM"}


@pytest.mark.asyncio
async def test_download_attachment_id_attachment_404(client):
    """attachment_id mode: the return-critical get_attachment 404 -> not_found."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get(f"/users/me/messages/M1/attachments/{PDF_ID}").mock(
            return_value=httpx.Response(404, json={})
        )
        r = await messages.download_attachment(client=client, message_id="M1", attachment_id=PDF_ID)
        assert r["code"] == ToolErrorCode.NOT_FOUND


@pytest.mark.asyncio
async def test_download_attachment_rejects_malformed_short_id(client):
    """Regression: a short 'bad' id is rejected as bad_request BEFORE any
    Gmail round trip."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route().mock(return_value=httpx.Response(200, json={}))
        r = await messages.download_attachment(client=client, message_id="M1", attachment_id="bad")
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


# ---------------------------------------------------------------------------
# download_attachment: filename / part_index modes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_download_attachment_by_filename(client):
    """filename mode resolves the exact match to its attachmentId, then
    fetches + enriches."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/M1").mock(
            return_value=httpx.Response(200, json=_full_message_payload())
        )
        att_route = router.get(f"/users/me/messages/M1/attachments/{PNG_ID}").mock(
            return_value=httpx.Response(200, json={"size": 555, "data": "cG5n"})
        )
        r = await messages.download_attachment(client=client, message_id="M1", filename="logo.png")
    assert att_route.called is True
    assert r == {"filename": "logo.png", "mime_type": "image/png", "size": 555, "data": "cG5n"}


@pytest.mark.asyncio
async def test_download_attachment_by_part_index(client):
    """part_index is 0-based document order over every part with an
    attachmentId: index 0 is report.pdf, index 1 is logo.png, index 2 is
    the nameless inline image (all three are enumerated)."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/M1").mock(
            return_value=httpx.Response(200, json=_full_message_payload())
        )
        att_route = router.get(f"/users/me/messages/M1/attachments/{PNG_ID}").mock(
            return_value=httpx.Response(200, json={"size": 555, "data": "cG5n"})
        )
        r = await messages.download_attachment(client=client, message_id="M1", part_index=1)
    assert att_route.called is True
    assert r["filename"] == "logo.png"


@pytest.mark.asyncio
async def test_download_attachment_nameless_inline_part_reachable_by_index(client):
    """FIX-1: a part with an attachmentId but NO filename (nameless inline
    attachment) is enumerated and reachable by part_index; its enriched
    filename is null. It sits at index 2 (after report.pdf and logo.png)."""
    inline_id = "INLINE_NOFILENAME_1"
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/M1").mock(
            return_value=httpx.Response(200, json=_full_message_payload())
        )
        att_route = router.get(f"/users/me/messages/M1/attachments/{inline_id}").mock(
            return_value=httpx.Response(200, json={"size": 22, "data": "Z2lm"})
        )
        r = await messages.download_attachment(client=client, message_id="M1", part_index=2)
    assert att_route.called is True
    assert r == {"filename": None, "mime_type": "image/gif", "size": 22, "data": "Z2lm"}


@pytest.mark.asyncio
async def test_download_attachment_deep_nesting_load_bearing_bad_request(client):
    """FIX-A: a pathologically deep MIME tree on the load-bearing
    filename/part_index path returns a typed bad_request (not an
    unhandled RecursionError escaping route_tool), and no attachment is
    fetched."""
    deep = _deeply_nested_payload(150)
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.get("/users/me/messages/M1").mock(return_value=httpx.Response(200, json=deep))
        att_route = router.get(url__regex=r".*/attachments/.*").mock(
            return_value=httpx.Response(200, json={"size": 1, "data": "YQ"})
        )
        r = await messages.download_attachment(client=client, message_id="M1", part_index=0)
        assert att_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_download_attachment_deep_nesting_id_path_degrades(client):
    """FIX-A + FIX-3: a deep MIME tree raised during id-path enrichment is
    swallowed by the broad best-effort except; the bytes still return with
    null metadata."""
    deep = _deeply_nested_payload(150)
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get(f"/users/me/messages/M1/attachments/{PDF_ID}").mock(
            return_value=httpx.Response(200, json={"size": 4, "data": "ZGF0"})
        )
        router.get("/users/me/messages/M1").mock(return_value=httpx.Response(200, json=deep))
        r = await messages.download_attachment(client=client, message_id="M1", attachment_id=PDF_ID)
    assert r == {"filename": None, "mime_type": None, "size": 4, "data": "ZGF0"}


@pytest.mark.asyncio
async def test_download_attachment_ambiguous_filename(client):
    """Two parts share the filename -> bad_request listing candidate
    part_index values; no attachment fetched."""

    def _dup_part(attachment_id: str) -> dict:
        return {
            "mimeType": "text/plain",
            "filename": "dup.txt",
            "body": {"attachmentId": attachment_id},
        }

    payload = {
        "id": "M1",
        "payload": {
            "mimeType": "multipart/mixed",
            "parts": [_dup_part(DUP_A_ID), _dup_part(DUP_B_ID)],
        },
    }
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.get("/users/me/messages/M1").mock(return_value=httpx.Response(200, json=payload))
        att_route = router.get(url__regex=r".*/attachments/.*").mock(
            return_value=httpx.Response(200, json={})
        )
        r = await messages.download_attachment(client=client, message_id="M1", filename="dup.txt")
        assert att_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST
    assert "0" in r["message"] and "1" in r["message"]


@pytest.mark.asyncio
async def test_download_attachment_filename_not_found(client):
    """filename with no matching part -> bad_request (not a Gmail 404)."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/M1").mock(
            return_value=httpx.Response(200, json=_full_message_payload())
        )
        r = await messages.download_attachment(client=client, message_id="M1", filename="nope.txt")
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_download_attachment_part_index_out_of_range(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/M1").mock(
            return_value=httpx.Response(200, json=_full_message_payload())
        )
        r = await messages.download_attachment(client=client, message_id="M1", part_index=5)
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_download_attachment_part_index_negative_rejected(client):
    """AMEND-3: part_index=-1 must be rejected, NOT resolved via Python
    negative indexing to the last attachment."""
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        router.get("/users/me/messages/M1").mock(
            return_value=httpx.Response(200, json=_full_message_payload())
        )
        att_route = router.get(url__regex=r".*/attachments/.*").mock(
            return_value=httpx.Response(200, json={"size": 1, "data": "YQ"})
        )
        r = await messages.download_attachment(client=client, message_id="M1", part_index=-1)
        assert att_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_download_attachment_filename_message_404(client):
    """AMEND-4(b): the load-bearing get_message 404 surfaces as not_found."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/M1").mock(return_value=httpx.Response(404, json={}))
        r = await messages.download_attachment(client=client, message_id="M1", part_index=0)
        assert r["code"] == ToolErrorCode.NOT_FOUND


@pytest.mark.asyncio
async def test_download_attachment_load_bearing_5xx_propagates(client):
    """AMEND-4(b): a NON-404 GmailApiError on the load-bearing get_message
    is not swallowed; it propagates so the router's gmail_error_to_dict
    maps it (5xx -> upstream_error, 429 -> rate_limited)."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/M1").mock(return_value=httpx.Response(503, json={}))
        with pytest.raises(GmailApiError):
            await messages.download_attachment(client=client, message_id="M1", part_index=0)


# ---------------------------------------------------------------------------
# download_attachment: selector-count enforcement
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_download_attachment_zero_selectors(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route().mock(return_value=httpx.Response(200, json={}))
        r = await messages.download_attachment(client=client, message_id="M1")
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_download_attachment_two_selectors(client):
    with respx.mock(base_url=GMAIL_API_BASE, assert_all_called=False) as router:
        any_route = router.route().mock(return_value=httpx.Response(200, json={}))
        r = await messages.download_attachment(
            client=client, message_id="M1", attachment_id=PDF_ID, part_index=0
        )
        assert any_route.called is False
    assert r["code"] == ToolErrorCode.BAD_REQUEST


# ---------------------------------------------------------------------------
# download_email
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_download_email_returns_raw_format(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["params"] = dict(request.url.params)
            return httpx.Response(200, json={"id": "M1", "raw": "ZW5jb2RlZA"})

        router.get("/users/me/messages/M1").mock(side_effect=handler)
        r = await messages.download_email(client=client, message_id="M1")
    assert captured["params"]["format"] == "raw"
    assert r["raw"] == "ZW5jb2RlZA"


@pytest.mark.asyncio
async def test_download_email_404(client):
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/missing").mock(return_value=httpx.Response(404, json={}))
        r = await messages.download_email(client=client, message_id="missing")
        assert r["code"] == ToolErrorCode.NOT_FOUND
