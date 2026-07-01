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
