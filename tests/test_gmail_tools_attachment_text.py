"""Tests for read_attachment_text: server-side text/table extraction.

Covers the four extraction methods (pdf, csv, xlsx, text) end to end
through the download_attachment selector reuse, the unsupported-mime
typed error, and the security surface: a malformed/hostile file of each
parsed type returns a typed extraction_failed bad_request WITHOUT a
crash/500/hang, the octet-stream extension fallback, the three selector
modes, and the text cap truncation with truncated=true.

Attachments are fed by mocking get_message (format=full, to resolve the
selector) and get_attachment (the base64url bytes) with respx, matching
the download_attachment test pattern. Real PDF/XLSX bytes are generated
in-process with pypdf/openpyxl so the extractors run against genuine
files, not stubs.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from mcp_gmail.gmail_tools import attachment_text
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.gmail_client import GMAIL_API_BASE, GmailClient
from mcp_gmail.gmail_tools.message_text import MAX_TEXT_CHARS

from ._attachment_fixtures import b64url, build_pdf_with_text, make_blank_pdf, make_xlsx

PDF_ID = "ATTACH_PDF_000001"
CSV_ID = "ATTACH_CSV_000001"
XLSX_ID = "ATTACH_XLSX_00001"
TXT_ID = "ATTACH_TXT_000001"
PNG_ID = "ATTACH_PNG_000001"
OCTET_ID = "ATTACH_OCTET_0001"

_PDF_WITH_TEXT = build_pdf_with_text("Invoice 42")


def _part(mime: str, filename: str, att_id: str) -> dict:
    return {"mimeType": mime, "filename": filename, "body": {"attachmentId": att_id, "size": 1}}


def _message_with(parts: list[dict]) -> dict:
    return {
        "id": "M1",
        "payload": {"mimeType": "multipart/mixed", "filename": "", "body": {}, "parts": parts},
    }


@pytest.fixture
async def client():
    c = GmailClient(access_token="t")
    yield c
    await c.aclose()


async def _run(client, *, message, att_id, raw_bytes, **selector):
    """Mock get_message + get_attachment and call read_attachment_text.

    Selector defaults to attachment_id=att_id; pass filename= or
    part_index= explicitly to exercise the other selection modes.
    """
    if not selector:
        selector = {"attachment_id": att_id}
    att_json = {"size": len(raw_bytes), "data": b64url(raw_bytes)}
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/M1").mock(return_value=httpx.Response(200, json=message))
        router.get(f"/users/me/messages/M1/attachments/{att_id}").mock(
            return_value=httpx.Response(200, json=att_json)
        )
        return await attachment_text.read_attachment_text(
            client=client, message_id="M1", **selector
        )


# ---------------------------------------------------------------------------
# Happy paths: one per extraction method
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pdf_extracts_text(client):
    msg = _message_with([_part("application/pdf", "invoice.pdf", PDF_ID)])
    r = await _run(client, message=msg, att_id=PDF_ID, raw_bytes=_PDF_WITH_TEXT)
    assert r["extraction_method"] == "pdf"
    assert r["filename"] == "invoice.pdf"
    assert r["mime_type"] == "application/pdf"
    assert r["truncated"] is False
    assert "Invoice 42" in r["text"]


@pytest.mark.asyncio
async def test_pdf_blank_page_does_not_crash(client):
    """A valid PDF with no text extracts to (near) empty, not an error."""
    msg = _message_with([_part("application/pdf", "blank.pdf", PDF_ID)])
    r = await _run(client, message=msg, att_id=PDF_ID, raw_bytes=make_blank_pdf())
    assert r["extraction_method"] == "pdf"
    assert "code" not in r


@pytest.mark.asyncio
async def test_csv_extracts_rows(client):
    raw = b"name,amount\nWidget,10\nGadget,20\n"
    msg = _message_with([_part("text/csv", "orders.csv", CSV_ID)])
    r = await _run(client, message=msg, att_id=CSV_ID, raw_bytes=raw, attachment_id=CSV_ID)
    assert r["extraction_method"] == "csv"
    assert "Widget\t10" in r["text"]
    assert "Gadget\t20" in r["text"]


@pytest.mark.asyncio
async def test_xlsx_extracts_cells(client):
    raw = make_xlsx([["name", "amount"], ["Widget", 10], ["Gadget", 20]])
    msg = _message_with([_part(attachment_text._MIME_XLSX, "book.xlsx", XLSX_ID)])
    r = await _run(client, message=msg, att_id=XLSX_ID, raw_bytes=raw, attachment_id=XLSX_ID)
    assert r["extraction_method"] == "xlsx"
    assert "Widget" in r["text"]
    assert "10" in r["text"]
    assert "20" in r["text"]


@pytest.mark.asyncio
async def test_text_plain_decodes(client):
    raw = "hello world\nsecond line".encode("utf-8")
    msg = _message_with([_part("text/plain", "note.txt", TXT_ID)])
    r = await _run(client, message=msg, att_id=TXT_ID, raw_bytes=raw, attachment_id=TXT_ID)
    assert r["extraction_method"] == "text"
    assert r["text"] == "hello world\nsecond line"


@pytest.mark.asyncio
async def test_text_plain_latin1_falls_back_to_replacement(client):
    """Non-utf-8 bytes decode with replacement rather than crashing."""
    raw = b"caf\xe9"  # latin-1 e-acute, invalid utf-8
    msg = _message_with([_part("text/plain", "note.txt", TXT_ID)])
    r = await _run(client, message=msg, att_id=TXT_ID, raw_bytes=raw, attachment_id=TXT_ID)
    assert r["extraction_method"] == "text"
    assert r["text"].startswith("caf")  # replacement char for the bad byte


# ---------------------------------------------------------------------------
# Unsupported mime -> typed bad_request (kind=unsupported), no crash
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unsupported_image_returns_typed_error(client):
    msg = _message_with([_part("image/png", "photo.png", PNG_ID)])
    r = await _run(client, message=msg, att_id=PNG_ID, raw_bytes=b"\x89PNG\r\n")
    assert r["code"] == ToolErrorCode.BAD_REQUEST
    assert r["data"]["error_data"]["kind"] == "unsupported"
    assert r["data"]["error_data"]["mime_type"] == "image/png"
    assert "download_attachment" in r["message"]


# ---------------------------------------------------------------------------
# octet-stream extension fallback
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_octet_stream_pdf_extension_fallback(client):
    """Gmail reports octet-stream but the .pdf extension routes to pypdf."""
    msg = _message_with([_part("application/octet-stream", "invoice.pdf", OCTET_ID)])
    r = await _run(client, message=msg, att_id=OCTET_ID, raw_bytes=_PDF_WITH_TEXT)
    assert r["extraction_method"] == "pdf"
    assert "Invoice 42" in r["text"]


@pytest.mark.asyncio
async def test_octet_stream_no_known_extension_unsupported(client):
    msg = _message_with([_part("application/octet-stream", "mystery.bin", OCTET_ID)])
    r = await _run(client, message=msg, att_id=OCTET_ID, raw_bytes=b"\x00\x01\x02")
    assert r["code"] == ToolErrorCode.BAD_REQUEST
    assert r["data"]["error_data"]["kind"] == "unsupported"


# ---------------------------------------------------------------------------
# Malformed / hostile file of each parsed type -> typed extraction_failed
# (never a raise / 500 / hang)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_malformed_pdf_returns_extraction_failed(client):
    raw = b"%PDF-1.4 this is not a real pdf body at all \x00\xff garbage"
    msg = _message_with([_part("application/pdf", "broken.pdf", PDF_ID)])
    r = await _run(client, message=msg, att_id=PDF_ID, raw_bytes=raw, attachment_id=PDF_ID)
    assert r["code"] == ToolErrorCode.BAD_REQUEST
    assert r["data"]["error_data"]["kind"] == "extraction_failed"


@pytest.mark.asyncio
async def test_malformed_xlsx_returns_extraction_failed(client):
    raw = b"PK\x03\x04 not really a zip/xlsx \x00\xff"
    msg = _message_with([_part(attachment_text._MIME_XLSX, "broken.xlsx", XLSX_ID)])
    r = await _run(client, message=msg, att_id=XLSX_ID, raw_bytes=raw, attachment_id=XLSX_ID)
    assert r["code"] == ToolErrorCode.BAD_REQUEST
    assert r["data"]["error_data"]["kind"] == "extraction_failed"


# ---------------------------------------------------------------------------
# Selector modes: attachment_id / filename / part_index all resolve
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_selector_by_filename(client):
    raw = b"a,b\n1,2\n"
    msg = _message_with([_part("text/csv", "data.csv", CSV_ID)])
    r = await _run(client, message=msg, att_id=CSV_ID, raw_bytes=raw, filename="data.csv")
    assert r["extraction_method"] == "csv"
    assert "1\t2" in r["text"]


@pytest.mark.asyncio
async def test_selector_by_part_index(client):
    raw = b"x,y\n3,4\n"
    msg = _message_with([_part("text/csv", "data.csv", CSV_ID)])
    r = await _run(client, message=msg, att_id=CSV_ID, raw_bytes=raw, part_index=0)
    assert r["extraction_method"] == "csv"
    assert "3\t4" in r["text"]


@pytest.mark.asyncio
async def test_selector_none_supplied_is_bad_request(client):
    # No selector: download_attachment rejects before any fetch.
    with respx.mock(base_url=GMAIL_API_BASE):
        r = await attachment_text.read_attachment_text(client=client, message_id="M1")
    assert r["code"] == ToolErrorCode.BAD_REQUEST


@pytest.mark.asyncio
async def test_selector_error_passes_through_unchanged(client):
    """A not-found on the load-bearing path surfaces as the selector error."""
    with respx.mock(base_url=GMAIL_API_BASE) as router:
        router.get("/users/me/messages/M1").mock(return_value=httpx.Response(404, json={}))
        r = await attachment_text.read_attachment_text(client=client, message_id="M1", part_index=0)
    assert r["code"] == ToolErrorCode.NOT_FOUND


# ---------------------------------------------------------------------------
# Text cap: a huge extraction truncates with the marker + truncated=true
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_huge_text_is_truncated_with_attachment_marker(client):
    raw = ("x" * (MAX_TEXT_CHARS + 5000)).encode("utf-8")
    msg = _message_with([_part("text/plain", "big.txt", TXT_ID)])
    r = await _run(client, message=msg, att_id=TXT_ID, raw_bytes=raw)
    assert r["truncated"] is True
    assert "text truncated" in r["text"]
    # The marker is attachment-appropriate: it points at download_attachment
    # for the raw bytes and must NOT carry the email-body remediation
    # ("format=full" / "download the message") reused from message_text.
    assert "download_attachment" in r["text"]
    assert "format=full" not in r["text"]
    assert "download the message" not in r["text"]
    # Text is capped at MAX_TEXT_CHARS plus the marker.
    assert len(r["text"]) < len(raw)
    assert r["text"].startswith("x" * 100)


@pytest.mark.asyncio
async def test_csv_early_exit_at_cap_truncates(client):
    """A CSV far larger than the cap truncates; extraction early-exits."""
    row = b"aaaaaaaaaa,bbbbbbbbbb\n"
    raw = row * (MAX_TEXT_CHARS // 10)  # well over the char cap
    msg = _message_with([_part("text/csv", "huge.csv", CSV_ID)])
    r = await _run(client, message=msg, att_id=CSV_ID, raw_bytes=raw)
    assert r["extraction_method"] == "csv"
    assert r["truncated"] is True
    assert "text truncated" in r["text"]
    assert "format=full" not in r["text"]
