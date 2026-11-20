"""read_attachment_text: server-side text extraction from an attachment.

download_attachment returns raw base64url bytes; the caller then has to
decode a PDF/XLSX itself, which is flaky. This tool does the extraction
SERVER-SIDE and returns readable text, so the model gets the numbers /
text of an invoice/order PDF, CSV, or spreadsheet directly.

Selection reuse
---------------
The attachment is selected the SAME way as download_attachment: the
caller passes message_id plus EXACTLY ONE of attachment_id / filename /
part_index. We do NOT re-implement the selector or the parts walk; we
call `download_attachment` (attachment_download.py) and reuse its
enriched result (filename, mime_type, base64url data). Any selector
error (zero/multiple selectors, malformed id, not found, ambiguous
filename) surfaces UNCHANGED from that call.

Format dispatch
---------------
Extraction method is chosen from the part's mime_type first, with a
FILENAME-EXTENSION FALLBACK (.pdf / .csv / .xlsx) used ONLY when Gmail
reports a generic `application/octet-stream` (senders routinely mislabel
attachments as octet-stream). Supported:

  - application/pdf                     -> pypdf           (method "pdf")
  - text/csv                            -> stdlib csv      (method "csv")
  - ...spreadsheetml.sheet (xlsx)       -> openpyxl        (method "xlsx")
  - text/plain and other text/*         -> charset decode  (method "text")

Anything else (images, other binaries) returns a TYPED unsupported
bad_request naming the mime_type and pointing at download_attachment
for raw bytes; it never crashes.

Robustness
----------
The per-format extractors (attachment_extractors.py) are hard-bounded
against hostile input: safe-wrap to a typed extraction_failed, early-exit
at the char cap, and iteration guards. A malformed/hostile PDF/XLSX/CSV
returns a typed extraction_failed bad_request, never a -32603 / 500, and
never hangs. The final `text` is capped at MAX_TEXT_CHARS (reused from
message_text) with the same truncation marker + `truncated: true`.
"""

from __future__ import annotations

import base64
from typing import Any

from .attachment_download import download_attachment
from .attachment_extractors import (
    ExtractionError,
    extract_csv_text,
    extract_pdf_text,
    extract_xlsx_text,
)
from .errors import bad_request_error
from .gmail_client import GmailClient
from .message_text import MAX_TEXT_CHARS

# Tool-local truncation marker. We reuse MAX_TEXT_CHARS from message_text
# but NOT its marker: message_text._TRUNCATION_MARKER's remediation
# ("use format=full or download the message") is email-body advice that
# does not apply to an attachment (this tool has no `format` argument and
# "the message" is the wrong object). The attachment-appropriate
# remediation is to fetch the raw bytes via download_attachment.
_TRUNCATION_MARKER = (
    "\n\n[text truncated: {omitted} characters omitted; the attachment "
    "exceeds the extraction cap. Use download_attachment for the raw bytes.]"
)

# Canonical mime types we extract natively.
_MIME_PDF = "application/pdf"
_MIME_CSV = "text/csv"
_MIME_XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
_MIME_OCTET = "application/octet-stream"

# Extension -> method, used ONLY when mime_type is the generic octet-stream
# (senders mislabel PDFs/spreadsheets as octet-stream). Lowercase suffixes.
_EXT_FALLBACK: dict[str, str] = {
    ".pdf": "pdf",
    ".csv": "csv",
    ".xlsx": "xlsx",
}


def _cap_text(text: str) -> tuple[str, bool]:
    """Apply MAX_TEXT_CHARS to the extracted text. Returns (text, truncated).

    Same cap discipline as message_text (reuses MAX_TEXT_CHARS): under
    the cap the text is returned unchanged (truncated=False); over it,
    truncated to MAX_TEXT_CHARS with the attachment-appropriate
    _TRUNCATION_MARKER appended (truncated=True).
    """
    if len(text) <= MAX_TEXT_CHARS:
        return text, False
    omitted = len(text) - MAX_TEXT_CHARS
    return text[:MAX_TEXT_CHARS] + _TRUNCATION_MARKER.format(omitted=omitted), True


def _resolve_method(mime_type: str | None, filename: str | None) -> str | None:
    """Pick an extraction method from mime_type, with an octet-stream ext fallback.

    Returns "pdf" | "csv" | "xlsx" | "text", or None when unsupported.
    mime_type wins; the filename-extension fallback fires ONLY for the
    generic application/octet-stream so a mislabeled PDF/CSV/XLSX is
    still handled. text/* (other than text/csv) maps to "text".
    """
    mime = (mime_type or "").split(";", 1)[0].strip().lower()
    if mime == _MIME_PDF:
        return "pdf"
    if mime == _MIME_CSV:
        return "csv"
    if mime == _MIME_XLSX:
        return "xlsx"
    if mime.startswith("text/"):
        return "text"
    if mime in ("", _MIME_OCTET):
        name = (filename or "").lower()
        for ext, method in _EXT_FALLBACK.items():
            if name.endswith(ext):
                return method
    return None


def _decode_bytes(data_b64url: str | None) -> bytes:
    """Decode the download result's base64url `data` to raw bytes.

    Gmail (and download_attachment) return base64url with padding
    stripped, so we re-pad before decoding.
    """
    data = data_b64url or ""
    if not data:
        return b""
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _decode_text_bytes(raw: bytes) -> str:
    """Decode text/csv bytes to str, utf-8 with replacement on failure.

    The attachment is raw bytes (not a Gmail MIME part with a declared
    charset header), so we default to utf-8 with errors='replace' the
    same way message_text_parts._decode_part_text falls back. This never
    raises, matching the "never crash the read" contract.
    """
    return raw.decode("utf-8", errors="replace")


async def read_attachment_text(
    *,
    client: GmailClient,
    message_id: str,
    attachment_id: str | None = None,
    filename: str | None = None,
    part_index: int | None = None,
) -> dict[str, Any]:
    """Extract readable text from one attachment, selected like download_attachment.

    Output contract (success):
        {
            "filename": str | None,        # from the matched part
            "mime_type": str | None,       # from the matched part
            "extraction_method": str,      # "pdf" | "csv" | "xlsx" | "text"
            "text": str,                   # extracted text, capped
            "truncated": bool,             # True when the cap fired
        }

    Selection is identical to download_attachment: supply EXACTLY ONE of
    attachment_id / filename / part_index. Selector errors (none/multiple
    selectors, malformed id, not found, ambiguous filename) surface
    unchanged from download_attachment.

    Unsupported binary (images, unknown types) -> bad_request with
    error_data.kind == "unsupported" naming the mime_type; use
    download_attachment for raw bytes. A malformed/hostile file of a
    parsed type -> bad_request with error_data.kind == "extraction_failed";
    it never raises to -32603/500 and never hangs (the extractors are
    safe-wrapped, early-exit at the cap, and iteration-bounded).
    """
    # Reuse the selector + byte-fetch + metadata enrichment wholesale.
    result = await download_attachment(
        client=client,
        message_id=message_id,
        attachment_id=attachment_id,
        filename=filename,
        part_index=part_index,
    )
    # download_attachment returns an error dict (top-level int "code") on
    # any selector/fetch failure; pass it straight through unchanged.
    if isinstance(result.get("code"), int):
        return result

    att_filename = result.get("filename")
    att_mime = result.get("mime_type")
    method = _resolve_method(att_mime, att_filename)
    if method is None:
        return bad_request_error(
            f"cannot extract text from mime_type {att_mime!r}; "
            "use download_attachment for raw bytes",
            error_data={"kind": "unsupported", "mime_type": att_mime},
        )

    raw = _decode_bytes(result.get("data"))

    # xlsx signals a cell-budget abort out of band (its text may be under
    # the char cap yet still incomplete); OR that into the final truncated.
    budget_truncated = False
    try:
        if method == "pdf":
            text = extract_pdf_text(raw, max_chars=MAX_TEXT_CHARS)
        elif method == "xlsx":
            text, budget_truncated = extract_xlsx_text(raw, max_chars=MAX_TEXT_CHARS)
        elif method == "csv":
            text = extract_csv_text(_decode_text_bytes(raw), max_chars=MAX_TEXT_CHARS)
        else:  # "text"
            text = _decode_text_bytes(raw)
    except ExtractionError as exc:
        # Generic reason only; the extractor already logged it and never
        # attaches file content. The caller sees a typed extraction_failed.
        return bad_request_error(
            f"could not extract text from attachment: {exc}",
            error_data={"kind": "extraction_failed", "mime_type": att_mime},
        )

    capped, truncated = _cap_text(text)
    return {
        "filename": att_filename,
        "mime_type": att_mime,
        "extraction_method": method,
        "text": capped,
        "truncated": truncated or budget_truncated,
    }
