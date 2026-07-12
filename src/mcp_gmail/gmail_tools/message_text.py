"""Inbound plain-text extraction for the token-efficient read mode.

`read_email` and `get_thread` accept `format="text"`. Gmail has no
"text" format, so the tool layer fetches the message with Gmail's
`format="full"` and hands the raw message dict to
`extract_lean_message` here, which returns a SMALL object: curated
headers, the decoded plain-text body, and attachment metadata (no
bytes). The full payload, the HTML part, and inline base64 parts are
dropped entirely. That is the whole point: Amazon-style HTML receipts
run 170K-250K characters and blow past the MCP output token cap; the
lean shape is a few KB.

Body-selection rules
--------------------
Walk the payload parts recursively (bounded depth, see below):

1. Prefer the first `text/plain` part: decode its `body.data`
   (base64url) using the part's declared charset (from its
   Content-Type header; default utf-8, decode errors -> replace).
   `text_source == "text/plain"`.
2. If there is NO text/plain part, take the first `text/html` part,
   decode it the same way, and convert HTML -> readable text via
   markdownify (MIT; sensible defaults, scripts/styles stripped).
   `text_source == "text/html"`.
3. If neither exists (e.g. attachment-only), return `text == ""`
   with `text_source == "none"`.

This module owns its OWN parts-walk and attachment-metadata walk. It
deliberately does NOT import `attachment_download._enumerate_attachment_parts`
(private, `size`-less, and on the attachment path this feature must not
touch); the depth-guard PATTERN (bounded recursion against a
sender-influenced MIME tree) is reused, not the symbol.

Charset handling
----------------
Gmail returns each part's `mimeType` (e.g. "text/plain") but the
charset lives on the raw part headers as `Content-Type:
text/plain; charset="iso-8859-1"`. We read the part's `headers` list
for Content-Type and parse the charset param. Unknown/absent charset
-> utf-8. Any decode failure falls back to utf-8 with
`errors="replace"` so a mislabeled part never crashes the read.
"""

from __future__ import annotations

import base64
from email.message import Message
from typing import Any

from markdownify import markdownify as _md


# Maximum MIME nesting depth the walkers descend before stopping. The
# payload tree is sender-influenced, so an unbounded recursive walk over
# a pathologically deep message could raise RecursionError. 100 is far
# above any real Gmail message yet far below Python's default ~1000
# recursion limit. Mirrors the bounded-recursion guard pattern in
# attachment_download.py (the pattern is reused; the symbol is not).
_MAX_MIME_DEPTH = 100

# Curated header set surfaced in the lean shape. Match is
# case-insensitive against Gmail's payload.headers; the OUTPUT key uses
# the canonical casing below. Absent headers are OMITTED (no null
# placeholders) to keep the object lean.
_CURATED_HEADERS: tuple[str, ...] = (
    "From",
    "To",
    "Cc",
    "Bcc",
    "Subject",
    "Date",
    "Reply-To",
    "Message-ID",
)
_CURATED_LOOKUP: dict[str, str] = {h.lower(): h for h in _CURATED_HEADERS}


def _charset_from_part(part: dict[str, Any]) -> str:
    """Return the declared charset for a part, defaulting to utf-8.

    Gmail exposes the charset only on the raw `Content-Type` header
    (e.g. `text/plain; charset="iso-8859-1"`), not as a top-level
    field. We parse it with email.message.Message so quoted and
    unquoted param forms are both handled. Absent/blank -> "utf-8".
    """
    for h in part.get("headers") or []:
        if (h.get("name") or "").lower() == "content-type":
            probe = Message()
            probe["Content-Type"] = h.get("value") or ""
            charset = probe.get_content_charset()
            if charset:
                return charset
            break
    return "utf-8"


def _decode_part_text(part: dict[str, Any]) -> str:
    """Decode a text part's base64url `body.data` using its charset.

    base64url decode is padding-tolerant (Gmail strips padding). The
    bytes are decoded with the declared charset; ANY failure (unknown
    codec or invalid bytes for the codec) falls back to utf-8 with
    `errors="replace"` so a mislabeled part yields best-effort text
    rather than crashing the read.
    """
    data = ((part.get("body") or {}).get("data")) or ""
    if not data:
        return ""
    raw = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
    charset = _charset_from_part(part)
    try:
        return raw.decode(charset, errors="replace")
    except (LookupError, TypeError):
        # Unknown codec name (LookupError) or non-str charset: fall back.
        return raw.decode("utf-8", errors="replace")


def _find_body_parts(payload: dict[str, Any]) -> tuple[dict | None, dict | None]:
    """Depth-first preorder walk returning (first text/plain, first text/html).

    Returns the first text/plain part and the first text/html part
    encountered in document order (either may be None). Bounded at
    `_MAX_MIME_DEPTH`; a tree deeper than the guard simply stops
    descending that branch (no exception: the lean read degrades to
    whatever body it already found rather than failing).
    """
    plain: dict | None = None
    html: dict | None = None

    def _walk(part: dict[str, Any], depth: int) -> None:
        nonlocal plain, html
        if depth > _MAX_MIME_DEPTH or not isinstance(part, dict):
            return
        mime = (part.get("mimeType") or "").lower()
        if mime == "text/plain" and plain is None:
            plain = part
        elif mime == "text/html" and html is None:
            html = part
        for child in part.get("parts") or []:
            _walk(child, depth + 1)

    if isinstance(payload, dict):
        _walk(payload, 0)
    return plain, html


def _collect_attachments(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """Walk the payload and return attachment METADATA (no bytes).

    An entry is emitted for every part with a `body.attachmentId`
    (server-side downloadable reference), in document order. Each is
    `{filename, mime_type, size, attachment_id}`; `filename` is None
    for nameless inline parts (they remain reachable by attachment_id).
    Bounded at `_MAX_MIME_DEPTH`.
    """
    out: list[dict[str, Any]] = []

    def _walk(part: dict[str, Any], depth: int) -> None:
        if depth > _MAX_MIME_DEPTH or not isinstance(part, dict):
            return
        body = part.get("body") or {}
        attachment_id = body.get("attachmentId")
        if attachment_id:
            out.append(
                {
                    "filename": part.get("filename") or None,
                    "mime_type": part.get("mimeType"),
                    "size": body.get("size"),
                    "attachment_id": attachment_id,
                }
            )
        for child in part.get("parts") or []:
            _walk(child, depth + 1)

    if isinstance(payload, dict):
        _walk(payload, 0)
    return out


def _curate_headers(payload: dict[str, Any]) -> dict[str, str]:
    """Pull the curated header set from payload.headers (omit-if-absent).

    Case-insensitive match against Gmail's header names; the output key
    uses the canonical casing in `_CURATED_HEADERS`. Absent headers are
    omitted (no null placeholders). First occurrence wins if a header
    repeats.
    """
    out: dict[str, str] = {}
    for h in payload.get("headers") or []:
        name = (h.get("name") or "").lower()
        canonical = _CURATED_LOOKUP.get(name)
        if canonical and canonical not in out:
            value = h.get("value")
            if value is not None:
                out[canonical] = value
    return out


def _extract_text(payload: dict[str, Any]) -> tuple[str, str]:
    """Return (text, text_source) per the body-selection rules.

    Prefer text/plain; else text/html converted via markdownify; else
    ("", "none"). markdownify strips script/style content by default,
    producing legible body text from HTML receipts (the goal is
    readable text, not perfect markdown).
    """
    plain, html = _find_body_parts(payload)
    if plain is not None:
        return _decode_part_text(plain), "text/plain"
    if html is not None:
        raw_html = _decode_part_text(html)
        # markdownify with defaults; strip nothing extra beyond its
        # built-in script/style handling. `.strip()` trims the leading/
        # trailing whitespace markdownify tends to leave around blocks.
        return _md(raw_html).strip(), "text/html"
    return "", "none"


def extract_lean_message(message: dict[str, Any]) -> dict[str, Any]:
    """Reduce a Gmail `format="full"` message to the lean text shape.

    Returns:
        {
          "id", "threadId", "labelIds", "snippet",
          "headers": {curated present headers, canonical-cased},
          "text": "<decoded plain-text body>",
          "text_source": "text/plain" | "text/html" | "none",
          "attachments": [
            {"filename", "mime_type", "size", "attachment_id"}  # no bytes
          ]
        }

    The full payload, HTML part, and inline base64 are intentionally
    dropped: the lean object is a few KB even for a 200KB HTML receipt.
    """
    payload = message.get("payload") or {}
    text, text_source = _extract_text(payload)
    return {
        "id": message.get("id"),
        "threadId": message.get("threadId"),
        "labelIds": message.get("labelIds") or [],
        "snippet": message.get("snippet"),
        "headers": _curate_headers(payload),
        "text": text,
        "text_source": text_source,
        "attachments": _collect_attachments(payload),
    }
