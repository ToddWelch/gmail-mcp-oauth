"""Low-level MIME-parsing primitives for the token-efficient read mode.

Extracted from message_text.py under the 300-LOC / distinct-
responsibility hard rule. message_text.py owns the public lean-shape
orchestration (extract_lean_message, safe_extract_lean_message, the
markdownify HTML fallback, the text cap); THIS module owns the raw
walk + decode primitives it composes:

- `_charset_from_part` / `_decode_part_text`: charset resolution and
  base64url body decode (default utf-8, decode errors replaced).
- `_find_body_parts`: bounded recursive walk returning the first
  text/plain and first text/html parts.
- `_collect_attachments`: bounded recursive walk returning attachment
  metadata (no bytes).
- `_curate_headers`: pull the curated present-only header set.

These are internal helpers (underscore-prefixed) imported by
message_text.py; the public entry points stay in message_text.py so
`from .message_text import extract_lean_message` is unchanged.

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
