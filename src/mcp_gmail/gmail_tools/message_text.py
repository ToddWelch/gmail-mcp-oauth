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
Walk the payload parts recursively (bounded depth):

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

The low-level walk + decode primitives live in message_text_parts.py
(split out under the 300-LOC / distinct-responsibility rule); this
module owns the public lean-shape orchestration: the markdownify HTML
fallback (which must never crash the read), the defensive text cap, and
the per-message fault isolation used by get_thread. This module owns its
OWN parts-walk (in message_text_parts) and does NOT touch the attachment
download path.

Robustness contract
-------------------
extract_lean_message NEVER raises on hostile input:
- Hostile MIME nesting is bounded by the depth guards in
  message_text_parts.
- Hostile HTML (deeply-nested DOM that makes markdownify recurse, or any
  bs4/markdownify parse failure) is caught and degrades to empty text
  while keeping text_source='text/html'.
- A pathological multi-MB text body is capped at MAX_TEXT_CHARS.
safe_extract_lean_message adds per-message fault isolation for the
thread walk so one bad message cannot fail the whole get_thread read.
"""

from __future__ import annotations

import logging
from typing import Any

from markdownify import markdownify as _md

from .message_text_parts import (
    _collect_attachments,
    _curate_headers,
    _decode_part_text,
    _find_body_parts,
)

logger = logging.getLogger(__name__)


# Defensive cap on the FINAL `text` field (from text/plain or converted
# HTML). format='text' exists to keep output under the MCP token cap;
# without a length ceiling a pathological multi-MB text/plain body would
# defeat that. Normal receipts are a few KB, well under this. Over the
# cap, `text` is truncated and a marker is appended; `text_truncated` is
# set True on the lean object. Todd can tune this default later.
MAX_TEXT_CHARS = 100_000

_TRUNCATION_MARKER = (
    "\n\n[text truncated: {omitted} characters omitted; use format=full "
    "or download the message for the full body]"
)


def _cap_text(text: str) -> tuple[str, bool]:
    """Apply MAX_TEXT_CHARS to the final text. Returns (text, truncated).

    Under the cap the text is returned unchanged with truncated=False.
    Over the cap it is truncated to MAX_TEXT_CHARS and the marker
    (naming the omitted-character count) is appended; truncated=True.
    """
    if len(text) <= MAX_TEXT_CHARS:
        return text, False
    omitted = len(text) - MAX_TEXT_CHARS
    return text[:MAX_TEXT_CHARS] + _TRUNCATION_MARKER.format(omitted=omitted), True


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
        # markdownify walks the HTML DOM recursively (one stack frame per
        # node), so pathologically-nested hostile HTML can raise
        # RecursionError; the depth guards in message_text_parts bound the
        # MIME-parts tree, NOT HTML-DOM depth. Any bs4/markdownify parse
        # failure on hostile HTML must not crash the read (this module's
        # contract is "never crashes the read"). Degrade to empty text
        # while keeping text_source='text/html' so the caller still learns
        # HTML was present but could not be converted. RecursionError is
        # caught explicitly (a bare `Exception` would miss it). The HTML
        # content is NEVER logged (no PII on the wire).
        try:
            # `.strip()` trims the leading/trailing whitespace markdownify
            # tends to leave around blocks.
            return _md(raw_html).strip(), "text/html"
        except RecursionError:
            logger.warning("markdownify RecursionError on hostile HTML; degrading to empty text")
            return "", "text/html"
        except Exception:  # noqa: BLE001 - hostile-HTML parse failures must not crash the read
            logger.warning("markdownify failed to convert HTML; degrading to empty text")
            return "", "text/html"
    return "", "none"


def extract_lean_message(message: dict[str, Any]) -> dict[str, Any]:
    """Reduce a Gmail `format="full"` message to the lean text shape.

    Returns:
        {
          "id", "threadId", "labelIds", "snippet",
          "headers": {curated present headers, canonical-cased},
          "text": "<decoded plain-text body>",
          "text_source": "text/plain" | "text/html" | "none",
          "text_truncated": true,   # ONLY present when the cap fired
          "attachments": [
            {"filename", "mime_type", "size", "attachment_id"}  # no bytes
          ]
        }

    The full payload, HTML part, and inline base64 are intentionally
    dropped: the lean object is a few KB even for a 200KB HTML receipt.
    The final `text` is capped at MAX_TEXT_CHARS (truncated with a
    marker + `text_truncated: true`) so the output stays manageable even
    for a pathological multi-MB text/plain body. `text_truncated` is
    omitted when the text is within the cap.
    """
    payload = message.get("payload") or {}
    text, text_source = _extract_text(payload)
    text, truncated = _cap_text(text)
    lean: dict[str, Any] = {
        "id": message.get("id"),
        "threadId": message.get("threadId"),
        "labelIds": message.get("labelIds") or [],
        "snippet": message.get("snippet"),
        "headers": _curate_headers(payload),
        "text": text,
        "text_source": text_source,
        "attachments": _collect_attachments(payload),
    }
    if truncated:
        lean["text_truncated"] = True
    return lean


def safe_extract_lean_message(message: dict[str, Any]) -> dict[str, Any]:
    """Fault-isolated `extract_lean_message` for the per-message thread walk.

    extract_lean_message is already non-raising on hostile HTML (see
    _extract_text) and on hostile MIME nesting (the depth guards), so
    this wrapper is defense-in-depth: ANY unexpected per-message failure
    degrades THAT message to a minimal lean entry instead of failing the
    whole get_thread read. One malformed message in a thread must not
    -32603 the entire thread. The message content is NEVER logged.
    """
    try:
        return extract_lean_message(message)
    except Exception:  # noqa: BLE001 - one bad message must not fail the whole thread read
        logger.warning("extract_lean_message failed for a thread message; degrading that entry")
        return {
            "id": message.get("id") if isinstance(message, dict) else None,
            "threadId": message.get("threadId") if isinstance(message, dict) else None,
            "labelIds": [],
            "snippet": None,
            "headers": {},
            "text": "",
            "text_source": "none",
            "attachments": [],
        }
