"""Pure recipient-computation helpers for reply_all.

Extracted from reply.py (which sat at the 300-LOC ceiling) so the tool
body and its address-parsing primitives live in separate, reviewable
modules. These are pure functions over Gmail message payloads and header
strings: no I/O, no DB, no Gmail client. reply.py re-exports them, so
`reply._split_address_list` / `reply._extract_header` /
`reply._looks_like_email` keep resolving for existing callers and tests.
"""

from __future__ import annotations

from typing import Any


def split_address_list(value: str | None) -> list[str]:
    """Split a comma-separated address header into individual entries.

    RFC 5322 address lists are comma-separated and may include angle-
    bracketed forms ("Name <addr@host>"). For reply_all we only need
    the bare addresses. We extract the angle-bracketed value when
    present, otherwise use the trimmed value. Empty or None header
    yields an empty list.
    """
    if not value:
        return []
    out: list[str] = []
    for piece in value.split(","):
        piece = piece.strip()
        if not piece:
            continue
        if "<" in piece and ">" in piece:
            start = piece.find("<")
            end = piece.find(">", start)
            if end > start:
                bare = piece[start + 1 : end].strip()
                if bare:
                    out.append(bare)
                    continue
        out.append(piece)
    return out


def extract_header(message: dict[str, Any], name: str) -> str | None:
    """Return the value of header `name` from a Gmail message payload, or None.

    Gmail's `payload.headers` is a list of {name, value} dicts. The
    name match is case-insensitive per RFC 5322. Returns the first
    match; duplicate header names (legal for some headers) are
    ignored beyond the first.
    """
    payload = message.get("payload")
    if not isinstance(payload, dict):
        return None
    headers = payload.get("headers")
    if not isinstance(headers, list):
        return None
    target = name.lower()
    for h in headers:
        if not isinstance(h, dict):
            continue
        hname = h.get("name")
        if isinstance(hname, str) and hname.lower() == target:
            v = h.get("value")
            return v if isinstance(v, str) else None
    return None


def looks_like_email(addr: str) -> bool:
    """Cheap syntactic check: exactly one @ with non-empty local + domain.

    Not RFC-complete (Gmail rejects malformed addresses anyway); this
    only fails fast on obvious caller bugs. Control-char-bearing
    addresses are rejected separately at build time by
    message_format.is_safe_header_value.
    """
    if not isinstance(addr, str):
        return False
    if addr.count("@") != 1:
        return False
    local, _, domain = addr.partition("@")
    return bool(local) and bool(domain)
