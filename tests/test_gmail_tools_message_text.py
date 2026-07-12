"""Unit tests for message_text.extract_lean_message (the format='text' core).

These hit the pure helper directly with Gmail-shaped payload dicts (no
HTTP): body selection (text/plain preferred over text/html), the
markdownify HTML->text fallback, the no-body/attachment-only branch,
charset handling (iso-8859-1 + decode-error replace), attachment
metadata (no bytes), nested multipart walking, and the core
size-regression guard (a ~200KB HTML part yields a small lean output).
"""

from __future__ import annotations

import base64

from mcp_gmail.gmail_tools.message_text import extract_lean_message


def _b64url(text: str, charset: str = "utf-8") -> str:
    """Encode text the way Gmail encodes body.data: base64url, no padding."""
    raw = text.encode(charset)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_bytes(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _headers(*pairs: tuple[str, str]) -> list[dict]:
    return [{"name": n, "value": v} for n, v in pairs]


# ---------------------------------------------------------------------------
# Body selection: text/plain preferred + SIZE REGRESSION GUARD
# ---------------------------------------------------------------------------


def test_multipart_alternative_prefers_plain_and_output_is_small():
    """Core regression guard for the reported problem: a multipart/
    alternative with a small text/plain and a ~200KB text/html returns
    the text/plain body, and the lean output is a few KB (no HTML/base64
    blob passes through)."""
    plain_body = "Your order #123 total $42.00. Thanks for shopping."
    big_html = "<html><body>" + ("<div>filler receipt row</div>" * 8000) + "</body></html>"
    assert len(big_html) > 200_000  # the bloated part the bug is about

    message = {
        "id": "M1",
        "threadId": "T1",
        "labelIds": ["INBOX"],
        "snippet": "Your order #123",
        "payload": {
            "mimeType": "multipart/alternative",
            "headers": _headers(("Subject", "Your order"), ("From", "amazon@example.com")),
            "parts": [
                {
                    "mimeType": "text/plain",
                    "headers": _headers(("Content-Type", "text/plain; charset=utf-8")),
                    "body": {"size": len(plain_body), "data": _b64url(plain_body)},
                },
                {
                    "mimeType": "text/html",
                    "headers": _headers(("Content-Type", "text/html; charset=utf-8")),
                    "body": {"size": len(big_html), "data": _b64url(big_html)},
                },
            ],
        },
    }

    lean = extract_lean_message(message)

    assert lean["text_source"] == "text/plain"
    assert lean["text"] == plain_body
    assert lean["headers"] == {"Subject": "Your order", "From": "amazon@example.com"}
    assert lean["attachments"] == []
    # The whole point: no HTML/base64 blob leaks. The serialized lean
    # object must be a few KB even though the source HTML was >200KB.
    import json

    serialized = json.dumps(lean)
    assert len(serialized) < 4_000
    assert "filler receipt row" not in serialized
    assert big_html not in serialized


# ---------------------------------------------------------------------------
# HTML-only fallback via markdownify
# ---------------------------------------------------------------------------


def test_html_only_converts_via_markdownify():
    """No text/plain part -> take text/html, convert to readable text,
    text_source == 'text/html'. markdownify strips script/style."""
    html = (
        "<html><head><style>.x{color:red}</style>"
        "<script>track()</script></head>"
        "<body><h1>Receipt</h1><p>Total: <b>$9.99</b></p></body></html>"
    )
    message = {
        "id": "M2",
        "threadId": "T2",
        "payload": {
            "mimeType": "text/html",
            "headers": _headers(("Content-Type", "text/html; charset=utf-8")),
            "body": {"size": len(html), "data": _b64url(html)},
        },
    }

    lean = extract_lean_message(message)

    assert lean["text_source"] == "text/html"
    assert "Receipt" in lean["text"]
    assert "$9.99" in lean["text"]
    # script/style content must not survive.
    assert "track()" not in lean["text"]
    assert "color:red" not in lean["text"]


# ---------------------------------------------------------------------------
# No body (attachment-only)
# ---------------------------------------------------------------------------


def test_attachment_only_has_empty_text_and_metadata():
    """No text/plain or text/html -> text == '' , text_source == 'none',
    attachment metadata present (no bytes)."""
    message = {
        "id": "M3",
        "threadId": "T3",
        "labelIds": [],
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": _headers(("Subject", "Invoice attached")),
            "parts": [
                {
                    "mimeType": "application/pdf",
                    "filename": "invoice.pdf",
                    "body": {"attachmentId": "ATTACH_PDF_000001", "size": 5120},
                },
            ],
        },
    }

    lean = extract_lean_message(message)

    assert lean["text"] == ""
    assert lean["text_source"] == "none"
    assert lean["attachments"] == [
        {
            "filename": "invoice.pdf",
            "mime_type": "application/pdf",
            "size": 5120,
            "attachment_id": "ATTACH_PDF_000001",
        }
    ]
    # No bytes field anywhere in the attachment metadata.
    assert "data" not in lean["attachments"][0]


# ---------------------------------------------------------------------------
# Charset handling
# ---------------------------------------------------------------------------


def test_iso_8859_1_charset_decodes_correctly():
    """A text/plain part declared iso-8859-1 decodes with that charset."""
    body = "Café façade naïve"  # non-ASCII chars valid in latin-1
    message = {
        "id": "M4",
        "payload": {
            "mimeType": "text/plain",
            "headers": _headers(("Content-Type", 'text/plain; charset="iso-8859-1"')),
            "body": {"data": _b64url(body, charset="iso-8859-1")},
        },
    }

    lean = extract_lean_message(message)

    assert lean["text"] == body
    assert lean["text_source"] == "text/plain"


def test_decode_error_falls_back_to_replace_without_crashing():
    """Bytes invalid for the declared charset do not crash; errors are
    replaced. utf-8-declared part carrying a raw 0xFF byte -> replacement
    char, no exception."""
    raw = "hello ".encode("utf-8") + b"\xff\xfe" + " world".encode("utf-8")
    message = {
        "id": "M5",
        "payload": {
            "mimeType": "text/plain",
            "headers": _headers(("Content-Type", "text/plain; charset=utf-8")),
            "body": {"data": _b64url_bytes(raw)},
        },
    }

    lean = extract_lean_message(message)

    assert lean["text_source"] == "text/plain"
    assert "hello" in lean["text"]
    assert "world" in lean["text"]
    assert "�" in lean["text"]  # replacement char present


def test_unknown_charset_falls_back_to_utf8():
    """An unknown/bogus charset name does not crash; falls back to utf-8."""
    body = "plain ascii body"
    message = {
        "id": "M6",
        "payload": {
            "mimeType": "text/plain",
            "headers": _headers(("Content-Type", "text/plain; charset=not-a-real-charset")),
            "body": {"data": _b64url(body)},
        },
    }

    lean = extract_lean_message(message)

    assert lean["text"] == body


def test_missing_content_type_defaults_to_utf8():
    """A text/plain part with no Content-Type header defaults to utf-8."""
    body = "no content-type header here"
    message = {
        "id": "M7",
        "payload": {
            "mimeType": "text/plain",
            "body": {"data": _b64url(body)},
        },
    }

    lean = extract_lean_message(message)

    assert lean["text"] == body
    assert lean["text_source"] == "text/plain"


def test_content_type_present_without_charset_param_defaults_to_utf8():
    """A text/plain part whose Content-Type header carries no charset
    param (e.g. just 'text/plain') defaults to utf-8. Covers the
    charset-parse 'present header, no charset param' branch."""
    body = "content-type but no charset"
    message = {
        "id": "M12",
        "payload": {
            "mimeType": "text/plain",
            "headers": _headers(("Content-Type", "text/plain")),
            "body": {"data": _b64url(body)},
        },
    }

    lean = extract_lean_message(message)

    assert lean["text"] == body
    assert lean["text_source"] == "text/plain"


def test_empty_body_data_returns_empty_text():
    """A text/plain part with an empty body.data yields empty text (the
    decode early-return), still text_source == 'text/plain'."""
    message = {
        "id": "M13",
        "payload": {
            "mimeType": "text/plain",
            "headers": _headers(("Content-Type", "text/plain; charset=utf-8")),
            "body": {"size": 0, "data": ""},
        },
    }

    lean = extract_lean_message(message)

    assert lean["text"] == ""
    assert lean["text_source"] == "text/plain"


# ---------------------------------------------------------------------------
# Nested multipart walking
# ---------------------------------------------------------------------------


def test_nested_multipart_mixed_containing_alternative_is_walked():
    """multipart/mixed -> multipart/alternative(text/plain + text/html)
    plus a sibling attachment: the nested text/plain is found and the
    attachment metadata is collected."""
    plain = "Nested plain body wins."
    html = "<p>nested html</p>"
    message = {
        "id": "M8",
        "threadId": "T8",
        "payload": {
            "mimeType": "multipart/mixed",
            "headers": _headers(("Subject", "Nested")),
            "parts": [
                {
                    "mimeType": "multipart/alternative",
                    "body": {},
                    "parts": [
                        {
                            "mimeType": "text/plain",
                            "headers": _headers(("Content-Type", "text/plain; charset=utf-8")),
                            "body": {"data": _b64url(plain)},
                        },
                        {
                            "mimeType": "text/html",
                            "headers": _headers(("Content-Type", "text/html; charset=utf-8")),
                            "body": {"data": _b64url(html)},
                        },
                    ],
                },
                {
                    "mimeType": "image/png",
                    "filename": "logo.png",
                    "body": {"attachmentId": "ATTACH_PNG_000002", "size": 777},
                },
            ],
        },
    }

    lean = extract_lean_message(message)

    assert lean["text"] == plain
    assert lean["text_source"] == "text/plain"
    assert lean["attachments"] == [
        {
            "filename": "logo.png",
            "mime_type": "image/png",
            "size": 777,
            "attachment_id": "ATTACH_PNG_000002",
        }
    ]


def test_nameless_inline_attachment_keeps_null_filename():
    """An inline part with an attachmentId but no filename is enumerated
    with filename == None (reachable by attachment_id)."""
    message = {
        "id": "M9",
        "payload": {
            "mimeType": "multipart/related",
            "parts": [
                {
                    "mimeType": "image/gif",
                    "body": {"attachmentId": "INLINE_NOFILENAME_1", "size": 12},
                },
            ],
        },
    }

    lean = extract_lean_message(message)

    assert lean["attachments"] == [
        {
            "filename": None,
            "mime_type": "image/gif",
            "size": 12,
            "attachment_id": "INLINE_NOFILENAME_1",
        }
    ]


def test_pathologically_deep_mime_tree_does_not_crash():
    """A MIME tree deeper than the depth guard degrades gracefully (no
    RecursionError); it simply stops descending that branch."""
    node: dict = {"mimeType": "text/plain", "body": {"data": _b64url("deep")}}
    for _ in range(300):  # far beyond _MAX_MIME_DEPTH (100)
        node = {"mimeType": "multipart/mixed", "body": {}, "parts": [node]}
    message = {"id": "M10", "payload": node}

    lean = extract_lean_message(message)

    # No exception. The deep text/plain is below the guard, so no body
    # is found and the branch degrades to text_source == 'none'.
    assert lean["text_source"] == "none"
    assert lean["text"] == ""


def test_curated_headers_omit_absent_and_are_case_insensitive():
    """Only present curated headers are emitted, canonical-cased, matched
    case-insensitively; non-curated headers (Received/DKIM) are dropped."""
    message = {
        "id": "M11",
        "payload": {
            "mimeType": "text/plain",
            "headers": _headers(
                ("from", "a@example.com"),
                ("SUBJECT", "Hi"),
                ("Message-Id", "<abc@example.com>"),
                ("Received", "from mx.example.com by ..."),
                ("DKIM-Signature", "v=1; a=rsa-sha256; ..."),
            ),
            "body": {"data": _b64url("body")},
        },
    }

    lean = extract_lean_message(message)

    assert lean["headers"] == {
        "From": "a@example.com",
        "Subject": "Hi",
        "Message-ID": "<abc@example.com>",
    }
    assert "Received" not in lean["headers"]
    assert "DKIM-Signature" not in lean["headers"]
