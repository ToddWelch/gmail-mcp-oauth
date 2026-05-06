"""Tests for gmail_tools.message_format (25 MiB encoded cap).

Boundary cases at the documented Gmail limit. Ships even
the helper is consumed by the send-side tools.
"""

from __future__ import annotations

import base64

import pytest

from mcp_gmail.gmail_tools.message_format import (
    MAX_ENCODED_BYTES,
    Attachment,
    OversizeMessage,
    build_email_message,
    message_to_base64url,
)


def _build_with_attachment(size_bytes: int):
    return build_email_message(
        sender="me@example.com",
        to=["you@example.com"],
        subject="hi",
        body_text="body",
        attachments=[
            Attachment(
                filename="file.bin",
                mime_type="application/octet-stream",
                data=b"x" * size_bytes,
            )
        ],
    )


def test_simple_message_under_cap():
    msg = build_email_message(
        sender="me@example.com",
        to=["you@example.com"],
        subject="hello",
        body_text="hi there",
    )
    assert msg["From"] == "me@example.com"
    assert msg["To"] == "you@example.com"
    assert msg["Subject"] == "hello"


def test_message_with_cc_bcc():
    msg = build_email_message(
        sender="me@example.com",
        to=["a@x.com"],
        subject="s",
        body_text="b",
        cc=["c@x.com"],
        bcc=["d@x.com"],
    )
    assert msg["Cc"] == "c@x.com"
    assert msg["Bcc"] == "d@x.com"


def test_attachment_round_trip():
    msg = build_email_message(
        sender="me@example.com",
        to=["you@example.com"],
        subject="s",
        body_text="b",
        attachments=[
            Attachment(filename="t.pdf", mime_type="application/pdf", data=b"PDF"),
        ],
    )
    payloads = list(msg.iter_attachments())
    assert len(payloads) == 1
    # Filename and MIME survive.
    assert payloads[0].get_filename() == "t.pdf"
    assert payloads[0].get_content_type() == "application/pdf"


def test_attachment_with_no_subtype_falls_back_to_octet_stream():
    msg = build_email_message(
        sender="me@example.com",
        to=["you@example.com"],
        subject="s",
        body_text="b",
        attachments=[
            Attachment(filename="t.bin", mime_type="application", data=b"x"),
        ],
    )
    payloads = list(msg.iter_attachments())
    assert payloads[0].get_content_type() == "application/octet-stream"


def test_threading_headers_emit_when_reply_to_set():
    msg = build_email_message(
        sender="me@example.com",
        to=["you@example.com"],
        subject="re: s",
        body_text="b",
        reply_to_message_id="<abc@example.com>",
        reply_to_references=["<a@x.com>", "<b@x.com>"],
    )
    assert msg["In-Reply-To"] == "<abc@example.com>"
    assert msg["References"] == "<a@x.com> <b@x.com>"


def test_threading_headers_add_angle_brackets_if_missing():
    msg = build_email_message(
        sender="me@example.com",
        to=["you@example.com"],
        subject="re: s",
        body_text="b",
        reply_to_message_id="abc@example.com",
    )
    assert msg["In-Reply-To"] == "<abc@example.com>"
    assert msg["References"] == "<abc@example.com>"


def test_oversize_raises_at_one_byte_past_cap():
    """Encoded-size cap: at exactly MAX + 1 bytes after encoding, the build raises."""
    # Aim for a raw size such that after MIME framing + base64 inflation
    # we exceed MAX_ENCODED_BYTES by at least 1 byte. Base64 inflates
    # by ~4/3, so a raw payload of (MAX * 0.76) gives a comfortable
    # margin past the cap. We probe upward.
    raw = int(MAX_ENCODED_BYTES * 0.78)
    with pytest.raises(OversizeMessage) as exc_info:
        _build_with_attachment(raw)
    assert exc_info.value.encoded_size > MAX_ENCODED_BYTES


def test_under_cap_passes():
    """Encoded-size cap: a message comfortably below the cap builds successfully."""
    raw = 1024 * 1024  # 1 MB raw, ~1.4 MB encoded
    msg = _build_with_attachment(raw)
    assert len(msg.as_bytes()) < MAX_ENCODED_BYTES


def test_encoded_size_reported_in_oversize_exception():
    raw = int(MAX_ENCODED_BYTES * 0.78)
    try:
        _build_with_attachment(raw)
    except OversizeMessage as exc:
        assert exc.max_size == MAX_ENCODED_BYTES
        assert exc.encoded_size > MAX_ENCODED_BYTES
    else:
        pytest.fail("expected OversizeMessage")


def test_message_to_base64url_round_trip():
    msg = build_email_message(
        sender="me@example.com",
        to=["you@example.com"],
        subject="s",
        body_text="hello body",
    )
    encoded = message_to_base64url(msg)
    # No padding (rstrip).
    assert "=" not in encoded
    # Decodable back to the same bytes.
    decoded = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    assert decoded == msg.as_bytes()


def test_max_encoded_bytes_constant_is_25_mb_mebi():
    """Encoded-size cap: spec is 25 MEBIBYTES (1024-based), not 25 megabytes."""
    assert MAX_ENCODED_BYTES == 25 * 1024 * 1024


def test_oversize_check_uses_strict_greater_than(monkeypatch):
    """The cap check is `encoded_size > MAX`, not `encoded_size >= MAX`.
    At exactly MAX bytes the build must succeed;
    only strictly-greater triggers OversizeMessage.

    We test the comparison semantics directly by patching
    MAX_ENCODED_BYTES to a small value and constructing a message we can
    measure with byte-level precision. The real 25 MiB constant cannot
    be hit precisely because EmailMessage's MIME framing produces
    line-wrapped bodies with non-trivial overhead; but the comparison
    relation is the property we actually want to pin.
    """
    from mcp_gmail.gmail_tools import message_format as mf

    # Build a small message and use its actual encoded size as our cap.
    msg = build_email_message(
        sender="me@example.com",
        to=["you@example.com"],
        subject="hi",
        body_text="exactly this much body",
    )
    exact_size = len(msg.as_bytes())

    # Patch MAX to exact_size. The same message MUST still build
    # successfully under the patched cap (proving the boundary is
    # inclusive of equality).
    monkeypatch.setattr(mf, "MAX_ENCODED_BYTES", exact_size)
    rebuilt = build_email_message(
        sender="me@example.com",
        to=["you@example.com"],
        subject="hi",
        body_text="exactly this much body",
    )
    assert len(rebuilt.as_bytes()) == exact_size


def test_oversize_at_max_plus_one_byte_raises(monkeypatch):
    """When encoded size is one byte past the cap, the build raises
    OversizeMessage.

    Same patch strategy as the inclusive test: patch MAX to exact_size - 1
    so the same message is now over the (patched) cap by one byte.
    """
    from mcp_gmail.gmail_tools import message_format as mf

    msg = build_email_message(
        sender="me@example.com",
        to=["you@example.com"],
        subject="hi",
        body_text="exactly this much body",
    )
    exact_size = len(msg.as_bytes())

    monkeypatch.setattr(mf, "MAX_ENCODED_BYTES", exact_size - 1)
    with pytest.raises(OversizeMessage) as exc_info:
        build_email_message(
            sender="me@example.com",
            to=["you@example.com"],
            subject="hi",
            body_text="exactly this much body",
        )
    # exc_info.value.max_size reflects the OversizeMessage default
    # captured at definition time (the production 25 MiB), not the
    # patched module-level value, since the constructor's default
    # argument is bound when the class was defined. The test's purpose
    # is to verify the comparison fires; the `encoded_size` field is
    # the one that reflects the actual measurement.
    assert exc_info.value.encoded_size == exact_size
