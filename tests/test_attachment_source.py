"""Tests for attachment_source.load_attachments / consume_slots + the schema.

Consume-after-build: the oversize gate is the EXACT rendered
build_email_message().as_bytes() size, not an estimate. These tests are
non-vacuous - they build the real message and assert that an oversize
set (from attachment size, RFC 2231 emoji filenames, a non-ASCII body,
or large recipient/References headers) is rejected at build with the
upload slots STILL consumable, while legitimate sends consume and work.
Also covers byte-for-byte integrity, ownership scoping, single-use, the
raw-sum decrypt-memory gate, and the oneOf discrimination.
"""

from __future__ import annotations

import base64

import pytest

from mcp_gmail import attachment_upload_store as store
from mcp_gmail import config as config_module
from mcp_gmail import db as db_module
from mcp_gmail.crypto import encrypt_bytes
from mcp_gmail.db import Base
from mcp_gmail.gmail_tools import attachment_source
from mcp_gmail.gmail_tools._schema_validator import validate_arguments
from mcp_gmail.gmail_tools.attachment_source import (
    EFFECTIVE_MAX_ATTACHMENT_BYTES,
    consume_slots,
    load_attachments,
)
from mcp_gmail.gmail_tools.errors import ToolErrorCode
from mcp_gmail.gmail_tools.message_format import (
    MAX_ENCODED_BYTES,
    OversizeMessage,
    build_email_message,
)

SUB = "auth0|alice"
EMAIL = "alice@example.com"
# High-bit bytes across the full 0..255 range so any utf-8 round-tripping
# in the storage path would corrupt them (the barcode guarantee).
PAYLOAD = bytes(range(256)) * 128  # 32 KiB, not valid utf-8


@pytest.fixture(autouse=True)
def _engine():
    db_module.reset_for_tests()
    engine = db_module.init_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    yield
    db_module.reset_for_tests()


def _enc_key() -> str:
    return config_module.load().encryption_key


def _upload_slot(
    payload: bytes = PAYLOAD,
    *,
    filename: str = "label.pdf",
    mime: str = "application/pdf",
    sub: str = SUB,
    email: str = EMAIL,
    size_override: int | None = None,
) -> str:
    with db_module.session_scope() as session:
        token, _ = store.create_slot(session, auth0_sub=sub, account_email=email)
        store.finalize_upload(
            session,
            token_hash=store.hash_token(token),
            encrypted=encrypt_bytes(payload, _enc_key()),
            size_bytes=size_override if size_override is not None else len(payload),
            filename=filename,
            mime_type=mime,
        )
    return token


def _load(raw, *, sub: str = SUB, email: str = EMAIL, key: object = "default"):
    return load_attachments(
        raw=raw,
        auth0_sub=sub,
        account_email=email,
        encryption_key=_enc_key() if key == "default" else key,
        prior_encryption_keys=(),
    )


def _resolve(raw, *, sub: str = SUB, email: str = EMAIL, key: object = "default"):
    """load + (if ok) consume; returns list[Attachment] or an error dict."""
    loaded = _load(raw, sub=sub, email=email, key=key)
    if isinstance(loaded, dict):
        return loaded
    atts, tokens = loaded
    err = consume_slots(token_hashes=tokens, auth0_sub=sub, account_email=email)
    return err if err is not None else atts


def _attempt(atts, tokens, *, to=None, subject="s", body_text="b", cc=None) -> str:
    """Mimic the handler: build (exact-size gate) then consume before POST."""
    try:
        build_email_message(
            sender=EMAIL,
            to=to or [EMAIL],
            subject=subject,
            body_text=body_text,
            cc=cc,
            attachments=atts or None,
        )
    except OversizeMessage:
        return "oversize"  # NO consume ran
    err = consume_slots(token_hashes=tokens, auth0_sub=SUB, account_email=EMAIL)
    return "race" if err is not None else "sent"


def _still_consumable(token: str) -> bool:
    with db_module.session_scope() as session:
        return (
            store.load_for_consume(
                session, token_hash=store.hash_token(token), auth0_sub=SUB, account_email=EMAIL
            )
            is not None
        )


def _base_send_args(attachments):
    return {
        "account_email": EMAIL,
        "sender": EMAIL,
        "to": [EMAIL],
        "subject": "s",
        "body_text": "b",
        "attachments": attachments,
    }


# --- schema boundary (oneOf enforced at dispatch) --------------------------


def test_schema_boundary_accepts_each_branch():
    inline = {"filename": "a.txt", "mime_type": "text/plain", "data_base64url": "aGk"}
    upload = {"source": "upload", "upload_token": "A" * 32}
    assert validate_arguments("send_email", _base_send_args([inline])) is None
    assert validate_arguments("send_email", _base_send_args([upload])) is None


def test_schema_boundary_rejects_both_and_neither_shapes():
    both = {
        "filename": "a.txt",
        "mime_type": "text/plain",
        "data_base64url": "aGk",
        "source": "upload",
        "upload_token": "A" * 32,
    }
    neither = {"filename": "a.txt"}
    assert validate_arguments("send_email", _base_send_args([both])) is not None
    assert validate_arguments("send_email", _base_send_args([neither])) is not None


# --- load + consume (non-oversize) -----------------------------------------


def test_inline_only_needs_no_key():
    data_b64 = base64.urlsafe_b64encode(b"hello").rstrip(b"=").decode()
    result = _resolve(
        [{"filename": "h.txt", "mime_type": "text/plain", "data_base64url": data_b64}], key=None
    )
    assert isinstance(result, list)
    assert result[0].data == b"hello"


def test_upload_is_byte_for_byte_and_consumes():
    token = _upload_slot()
    result = _resolve([{"source": "upload", "upload_token": token}])
    assert isinstance(result, list)
    assert result[0].data == PAYLOAD  # barcode guarantee
    assert result[0].filename == "label.pdf"
    assert result[0].mime_type == "application/pdf"
    assert not _still_consumable(token)  # consumed


def test_mixed_inline_and_upload_preserves_order():
    token = _upload_slot(b"UPLOADED", filename="u.bin", mime="application/octet-stream")
    inline_b64 = base64.urlsafe_b64encode(b"INLINE").rstrip(b"=").decode()
    result = _resolve(
        [
            {"filename": "i.txt", "mime_type": "text/plain", "data_base64url": inline_b64},
            {"source": "upload", "upload_token": token},
        ]
    )
    assert [a.data for a in result] == [b"INLINE", b"UPLOADED"]


def test_filename_and_mime_override():
    token = _upload_slot()
    result = _resolve([{"source": "upload", "upload_token": token, "filename": "renamed.pdf"}])
    assert result[0].filename == "renamed.pdf"


def test_wrong_user_rejected_and_slot_untouched():
    token = _upload_slot()  # owned by SUB
    result = _resolve([{"source": "upload", "upload_token": token}], sub="auth0|eve")
    assert result["code"] == ToolErrorCode.BAD_REQUEST
    assert _still_consumable(token)  # true owner's slot not touched


def test_expired_rejected():
    from datetime import datetime, timedelta, timezone

    token = _upload_slot()
    with db_module.session_scope() as session:
        store.find_slot(session, store.hash_token(token)).expires_at = datetime.now(
            timezone.utc
        ) - timedelta(minutes=1)
    result = _resolve([{"source": "upload", "upload_token": token}])
    assert result["code"] == ToolErrorCode.BAD_REQUEST


def test_replay_after_consume_rejected():
    token = _upload_slot()
    assert isinstance(_resolve([{"source": "upload", "upload_token": token}]), list)
    assert (
        _resolve([{"source": "upload", "upload_token": token}])["code"] == ToolErrorCode.BAD_REQUEST
    )


def test_consume_race_rolls_back(monkeypatch):
    token = _upload_slot()
    monkeypatch.setattr(store, "consume", lambda *a, **k: False)
    result = _resolve([{"source": "upload", "upload_token": token}])
    assert result["code"] == ToolErrorCode.BAD_REQUEST
    monkeypatch.undo()
    assert _still_consumable(token)  # rolled back, still usable


def test_classify_backstop_rejects_ambiguous_and_neither():
    both = {"data_base64url": "aGk", "source": "upload", "upload_token": "A" * 20}
    neither = {"filename": "x"}
    assert isinstance(attachment_source._classify(both, index=0), dict)
    assert isinstance(attachment_source._classify(neither, index=0), dict)
    assert attachment_source._classify({"source": "upload", "upload_token": "A" * 20}, index=0) == (
        "upload"
    )


# --- oversize rejected at BUILD (exact render), slots intact ----------------


def test_co_exploit_ten_emoji_parts_rejected_pre_consume_slots_intact():
    # CO's exact exploit: 10 upload parts * 1,939,560 bytes with 256-code-
    # point 4-byte (emoji) filenames. The raw sum (19.4 MiB) clears the
    # memory gate so load succeeds, but RFC 2231 filename headers + base64
    # push the assembled message over 25 MiB, so build raises and NO slot
    # is consumed - all 10 survive for a corrected retry.
    tokens = [_upload_slot(b"\0" * 1_939_560, filename="\U0001f600" * 256) for _ in range(10)]
    loaded = _load([{"source": "upload", "upload_token": t} for t in tokens])
    assert not isinstance(loaded, dict)  # memory gate passed; loaded ok
    atts, hashes = loaded
    assert _attempt(atts, hashes) == "oversize"
    for t in tokens:
        assert _still_consumable(t)


def test_single_attachment_over_boundary_rejected_slot_intact():
    # ~19.6 MiB raw is under the 25 MiB memory gate but its base64 render
    # exceeds Gmail's 25 MiB encoded ceiling: rejected at build, slot intact.
    token = _upload_slot(b"\0" * 19_600_000)
    atts, hashes = _load([{"source": "upload", "upload_token": token}])
    assert _attempt(atts, hashes) == "oversize"
    assert _still_consumable(token)


def test_single_attachment_near_boundary_send_succeeds_and_consumes():
    # ~18 MiB raw renders under the cap: a legitimate large send works and
    # the slot is consumed (the cap does not over-reject).
    token = _upload_slot(b"\0" * 18_000_000)
    atts, hashes = _load([{"source": "upload", "upload_token": token}])
    assert _attempt(atts, hashes) == "sent"
    assert not _still_consumable(token)


def test_large_recipient_header_oversize_rejected_slot_intact():
    # A single enormous recipient string (schema places NO maxLength on
    # list items) makes the To header ~30 MiB - invisible to any estimate
    # from resolve's vantage point, but build sees it and rejects; the
    # tiny slot is not consumed.
    token = _upload_slot(b"x")
    atts, hashes = _load([{"source": "upload", "upload_token": token}])
    huge_to = ["u" * 30_000_000 + "@e.com"]
    assert _attempt(atts, hashes, to=huge_to) == "oversize"
    assert _still_consumable(token)


def test_non_ascii_body_oversize_rejected_slot_intact():
    # A non-ASCII body renders quoted-printable/base64 and inflates far
    # past its raw UTF-8 length; with a tiny slot it still tips the message
    # over the cap at build, and the slot survives.
    token = _upload_slot(b"x")
    atts, hashes = _load([{"source": "upload", "upload_token": token}])
    body = "の" * 9_000_000  # 9M 3-byte chars = 27 MB UTF-8, over the cap
    assert _attempt(atts, hashes, body_text=body) == "oversize"
    assert _still_consumable(token)


def test_raw_sum_memory_gate_rejects_before_decrypt(monkeypatch):
    # A reference set whose stored raw sizes exceed 25 MiB is rejected in
    # load_attachments BEFORE any decrypt, so RAM stays bounded. Stored
    # size only; actual ciphertext is tiny.
    token = _upload_slot(b"x", size_override=MAX_ENCODED_BYTES + 1)

    def _boom(*_a, **_k):
        raise AssertionError("decrypt_bytes must not run past the memory gate")

    monkeypatch.setattr(attachment_source, "decrypt_bytes", _boom)
    result = _load([{"source": "upload", "upload_token": token}])
    assert result["code"] == ToolErrorCode.BAD_REQUEST
    monkeypatch.undo()
    assert _still_consumable(token)  # gate rejects without consuming


def test_advisory_effective_cap_is_below_the_hard_caps():
    assert EFFECTIVE_MAX_ATTACHMENT_BYTES < MAX_ENCODED_BYTES
    assert EFFECTIVE_MAX_ATTACHMENT_BYTES < store.MAX_UPLOAD_BYTES
