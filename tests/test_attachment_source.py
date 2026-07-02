"""Tests for attachment_source.resolve_attachments + the schema oneOf boundary.

Covers the consume path end to end: the byte-for-byte integrity
guarantee (the barcode-corruption fix), mixed inline+upload, ownership
scoping, single-use, the pre-decrypt size cap (AMEND-B4), and the
tagged-union discrimination both at the JSON Schema boundary
(AMEND-B1) and in the _classify handler backstop.
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
from mcp_gmail.gmail_tools.attachment_source import resolve_attachments
from mcp_gmail.gmail_tools.errors import ToolErrorCode

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


def _base_send_args(attachments):
    return {
        "account_email": EMAIL,
        "sender": EMAIL,
        "to": [EMAIL],
        "subject": "s",
        "body_text": "b",
        "attachments": attachments,
    }


# --- schema boundary (AMEND-B1: oneOf enforced at dispatch) ----------------


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


# --- resolve_attachments ---------------------------------------------------


def test_resolve_inline_only_needs_no_key():
    data_b64 = base64.urlsafe_b64encode(b"hello").rstrip(b"=").decode()
    result = resolve_attachments(
        raw=[{"filename": "h.txt", "mime_type": "text/plain", "data_base64url": data_b64}],
        auth0_sub=SUB,
        account_email=EMAIL,
        encryption_key=None,
    )
    assert isinstance(result, list)
    assert result[0].data == b"hello"


def test_resolve_upload_is_byte_for_byte_and_consumes():
    token = _upload_slot()
    result = resolve_attachments(
        raw=[{"source": "upload", "upload_token": token}],
        auth0_sub=SUB,
        account_email=EMAIL,
        encryption_key=_enc_key(),
    )
    assert isinstance(result, list)
    assert result[0].data == PAYLOAD  # barcode guarantee
    assert result[0].filename == "label.pdf"
    assert result[0].mime_type == "application/pdf"
    # Slot is consumed: replay fails and bytes are gone.
    with db_module.session_scope() as session:
        assert (
            store.load_for_consume(
                session, token_hash=store.hash_token(token), auth0_sub=SUB, account_email=EMAIL
            )
            is None
        )


def test_resolve_mixed_inline_and_upload_preserves_order():
    token = _upload_slot(b"UPLOADED", filename="u.bin", mime="application/octet-stream")
    inline_b64 = base64.urlsafe_b64encode(b"INLINE").rstrip(b"=").decode()
    result = resolve_attachments(
        raw=[
            {"filename": "i.txt", "mime_type": "text/plain", "data_base64url": inline_b64},
            {"source": "upload", "upload_token": token},
        ],
        auth0_sub=SUB,
        account_email=EMAIL,
        encryption_key=_enc_key(),
    )
    assert [a.data for a in result] == [b"INLINE", b"UPLOADED"]


def test_resolve_filename_and_mime_override():
    token = _upload_slot()
    result = resolve_attachments(
        raw=[{"source": "upload", "upload_token": token, "filename": "renamed.pdf"}],
        auth0_sub=SUB,
        account_email=EMAIL,
        encryption_key=_enc_key(),
    )
    assert result[0].filename == "renamed.pdf"


def test_resolve_wrong_user_rejected_and_slot_untouched():
    token = _upload_slot()  # owned by SUB
    result = resolve_attachments(
        raw=[{"source": "upload", "upload_token": token}],
        auth0_sub="auth0|eve",
        account_email=EMAIL,
        encryption_key=_enc_key(),
    )
    assert result["code"] == ToolErrorCode.BAD_REQUEST
    with db_module.session_scope() as session:
        # The true owner's slot was NOT consumed.
        assert (
            store.load_for_consume(
                session, token_hash=store.hash_token(token), auth0_sub=SUB, account_email=EMAIL
            )
            is not None
        )


def test_resolve_expired_rejected():
    token = _upload_slot()
    with db_module.session_scope() as session:
        row = store.find_slot(session, store.hash_token(token))
        from datetime import datetime, timedelta, timezone

        row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    result = resolve_attachments(
        raw=[{"source": "upload", "upload_token": token}],
        auth0_sub=SUB,
        account_email=EMAIL,
        encryption_key=_enc_key(),
    )
    assert result["code"] == ToolErrorCode.BAD_REQUEST


def test_resolve_replay_after_consume_rejected():
    token = _upload_slot()
    args = dict(
        raw=[{"source": "upload", "upload_token": token}],
        auth0_sub=SUB,
        account_email=EMAIL,
        encryption_key=_enc_key(),
    )
    assert isinstance(resolve_attachments(**args), list)
    replay = resolve_attachments(**args)
    assert replay["code"] == ToolErrorCode.BAD_REQUEST


def test_resolve_size_cap_checked_before_decrypt(monkeypatch):
    # Slot claims 10 stored bytes; cap lowered to 5 so it is rejected.
    token = _upload_slot(b"tiny", size_override=10)
    monkeypatch.setattr(attachment_source, "MAX_ENCODED_BYTES", 5)

    def _boom(*_a, **_k):
        raise AssertionError("decrypt_bytes must not be called before the size check")

    monkeypatch.setattr(attachment_source, "decrypt_bytes", _boom)
    result = resolve_attachments(
        raw=[{"source": "upload", "upload_token": token}],
        auth0_sub=SUB,
        account_email=EMAIL,
        encryption_key=_enc_key(),
    )
    assert result["code"] == ToolErrorCode.BAD_REQUEST


def test_resolve_consume_race_rolls_back(monkeypatch):
    token = _upload_slot()
    monkeypatch.setattr(store, "consume", lambda *a, **k: False)
    result = resolve_attachments(
        raw=[{"source": "upload", "upload_token": token}],
        auth0_sub=SUB,
        account_email=EMAIL,
        encryption_key=_enc_key(),
    )
    assert result["code"] == ToolErrorCode.BAD_REQUEST
    monkeypatch.undo()
    # The slot was not consumed (rollback), so it remains usable.
    with db_module.session_scope() as session:
        assert (
            store.load_for_consume(
                session, token_hash=store.hash_token(token), auth0_sub=SUB, account_email=EMAIL
            )
            is not None
        )


def test_classify_backstop_rejects_ambiguous_and_neither():
    both = {"data_base64url": "aGk", "source": "upload", "upload_token": "A" * 20}
    neither = {"filename": "x"}
    assert isinstance(attachment_source._classify(both, index=0), dict)
    assert isinstance(attachment_source._classify(neither, index=0), dict)
    assert (
        attachment_source._classify({"source": "upload", "upload_token": "A" * 20}, index=0)
        == "upload"
    )
