"""Tests for POST /attachments/upload.

Covers the token-before-body ordering (AMEND-B2), the streaming size
guard (independent of Content-Length), the single-write + per-user byte
cap (AMEND-B5), Fernet-at-rest, and the typed 401/404/410/409 rejects.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import httpx
import pytest
import respx
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from mcp_gmail import attachment_upload_store as store
from mcp_gmail import config as config_module
from mcp_gmail import db as db_module
from mcp_gmail import token_manager as tm
from mcp_gmail.attachment_routes import _read_body_capped, _UploadTooLarge
from mcp_gmail.crypto import decrypt_bytes
from mcp_gmail.db import Base
from mcp_gmail.logging_filters import AccessLogQueryStringScrubber, RedactingFilter
from mcp_gmail.server import app

from .conftest import TEST_JWKS_URL

SUB = "auth0|alice"
EMAIL = "alice@example.com"
UPLOAD = "/attachments/upload"


def _remove_redaction_filters() -> None:
    """Strip the process-global redaction filters installed by lifespan.

    Booting a TestClient runs the app lifespan, which calls
    install_redacting_filter() and attaches a RedactingFilter to the
    root logger + its handlers (and the uvicorn loggers). That install
    is process-global and never removed; if this file's alphabetically
    early name lets it run before other tests, the leaked filter mutates
    their captured records (e.g. the RedactingFilter's `code` key redacts
    the `error_code=` substring in an audit line). This test cleans up
    after the side effect it triggers.
    """
    targets = [
        logging.getLogger(),
        logging.getLogger("uvicorn.access"),
        logging.getLogger("uvicorn.error"),
    ]
    for lg in targets:
        for scope in (lg, *lg.handlers):
            for f in list(scope.filters):
                if isinstance(f, (RedactingFilter, AccessLogQueryStringScrubber)):
                    scope.removeFilter(f)


@pytest.fixture
def client(jwks_document):
    with respx.mock(assert_all_called=False) as router:
        router.get(TEST_JWKS_URL).mock(return_value=httpx.Response(200, json=jwks_document))
        with TestClient(app) as c:
            engine = create_engine(
                "sqlite+pysqlite:///:memory:",
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
                future=True,
            )
            Base.metadata.create_all(engine)
            db_module._engine = engine
            db_module._SessionFactory = sessionmaker(
                bind=engine, autoflush=False, expire_on_commit=False
            )
            tm.reset_cache_for_tests()
            yield c
    db_module.reset_for_tests()
    tm.reset_cache_for_tests()
    _remove_redaction_filters()


def _mint(sub: str = SUB, email: str = EMAIL) -> str:
    with db_module.session_scope() as session:
        token, _ = store.create_slot(session, auth0_sub=sub, account_email=email)
    return token


def _hdrs(token: str, filename: str = "label.pdf", mime: str = "application/pdf") -> dict:
    return {
        "X-Upload-Token": token,
        "Content-Type": mime,
        "X-Attachment-Filename": filename,
    }


# --- _read_body_capped unit (lying/absent Content-Length coverage) ---------


async def _aiter(chunks):
    for c in chunks:
        yield c


@pytest.mark.asyncio
async def test_read_body_capped_overflow():
    with pytest.raises(_UploadTooLarge):
        await _read_body_capped(_aiter([b"x" * 6, b"x" * 6]), max_bytes=10)


@pytest.mark.asyncio
async def test_read_body_capped_under_cap():
    out = await _read_body_capped(_aiter([b"ab", b"cd"]), max_bytes=10)
    assert bytes(out) == b"abcd"


# --- endpoint ordering + rejects -------------------------------------------


def test_missing_token_header_returns_401(client):
    r = client.post(UPLOAD, content=b"data", headers={"Content-Type": "application/pdf"})
    assert r.status_code == 401


def test_unknown_token_returns_404(client):
    r = client.post(UPLOAD, content=b"data", headers=_hdrs("Z" * 32))
    assert r.status_code == 404


def test_expired_token_returns_410(client):
    token = _mint()
    with db_module.session_scope() as session:
        row = store.find_slot(session, store.hash_token(token))
        row.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    r = client.post(UPLOAD, content=b"data", headers=_hdrs(token))
    assert r.status_code == 410


def test_consumed_token_returns_410(client):
    token = _mint()
    with db_module.session_scope() as session:
        th = store.hash_token(token)
        store.finalize_upload(
            session,
            token_hash=th,
            encrypted=b"c",
            size_bytes=1,
            filename="f",
            mime_type="text/plain",
        )
        store.consume(session, token_hash=th, auth0_sub=SUB, account_email=EMAIL)
    r = client.post(UPLOAD, content=b"data", headers=_hdrs(token))
    assert r.status_code == 410


def test_missing_filename_returns_400(client):
    token = _mint()
    r = client.post(
        UPLOAD,
        content=b"data",
        headers={"X-Upload-Token": token, "Content-Type": "application/pdf"},
    )
    assert r.status_code == 400


def test_upload_happy_path_stores_encrypted(client):
    token = _mint()
    payload = bytes(range(256)) * 4  # 1 KiB, high-bit bytes
    r = client.post(UPLOAD, content=payload, headers=_hdrs(token))
    assert r.status_code == 200
    assert r.json()["size_bytes"] == len(payload)
    key = config_module.load().encryption_key
    with db_module.session_scope() as session:
        row = store.find_slot(session, store.hash_token(token))
        assert row.uploaded_at is not None
        assert row.size_bytes == len(payload)
        assert row.filename == "label.pdf"
        assert row.encrypted_bytes != payload  # encrypted at rest
        assert decrypt_bytes(row.encrypted_bytes, key) == payload


def test_second_upload_to_same_slot_returns_409(client):
    token = _mint()
    assert client.post(UPLOAD, content=b"first", headers=_hdrs(token)).status_code == 200
    r = client.post(UPLOAD, content=b"second", headers=_hdrs(token))
    assert r.status_code == 409


def test_oversize_content_length_rejected_413(client, monkeypatch):
    monkeypatch.setattr(store, "MAX_UPLOAD_BYTES", 10)
    token = _mint()
    r = client.post(UPLOAD, content=b"x" * 50, headers=_hdrs(token))
    assert r.status_code == 413


def test_per_user_byte_quota_exceeded_413(client, monkeypatch):
    monkeypatch.setattr(store, "MAX_ACTIVE_BYTES_PER_USER", 100)
    # Pre-seed an uploaded slot consuming most of the quota.
    seed = _mint()
    with db_module.session_scope() as session:
        store.finalize_upload(
            session,
            token_hash=store.hash_token(seed),
            encrypted=b"c" * 10,
            size_bytes=95,
            filename="seed.bin",
            mime_type="application/octet-stream",
        )
    token = _mint()
    r = client.post(UPLOAD, content=b"x" * 20, headers=_hdrs(token))
    assert r.status_code == 413
    assert r.json()["error"] == "user_storage_quota_exceeded"
