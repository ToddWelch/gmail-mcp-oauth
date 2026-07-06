"""Transient DB-backed store for attachment upload slots.

Backs the upload-slot + handle flow for large outbound attachments: an
authenticated tool mints a single-use capability slot, the client curls
raw file bytes to the server, and a later send/draft tool attaches the
bytes by handle and consumes the slot (barcode-safe for large binaries).

Security invariants:
  - Only the token's SHA-256 hash is persisted (the PK), so a DB leak
    yields no replayable upload credential.
  - Uploaded bytes may carry PII, so they are Fernet-encrypted as BYTEA.
    `consume` NULLs the ciphertext in the txn it sets `consumed_at`;
    `purge_expired_and_consumed` NULLs then DELETEs in one txn (MVCC
    old-tuple defense, per pending_link_store).

The hourly in-process purge (lifespan.py) assumes a single replica,
enforced at boot by _enforce_replica_constraint; do not scale out.
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    TIMESTAMP,
    CheckConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    delete,
    func,
    select,
    update,
)
from sqlalchemy.orm import Mapped, Session, mapped_column

from .db import Base


# Slot lifetime: long enough for mint -> relay URL -> curl -> send, short
# enough to bound abandoned-slot storage (cf. the 10-min nonce TTLs).
UPLOAD_SLOT_TTL_MINUTES = 15

# Hard per-upload byte cap enforced during streaming; matches Gmail's
# 25 MiB message ceiling. Measured on PLAINTEXT bytes (ciphertext larger).
MAX_UPLOAD_BYTES = 25 * 1024 * 1024

# Per-user caps that bound storage / DoS. COUNT is enforced at mint;
# total BYTES at the upload endpoint (size known only after streaming).
MAX_ACTIVE_SLOTS_PER_USER = 10
MAX_ACTIVE_BYTES_PER_USER = 100 * 1024 * 1024


class SlotCapExceeded(Exception):
    """Raised by create_slot when the user already holds the max active slots."""


# Slot classification -> the endpoint maps each to a typed HTTP status.
STATUS_OK = "ok"
STATUS_NOT_FOUND = "not_found"
STATUS_EXPIRED = "expired"
STATUS_CONSUMED = "consumed"
STATUS_ALREADY_UPLOADED = "already_uploaded"


class AttachmentUpload(Base):
    """One row per minted upload slot.

    Lifecycle: minted (bytes NULL) -> uploaded -> consumed (bytes NULL,
    consumed_at set) -> purged. The token_hash PK is the SHA-256 of the
    raw capability token; the raw token is never stored.
    """

    __tablename__ = "attachment_uploads"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    auth0_sub: Mapped[str] = mapped_column(String(255), nullable=False)
    account_email: Mapped[str] = mapped_column(String(320), nullable=False)
    filename: Mapped[str | None] = mapped_column(String(256), nullable=True)
    mime_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # PLAINTEXT byte length (matches the 25 MiB cap); ciphertext is larger.
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Fernet ciphertext. NULL at mint, set at upload, NULLed at consume.
    encrypted_bytes: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    uploaded_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    consumed_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True), nullable=True)

    __table_args__ = (
        Index("ix_attachment_uploads_auth0_sub", "auth0_sub"),
        Index("ix_attachment_uploads_expires_at", "expires_at"),
        CheckConstraint(
            "account_email = LOWER(account_email)",
            name="ck_attachment_uploads_email_lowercase",
        ),
    )


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware(dt: datetime) -> datetime:
    """Coerce a naive timestamp to UTC-aware.

    Postgres returns tz-aware datetimes; SQLite drops tzinfo. Stored
    times are UTC, so treating a naive read as UTC keeps the Python-side
    comparison in classify_slot correct on both backends (the SQL-side
    predicates elsewhere compare in the DB and do not need this).
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of a raw capability token."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _generate_token() -> str:
    """Return a 256-bit URL-safe random capability token (mirrors nonce gen)."""
    return secrets.token_urlsafe(32)


def count_active_slots(session: Session, auth0_sub: str) -> int:
    """Count the user's unconsumed, unexpired slots (for the mint count cap)."""
    stmt = (
        select(func.count())
        .select_from(AttachmentUpload)
        .where(
            AttachmentUpload.auth0_sub == auth0_sub,
            AttachmentUpload.consumed_at.is_(None),
            AttachmentUpload.expires_at > _now_utc(),
        )
    )
    return int(session.execute(stmt).scalar_one())


def sum_active_bytes(session: Session, auth0_sub: str) -> int:
    """Sum stored plaintext sizes of the user's uploaded, unconsumed slots."""
    stmt = select(func.coalesce(func.sum(AttachmentUpload.size_bytes), 0)).where(
        AttachmentUpload.auth0_sub == auth0_sub,
        AttachmentUpload.uploaded_at.is_not(None),
        AttachmentUpload.consumed_at.is_(None),
        AttachmentUpload.expires_at > _now_utc(),
    )
    return int(session.execute(stmt).scalar_one())


def create_slot(session: Session, *, auth0_sub: str, account_email: str) -> tuple[str, datetime]:
    """Mint a slot; returns (raw_token, expires_at). Enforces the per-user
    COUNT cap (raises SlotCapExceeded); only the token hash is stored.
    """
    if not auth0_sub:
        raise ValueError("auth0_sub is required")
    if not account_email:
        raise ValueError("account_email is required")
    if count_active_slots(session, auth0_sub) >= MAX_ACTIVE_SLOTS_PER_USER:
        raise SlotCapExceeded(
            f"active upload-slot limit reached ({MAX_ACTIVE_SLOTS_PER_USER}); "
            "use or let existing slots expire before minting more"
        )
    token = _generate_token()
    now = _now_utc()
    row = AttachmentUpload(
        token_hash=hash_token(token),
        auth0_sub=auth0_sub,
        account_email=account_email.strip().lower(),
        created_at=now,
        expires_at=now + timedelta(minutes=UPLOAD_SLOT_TTL_MINUTES),
    )
    session.add(row)
    session.flush()
    return token, row.expires_at


def find_slot(session: Session, token_hash: str) -> AttachmentUpload | None:
    """Plain PK lookup used by the endpoint's pre-body classification."""
    if not token_hash:
        return None
    return session.get(AttachmentUpload, token_hash)


def classify_slot(row: AttachmentUpload | None, *, now: datetime | None = None) -> str:
    """Return a STATUS_* value for the endpoint's early, no-body-read reject.

    Order: not_found -> consumed -> expired -> already_uploaded -> ok
    (consumed before expired so a used-then-expired slot reads consumed).
    """
    if row is None:
        return STATUS_NOT_FOUND
    now = now or _now_utc()
    if row.consumed_at is not None:
        return STATUS_CONSUMED
    if _as_aware(row.expires_at) <= now:
        return STATUS_EXPIRED
    if row.uploaded_at is not None:
        return STATUS_ALREADY_UPLOADED
    return STATUS_OK


def finalize_upload(
    session: Session,
    *,
    token_hash: str,
    encrypted: bytes,
    size_bytes: int,
    filename: str,
    mime_type: str,
) -> bool:
    """Atomically store bytes into a minted, not-yet-uploaded slot.

    Conditional UPDATE (unconsumed/unexpired/not-uploaded); True iff one
    row updated, else a lost race (endpoint -> 409).
    """
    now = _now_utc()
    stmt = (
        update(AttachmentUpload)
        .where(AttachmentUpload.token_hash == token_hash)
        .where(AttachmentUpload.consumed_at.is_(None))
        .where(AttachmentUpload.uploaded_at.is_(None))
        .where(AttachmentUpload.encrypted_bytes.is_(None))
        .where(AttachmentUpload.expires_at > now)
        .values(
            encrypted_bytes=encrypted,
            size_bytes=size_bytes,
            filename=filename,
            mime_type=mime_type,
            uploaded_at=now,
        )
        .execution_options(synchronize_session=False)
    )
    return session.execute(stmt).rowcount == 1


def load_for_consume(
    session: Session, *, token_hash: str, auth0_sub: str, account_email: str
) -> AttachmentUpload | None:
    """Owner-scoped read of an uploaded, unconsumed, unexpired slot.

    Scoped to (auth0_sub, account_email) so another user's/mailbox's
    token resolves to None and can never be attached. Does NOT consume.
    """
    if not token_hash:
        return None
    now = _now_utc()
    stmt = (
        select(AttachmentUpload)
        .where(AttachmentUpload.token_hash == token_hash)
        .where(AttachmentUpload.auth0_sub == auth0_sub)
        .where(AttachmentUpload.account_email == account_email.strip().lower())
        .where(AttachmentUpload.consumed_at.is_(None))
        .where(AttachmentUpload.expires_at > now)
        .where(AttachmentUpload.encrypted_bytes.is_not(None))
    )
    return session.execute(stmt).scalar_one_or_none()


def consume(session: Session, *, token_hash: str, auth0_sub: str, account_email: str) -> bool:
    """Atomically consume an owned slot: set consumed_at + NULL the bytes.

    Conditional UPDATE (unconsumed/unexpired/owned) makes single-use
    airtight: concurrent sends serialize and exactly one wins.
    """
    now = _now_utc()
    stmt = (
        update(AttachmentUpload)
        .where(AttachmentUpload.token_hash == token_hash)
        .where(AttachmentUpload.auth0_sub == auth0_sub)
        .where(AttachmentUpload.account_email == account_email.strip().lower())
        .where(AttachmentUpload.consumed_at.is_(None))
        .where(AttachmentUpload.expires_at > now)
        .values(consumed_at=now, encrypted_bytes=None)
        .execution_options(synchronize_session=False)
    )
    return session.execute(stmt).rowcount == 1


def purge_expired_and_consumed(session: Session) -> int:
    """NULL bytes then DELETE expired-or-consumed rows in one transaction.

    NULL-then-DELETE (per pending_link_store) keeps an MVCC old-tuple
    from retaining encrypted PII. Returns rows removed. Runs hourly.
    """
    now = _now_utc()
    condition = (AttachmentUpload.expires_at < now) | (AttachmentUpload.consumed_at.is_not(None))
    session.execute(
        update(AttachmentUpload)
        .where(condition)
        .values(encrypted_bytes=None)
        .execution_options(synchronize_session=False)
    )
    result = session.execute(delete(AttachmentUpload).where(condition))
    return result.rowcount or 0
